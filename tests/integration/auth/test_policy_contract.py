"""Policy covers sessions, authentication and privileged status mutations."""

from datetime import UTC, datetime, timedelta
from typing import Annotated

import pytest
from pydantic import SecretStr

from fastauth import FastAuth, email_password
from fastauth.api.commands import BearerCredentialDelivery, SignInEmailCommand, SignUpEmailCommand
from fastauth.database import custom
from fastauth.exceptions import PolicyDeniedError
from fastauth.options import FastAuthOptions, PasswordOptions, RateLimitOptions, SessionOptions
from fastauth.security.policy import PolicyDecision, PolicyRequest
from fastauth.storage.memory import InMemoryAdapter


def build_auth(*, verified: bool = False) -> FastAuth:
    return FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("s" * 64),
            database=custom(adapter=InMemoryAdapter()),
            session=SessionOptions(require_verified_user=verified),
            password=PasswordOptions(argon2_time_cost=1, argon2_memory_cost_kib=8192),
            rate_limit=RateLimitOptions(enabled=False),
        ),
        plugins=[email_password()],
    )


async def sign_up(auth: FastAuth):
    return await auth.api.sign_up.email(
        SignUpEmailCommand(
            email="policy@example.com",
            password=SecretStr("password123"),
            delivery=BearerCredentialDelivery(include_refresh_token=False),
        )
    )


async def test_suspension_blocks_password_and_existing_session_and_is_audited() -> None:
    auth = build_auth()
    from fastauth.domain.events import UserUpdated

    events: list[UserUpdated] = []

    async def record(event: UserUpdated) -> None:
        events.append(event)

    auth.events.subscribe(UserUpdated, record)
    response = await sign_up(auth)
    assert response.credentials is not None
    token = response.credentials.token.root
    await auth.policy.set_active(response.user.id, active=False, reason="account review")
    assert await auth.context.session_strategy.read(token) is None
    with pytest.raises(PolicyDeniedError):
        await auth.api.sign_in.email(
            SignInEmailCommand(
                email="policy@example.com",
                password=SecretStr("password123"),
            )
        )
    assert events[-1].extra["trusted_admin"] is True
    assert events[-1].changed_fields == ["active"]


async def test_verified_policy_restricts_bootstrap_session() -> None:
    auth = build_auth(verified=True)
    response = await sign_up(auth)
    assert response.credentials is not None
    token = response.credentials.token.root
    assert await auth.context.session_strategy.read(token) is None
    user = await auth.context.adapter.get_user_by_id(response.user.id.root)
    assert user is not None
    user.email_verified = True
    await auth.context.adapter.update_user(user)
    assert await auth.context.session_strategy.read(token) is not None


async def test_recent_auth_rejects_unknown_or_stale_timestamp() -> None:
    auth = build_auth()
    response = await sign_up(auth)
    assert response.credentials is not None
    token = response.credentials.token.root
    actor = await auth.policy.authenticate(token, max_age=timedelta(minutes=5))
    assert actor.session.authenticated_at is not None
    sessions = await auth.context.adapter.list_sessions_for_user(response.user.id.root)
    session = sessions[0]
    for authenticated_at in (None, datetime.now(UTC) - timedelta(hours=1)):
        session.authenticated_at = authenticated_at
        await auth.context.adapter.update_session(session)
        with pytest.raises(PolicyDeniedError, match="recent"):
            await auth.policy.authenticate(token, max_age=timedelta(minutes=5))


async def test_application_policy_can_deny_session_issue() -> None:
    async def deny(request: PolicyRequest) -> PolicyDecision:
        return PolicyDecision(allowed=request.action != "session.issue", reason="app policy")

    base = build_auth()
    auth = FastAuth(base.options, plugins=[email_password()], policy_hook=deny)
    with pytest.raises(PolicyDeniedError, match="app policy"):
        await sign_up(auth)


async def test_api_key_verification_checks_owner_status_and_application_policy() -> None:
    from fastauth.plugins.api_key import ApiKeyPlugin, CreateApiKeyRequest, VerifyApiKeyRequest

    base = build_auth()
    plugin = ApiKeyPlugin()
    auth = FastAuth(base.options, plugins=[email_password(), plugin])
    response = await sign_up(auth)
    key = await plugin.create_for_user(response.user.id, CreateApiKeyRequest(name="test"))
    assert (await plugin.verify_key(VerifyApiKeyRequest(key=SecretStr(key.key)))).valid
    await auth.policy.set_active(response.user.id, active=False, reason="suspend")
    result = await plugin.verify_key(VerifyApiKeyRequest(key=SecretStr(key.key)))
    assert not result.valid
    assert result.error is not None
    assert result.error.code == "POLICY_DENIED"


async def test_policy_permission_ceiling_cannot_mutate_rejected_key_update() -> None:
    from fastauth.domain.value_objects import PermissionSet
    from fastauth.plugins.api_key import ApiKeyPlugin, CreateApiKeyRequest, UpdateApiKeyRequest

    async def ceiling(request: PolicyRequest) -> PolicyDecision:
        return PolicyDecision(
            allowed=request.api_key is None or "admin" not in request.api_key.permissions,
            reason="permission ceiling",
        )

    base = build_auth()
    plugin = ApiKeyPlugin()
    auth = FastAuth(base.options, plugins=[email_password(), plugin], policy_hook=ceiling)
    response = await sign_up(auth)
    key = await plugin.create_for_user(response.user.id, CreateApiKeyRequest(name="test"))
    with pytest.raises(PolicyDeniedError):
        await plugin.update_for_user(
            response.user.id,
            UpdateApiKeyRequest(
                id=key.api_key.id,
                permissions=PermissionSet({"admin": frozenset({"write"})}),
            ),
        )
    persisted = await plugin.assert_store().get_api_key_by_id(key.api_key.id.root)
    assert persisted is not None
    assert persisted.permissions == {}


async def test_verified_and_recent_fastapi_dependencies() -> None:
    import httpx
    from fastapi import Depends

    from fastauth.api.responses import UserView
    from fastauth.security.sessions import SessionContext

    auth = build_auth()
    app = auth.as_asgi()

    @app.get("/verified")
    async def verified(
        user: Annotated[UserView, Depends(auth.depends.verified_user())],
    ) -> UserView:
        return user

    @app.get("/recent")
    async def recent(
        session: Annotated[SessionContext, Depends(auth.depends.recent_session())],
    ) -> UserView:
        return await auth.api.get_user(by_id=session.user.id)  # type: ignore[return-value]

    assert callable(verified) and callable(recent)
    response = await sign_up(auth)
    assert response.credentials is not None
    headers = {"Authorization": f"Bearer {response.credentials.token.root}"}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://test"
    ) as client:
        assert (await client.get("/verified", headers=headers)).status_code == 403
        assert (await client.get("/recent", headers=headers)).status_code == 200
        sessions = await auth.context.adapter.list_sessions_for_user(response.user.id.root)
        sessions[0].authenticated_at = None
        await auth.context.adapter.update_session(sessions[0])
        assert (await client.get("/recent", headers=headers)).status_code == 403


async def test_logout_restricted_bootstrap_also_revokes_refresh() -> None:
    from fastauth.api.commands import SignOutCommand
    from fastauth.exceptions import TokenInvalidError
    from fastauth.options import RefreshTokenOptions

    base = build_auth(verified=True)
    auth = FastAuth(
        base.options.model_copy(update={"refresh_token": RefreshTokenOptions(enabled=True)}),
        plugins=[email_password()],
    )
    response = await auth.api.sign_up.email(
        SignUpEmailCommand(
            email="bootstrap@example.com",
            password=SecretStr("password123"),
            delivery=BearerCredentialDelivery(),
        )
    )
    assert response.credentials is not None
    assert response.credentials.refresh_token is not None
    await auth.api.sign_out(SignOutCommand(token=SecretStr(response.credentials.token.root)))
    with pytest.raises(TokenInvalidError):
        await auth.context.refresh_token_service.get_valid(response.credentials.refresh_token.root)


async def test_login_rehashes_only_after_successful_password_verification() -> None:
    from fastauth.domain.enums import ProviderId
    from fastauth.exceptions import InvalidCredentialsError
    from fastauth.security.passwords import Argon2idHasher

    old = build_auth()
    response = await sign_up(old)
    account = await old.context.adapter.get_account_for_user(
        response.user.id.root, ProviderId.CREDENTIAL
    )
    assert account is not None and account.password is not None
    original = account.password
    options = old.options.model_copy(
        update={"password": PasswordOptions(argon2_time_cost=2, argon2_memory_cost_kib=8192)}
    )
    auth = FastAuth(options, plugins=[email_password()])
    with pytest.raises(InvalidCredentialsError):
        await auth.api.sign_in.email(
            SignInEmailCommand(email="policy@example.com", password=SecretStr("wrong-password"))
        )
    unchanged = await auth.context.adapter.get_account_for_user(
        response.user.id.root, ProviderId.CREDENTIAL
    )
    assert unchanged is not None and unchanged.password == original
    await auth.api.sign_in.email(
        SignInEmailCommand(email="policy@example.com", password=SecretStr("password123"))
    )
    updated = await auth.context.adapter.get_account_for_user(
        response.user.id.root, ProviderId.CREDENTIAL
    )
    assert updated is not None and updated.password is not None
    assert updated.password != original
    assert not Argon2idHasher(options.password).needs_rehash(updated.password)


async def test_concurrent_password_change_wins_over_login_rehash() -> None:
    from fastauth.domain.enums import ProviderId
    from fastauth.exceptions import InvalidCredentialsError

    class ResetDuringRehashAdapter(InMemoryAdapter):
        async def replace_account_password(
            self, account_id: str, *, expected_hash: str, new_hash: str
        ) -> bool:
            account = next(item for item in self.accounts.values() if item.id == account_id)
            account.password = "new-credential-from-concurrent-reset"
            await self.update_account(account)
            return await super().replace_account_password(
                account_id, expected_hash=expected_hash, new_hash=new_hash
            )

    store = ResetDuringRehashAdapter()
    base = build_auth()
    old = FastAuth(
        base.options.model_copy(update={"database": custom(adapter=store)}),
        plugins=[email_password()],
    )
    response = await sign_up(old)
    auth = FastAuth(
        old.options.model_copy(
            update={
                "password": PasswordOptions(
                    argon2_time_cost=2,
                    argon2_memory_cost_kib=8192,
                )
            }
        ),
        plugins=[email_password()],
    )
    before = await store.list_sessions_for_user(response.user.id.root)
    with pytest.raises(InvalidCredentialsError):
        await auth.api.sign_in.email(
            SignInEmailCommand(email="policy@example.com", password=SecretStr("password123"))
        )
    after = await store.list_sessions_for_user(response.user.id.root)
    assert len(after) == len(before)
    account = await store.get_account_for_user(response.user.id.root, ProviderId.CREDENTIAL)
    assert account is not None
    assert account.password == "new-credential-from-concurrent-reset"


async def test_session_issue_racing_suspension_cannot_survive_reactivation() -> None:
    import asyncio

    from fastauth.domain.models import Session

    class PausingSessionAdapter(InMemoryAdapter):
        def __init__(self) -> None:
            super().__init__()
            self.entered = asyncio.Event()
            self.release = asyncio.Event()
            self.pause = False

        async def create_session(self, session: Session) -> Session:
            if self.pause:
                self.entered.set()
                await self.release.wait()
            return await super().create_session(session)

    store = PausingSessionAdapter()
    base = build_auth()
    auth = FastAuth(
        base.options.model_copy(update={"database": custom(adapter=store)}),
        plugins=[email_password()],
    )
    response = await sign_up(auth)
    store.pause = True
    login = asyncio.create_task(
        auth.api.sign_in.email(
            SignInEmailCommand(
                email="policy@example.com",
                password=SecretStr("password123"),
            )
        )
    )
    await store.entered.wait()
    await auth.policy.set_active(response.user.id, active=False, reason="suspend")
    store.release.set()
    with pytest.raises(PolicyDeniedError):
        await login
    await auth.policy.set_active(response.user.id, active=True, reason="restore")
    assert await store.list_sessions_for_user(response.user.id.root) == []
