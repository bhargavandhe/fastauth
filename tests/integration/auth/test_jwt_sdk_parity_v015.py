"""Trusted session-reference commands retain parity for database/JWT strategies."""

from typing import Literal

import httpx
import pytest
from fastapi import FastAPI
from pydantic import SecretStr, ValidationError

from fastauth import FastAuth, email_otp, email_password, jwt
from fastauth.api.commands import BearerCredentialDelivery
from fastauth.api.responses import AuthenticationResponse
from fastauth.database import custom
from fastauth.domain.enums import SessionStrategyKind
from fastauth.domain.events import OtpGenerated
from fastauth.domain.value_objects import SessionId
from fastauth.exceptions import InvalidCredentialsError, TokenInvalidError
from fastauth.options import (
    CsrfOptions,
    FastAuthOptions,
    PasswordOptions,
    RateLimitOptions,
    RefreshTokenOptions,
    SessionOptions,
)
from fastauth.runtime.services import EmailOtpPurpose, SendOtpRequest, SignInOtpRequest
from fastauth.storage.memory import InMemoryAdapter

Operation = Literal["change", "set", "revoke_other"]


def jwt_auth() -> FastAuth:
    return FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("p" * 64),
            database=custom(adapter=InMemoryAdapter()),
            session=SessionOptions(strategy=SessionStrategyKind.JWT),
            password=PasswordOptions(argon2_time_cost=1, argon2_memory_cost_kib=8192),
            rate_limit=RateLimitOptions(enabled=False),
            csrf=CsrfOptions(enabled=False),
            refresh_token=RefreshTokenOptions(enabled=True),
        ),
        plugins=[email_password(), email_otp(), jwt()],
    )


async def otp_session(auth: FastAuth) -> AuthenticationResponse:
    codes: list[str] = []

    async def remember(event: OtpGenerated) -> None:
        codes.append(event.plain)

    auth.on(OtpGenerated)(remember)
    await auth.otp.send(
        SendOtpRequest(email="jwt-sdk@example.com", purpose=EmailOtpPurpose.SIGN_IN)
    )
    return await auth.otp.sign_in(
        SignInOtpRequest(
            email="jwt-sdk@example.com",
            otp=SecretStr(codes[-1]),
            delivery=BearerCredentialDelivery(),
        )
    )


@pytest.mark.parametrize("operation", ["change", "set", "revoke_other"])
@pytest.mark.parametrize("transport", ["sdk", "http"])
async def test_jwt_session_operations_preserve_current_refresh_family(
    operation: Operation, transport: Literal["sdk", "http"]
) -> None:
    auth = jwt_auth()
    if operation == "set":
        current = await otp_session(auth)
        other = await otp_session(auth)
    else:
        current = await auth.sign_up.email(
            "jwt-sdk@example.com", SecretStr("Password123!"), delivery=BearerCredentialDelivery()
        )
        other = await auth.sign_in.email(
            "jwt-sdk@example.com", SecretStr("Password123!"), delivery=BearerCredentialDelivery()
        )
    assert current.credentials is not None and current.credentials.refresh_token is not None
    assert other.credentials is not None and other.credentials.refresh_token is not None
    assert current.session.id.root.startswith("jwt:")
    assert await auth.context.adapter.list_sessions_for_user(current.user.id.root) == []
    actor = await auth.policy.authenticate(current.credentials.token.root)
    if transport == "sdk":
        if operation == "change":
            await auth.passwords.change(
                user_id=actor.user.id,
                session_id=actor.session.id,
                current_password=SecretStr("Password123!"),
                new_password=SecretStr("ChangedPassword123!"),
            )
        elif operation == "set":
            await auth.passwords.set(
                user_id=actor.user.id,
                session_id=actor.session.id,
                new_password=SecretStr("ChangedPassword123!"),
            )
        else:
            result = await auth.sessions.revoke_other(actor.user.id, actor.session.id)
            assert result.revoked_refresh_tokens == 1
    else:
        app = FastAPI()
        app.include_router(auth.router, prefix="/auth")
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
            headers={"Authorization": f"Bearer {current.credentials.token.root}"},
        ) as client:
            if operation == "change":
                response = await client.post(
                    "/auth/change-password",
                    json={"currentPassword": "Password123!", "newPassword": "ChangedPassword123!"},
                )
            elif operation == "set":
                response = await client.post(
                    "/auth/set-password", json={"newPassword": "ChangedPassword123!"}
                )
            else:
                response = await client.delete("/auth/sessions")
            assert response.status_code == 200, response.text
    with pytest.raises(TokenInvalidError):
        await auth.sessions.refresh(SecretStr(other.credentials.refresh_token.root))
    refreshed = await auth.sessions.refresh(SecretStr(current.credentials.refresh_token.root))
    assert refreshed.session.id == actor.session.id
    if operation in {"change", "set"}:
        assert (
            await auth.sign_in.email("jwt-sdk@example.com", SecretStr("ChangedPassword123!"))
        ).user.id == actor.user.id


@pytest.mark.parametrize(
    "session_id", ["jwt:invalid", "jwt:" + "g" * 32, "jwt:" + "a" * 31, "arbitrary"]
)
async def test_malformed_jwt_principal_rejected(session_id: str) -> None:
    auth = jwt_auth()
    user = await auth.api.create_user(email="bad-reference@example.com", password="Password123!")
    with pytest.raises(ValidationError):
        await auth.sessions.revoke_other(user.id, SessionId(session_id))


async def test_database_principal_rejects_jwt_reference(auth: FastAuth) -> None:
    user = await auth.api.create_user(email="db-reference@example.com", password="Password123!")
    with pytest.raises(InvalidCredentialsError):
        await auth.sessions.revoke_other(user.id, SessionId("jwt:" + "a" * 32))


async def test_jwt_config_with_injected_database_strategy_still_checks_rows() -> None:
    from fastauth.security.sessions import DatabaseSessionStrategy
    from fastauth.security.tokens import TokenService

    base = jwt_auth()
    strategy = DatabaseSessionStrategy(base.context.adapter, TokenService(), base.options.session)
    auth = FastAuth(base.options, plugins=[email_password(), jwt()], session_strategy=strategy)
    user = await auth.api.create_user(email="override@example.com", password="Password123!")
    with pytest.raises(InvalidCredentialsError):
        await auth.sessions.revoke_other(user.id, SessionId("jwt:" + "a" * 32))


async def test_legacy_verified_jwt_principal_remains_usable_until_expiry() -> None:
    from datetime import UTC, datetime

    from fastauth.security.jwt import JwtSessionStrategy

    auth = jwt_auth()
    user = await auth.api.create_user(email="legacy@example.com", password="Password123!")
    strategy = auth.policy.sessions
    assert isinstance(strategy, JwtSessionStrategy)
    token = await strategy.signer.sign(
        header={"alg": strategy.registry.alg.value, "typ": "JWT"},
        payload={
            "sub": user.id.root,
            "iss": strategy.issuer,
            "aud": strategy.audience,
            "exp": datetime.now(UTC).timestamp() + 60,
        },
    )
    actor = await auth.policy.authenticate(token)
    assert actor.session.id.root.startswith("legacy-jwt:")
    result = await auth.sessions.revoke_other(actor.user.id, actor.session.id)
    assert result.revoked_refresh_tokens == 0
