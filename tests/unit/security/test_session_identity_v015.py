from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from joserfc import jwk, jwt
from pydantic import SecretStr

from fastauth.domain.enums import JwtAlgorithm
from fastauth.domain.models import User
from fastauth.security.jwt import JwksRegistry, JwtSessionStrategy, LocalKmsSigner
from fastauth.storage.memory import InMemoryAdapter


def registry_for(adapter: InMemoryAdapter) -> JwksRegistry:
    return JwksRegistry(
        adapter,
        secret_key=SecretStr("k" * 64),
        alg=JwtAlgorithm.ED25519,
        rotation_interval_seconds=60,
        grace_period_seconds=900,
        encrypt_private_keys=True,
    )


def strategy_for(adapter: InMemoryAdapter, registry: JwksRegistry) -> JwtSessionStrategy:
    return JwtSessionStrategy(
        adapter=adapter,
        registry=registry,
        signer=LocalKmsSigner(registry),
        issuer="test",
        audience="test",
        expires_in_seconds=900,
        payload_builder=lambda user: {},
    )


async def test_jwt_session_identity_is_stable_on_read_and_renew() -> None:
    adapter = InMemoryAdapter()
    registry = registry_for(adapter)
    strategy = strategy_for(adapter, registry)
    user = await adapter.create_user(User(email="identity@example.com"))
    original = await strategy.create(user, ip=None, user_agent=None)
    read = await strategy.read(original.token)
    assert read is not None
    assert read.session.id == original.session.id
    assert original.session.id.startswith("jwt:")
    renewed = await strategy.renew(
        user,
        session_id=read.session.id,
        authenticated_at=read.session.authenticated_at,
        ip=None,
        user_agent=None,
    )
    assert renewed.session.id == original.session.id
    assert renewed.session.authenticated_at == original.session.authenticated_at


async def test_stale_worker_does_not_sign_with_retired_cached_key() -> None:
    adapter = InMemoryAdapter()
    worker_a, worker_b = registry_for(adapter), registry_for(adapter)
    await worker_a.ensure_key()
    await worker_b.ensure_key()
    replacement = await worker_a.rotate_now()
    token = await LocalKmsSigner(worker_b).sign(header={"alg": "Ed25519"}, payload={"sub": "one"})
    keys = jwk.KeySet([jwk.import_key(item) for item in (await worker_a.as_jwks_json()).keys])
    decoded = jwt.decode(token, keys, algorithms=["Ed25519"])
    assert decoded.header["kid"] == replacement.kid


async def test_signing_rotates_due_key_without_restart() -> None:
    adapter = InMemoryAdapter()
    registry = registry_for(adapter)
    old = await registry.ensure_key()
    old.created_at = datetime.now(UTC) - timedelta(seconds=61)
    await adapter.update_jwks_key(old)
    token = await LocalKmsSigner(registry).sign(header={"alg": "Ed25519"}, payload={"sub": "one"})
    keys = jwk.KeySet([jwk.import_key(item) for item in (await registry.as_jwks_json()).keys])
    assert jwt.decode(token, keys, algorithms=["Ed25519"]).header["kid"] != old.kid


@pytest.mark.parametrize("claim,value", [("sid", "evil"), ("sub", "evil"), ("exp", 1)])
async def test_payload_builder_cannot_override_session_claims(claim: str, value: str | int) -> None:
    adapter = InMemoryAdapter()
    strategy = strategy_for(adapter, registry_for(adapter))

    def builder(user: User) -> dict[str, Any]:
        return {claim: value, "email": user.email}

    strategy.payload_builder = builder
    user = await adapter.create_user(User(email="reserved@example.com"))
    created = await strategy.create(user, ip=None, user_agent=None)
    read = await strategy.read(created.token)
    assert read is not None
    assert read.user.id == user.id
    assert read.session.id == created.session.id


async def test_refresh_renews_jwt_identity_and_authentication_age() -> None:
    from fastauth import email_password
    from fastauth.api.commands import BearerCredentialDelivery
    from fastauth.database import custom
    from fastauth.domain.enums import SessionStrategyKind
    from fastauth.flows.credentials import SignUpEmailRequest, sign_up_email
    from fastauth.flows.refresh import RefreshTokenRequest, refresh_session
    from fastauth.options import FastAuthOptions, RefreshTokenOptions, SessionOptions
    from fastauth.plugins.jwt import JwtPlugin
    from fastauth.runtime.auth import FastAuth

    adapter = InMemoryAdapter()
    auth = FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("k" * 64),
            database=custom(adapter=adapter),
            refresh_token=RefreshTokenOptions(enabled=True),
            session=SessionOptions(strategy=SessionStrategyKind.JWT),
        ),
        plugins=[email_password(), JwtPlugin()],
    )
    response, initial = await sign_up_email(
        auth.context,
        SignUpEmailRequest(
            email="refresh-identity@example.com",
            password=SecretStr("safe-password-123"),
            delivery=BearerCredentialDelivery(),
        ),
        ip=None,
        user_agent=None,
    )
    assert response.credentials is not None and response.credentials.refresh_token is not None
    refreshed, renewed = await refresh_session(
        auth.context,
        RefreshTokenRequest(refresh_token=SecretStr(response.credentials.refresh_token.root)),
        ip=None,
        user_agent=None,
    )
    assert renewed.session.id == initial.session.id
    assert renewed.session.authenticated_at == initial.session.authenticated_at
    assert refreshed.credentials is not None


async def test_revoke_other_sessions_preserves_entire_current_refresh_family() -> None:
    from fastauth.domain.models import RefreshToken, new_id

    adapter = InMemoryAdapter()
    user = await adapter.create_user(User(email="family@example.com"))
    now = datetime.now(UTC)
    root_id = new_id()
    root = RefreshToken(
        id=root_id,
        family_id=root_id,
        user_id=user.id,
        session_id="old-session",
        token_hash="old",
        family_created_at=now,
        expires_at=now + timedelta(days=1),
    )
    await adapter.create_refresh_token(root)
    await adapter.rotate_refresh_token(
        current_token_id=root.id,
        consumed_at=now,
        new_token=RefreshToken(
            family_id=root.id,
            user_id=user.id,
            session_id="current-session",
            token_hash="current",
            family_created_at=now,
            expires_at=now + timedelta(days=1),
        ),
    )
    assert (
        await adapter.delete_refresh_tokens_for_user(user.id, except_session_id="current-session")
        == 0
    )
    assert await adapter.get_refresh_token_by_hash("old") is not None


async def test_revoke_old_session_revokes_rotated_refresh_family() -> None:
    from fastauth.domain.models import RefreshToken, new_id

    adapter = InMemoryAdapter()
    user = await adapter.create_user(User(email="old-family@example.com"))
    now = datetime.now(UTC)
    root_id = new_id()
    root = RefreshToken(
        id=root_id,
        family_id=root_id,
        user_id=user.id,
        session_id="old-session",
        token_hash="old",
        family_created_at=now,
        expires_at=now + timedelta(days=1),
    )
    await adapter.create_refresh_token(root)
    await adapter.rotate_refresh_token(
        current_token_id=root.id,
        consumed_at=now,
        new_token=RefreshToken(
            family_id=root.id,
            user_id=user.id,
            session_id="current-session",
            token_hash="current",
            family_created_at=now,
            expires_at=now + timedelta(days=1),
        ),
    )
    await adapter.delete_refresh_tokens_for_session("old-session")
    assert await adapter.get_refresh_token_by_hash("current") is None


def test_jwt_grace_must_cover_token_lifetime() -> None:
    from pydantic import ValidationError

    from fastauth.plugins.jwt import JwtOptions

    with pytest.raises(ValidationError, match="grace_period"):
        JwtOptions(expires_in=timedelta(hours=2), grace_period=timedelta(hours=1))


async def test_concurrent_active_jwks_keys_have_deterministic_selection() -> None:
    import asyncio

    adapter = InMemoryAdapter()
    workers = [registry_for(adapter), registry_for(adapter)]
    created = await asyncio.gather(*(worker.create_key() for worker in workers))
    expected = max(created, key=lambda key: (key.created_at, key.kid))
    selected = await asyncio.gather(*(worker.ensure_key() for worker in workers))
    assert {key.kid for key in selected} == {expected.kid}
    assert {item["kid"] for item in (await workers[0].as_jwks_json()).keys} == {
        key.kid for key in created
    }


async def test_legacy_jwt_identity_is_deterministic_and_not_fresh() -> None:
    adapter = InMemoryAdapter()
    registry = registry_for(adapter)
    strategy = strategy_for(adapter, registry)
    user = await adapter.create_user(User(email="legacy@example.com"))
    token = await LocalKmsSigner(registry).sign(
        header={"alg": "Ed25519"},
        payload={
            "sub": user.id,
            "iss": "test",
            "aud": "test",
            "exp": datetime.now(UTC).timestamp() + 900,
        },
    )
    first, second = await strategy.read(token), await strategy.read(token)
    assert first is not None and second is not None
    assert first.session.id == second.session.id
    assert first.session.authenticated_at is None


async def test_jwt_renew_does_not_make_legacy_authentication_fresh() -> None:
    adapter = InMemoryAdapter()
    strategy = strategy_for(adapter, registry_for(adapter))
    user = await adapter.create_user(User(email="unknown-age@example.com"))
    renewed = await strategy.renew(
        user, session_id="jwt:" + "a" * 32, authenticated_at=None, ip=None, user_agent=None
    )
    read = await strategy.read(renewed.token)
    assert read is not None and read.session.authenticated_at is None
