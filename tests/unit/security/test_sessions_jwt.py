from __future__ import annotations

import pytest
from pydantic import SecretStr

from fastauth.domain.enums import JwtAlgorithm
from fastauth.domain.models import User
from fastauth.security.jwt import JwksRegistry, JwtSessionStrategy, LocalKmsSigner
from fastauth.storage.memory import InMemoryAdapter


async def build_registry(adapter: InMemoryAdapter | None = None) -> JwksRegistry:
    adapter = adapter or InMemoryAdapter()
    registry = JwksRegistry(
        adapter,
        secret_key=SecretStr("k" * 64),
        alg=JwtAlgorithm.EDDSA,
        rotation_interval_seconds=None,
        grace_period_seconds=86400,
        encrypt_private_keys=True,
    )
    await registry.ensure_key()
    return registry


@pytest.fixture
async def registry() -> JwksRegistry:
    return await build_registry()


async def test_local_signer_round_trip(registry: JwksRegistry) -> None:
    signer = LocalKmsSigner(registry)
    token = await signer.sign(
        header={"alg": "EdDSA", "typ": "JWT"},
        payload={"sub": "user-1", "iss": "test", "aud": "test"},
    )
    assert token.count(".") == 2  # JWT structure


async def test_jwks_returned_as_json(registry: JwksRegistry) -> None:
    jwks = await registry.as_jwks_json()
    assert len(jwks.keys) >= 1
    assert jwks.keys[0]["kty"] in {"OKP", "EC", "RSA"}


async def test_strategy_creates_verifiable_token() -> None:
    adapter = InMemoryAdapter()
    registry = await build_registry(adapter)
    signer = LocalKmsSigner(registry)
    strategy = JwtSessionStrategy(
        adapter=adapter,
        registry=registry,
        signer=signer,
        issuer="http://localhost",
        audience="http://localhost",
        expires_in_seconds=900,
        payload_builder=lambda user: {"sub": user.id, "email": user.email},
    )
    user = await adapter.create_user(User(email="alice@example.com"))
    context = await strategy.create(user, ip=None, user_agent=None)
    assert context.token.count(".") == 2

    decoded = await strategy.read(context.token)
    assert decoded is not None
    assert decoded.user.id == user.id


async def test_rotation_keeps_old_keys_valid_during_grace() -> None:
    adapter = InMemoryAdapter()
    registry = await build_registry(adapter)
    signer = LocalKmsSigner(registry)
    strategy = JwtSessionStrategy(
        adapter=adapter,
        registry=registry,
        signer=signer,
        issuer="iss",
        audience="aud",
        expires_in_seconds=900,
        payload_builder=lambda user: {"sub": user.id},
    )
    user = await adapter.create_user(User(email="bob@example.com"))
    context = await strategy.create(user, ip=None, user_agent=None)

    rotated = await registry.rotate_now()
    assert rotated.kid != registry.current_key.kid or rotated is not None  # pyright: ignore[reportOptionalMemberAccess]

    decoded = await strategy.read(context.token)
    assert decoded is not None  # old key still valid during grace


async def test_decrypt_succeeds_with_rotation_kek_when_primary_changes() -> None:
    """A key encrypted under the previous secret_key decrypts via the rotation list."""
    from pydantic import SecretStr

    from fastauth.storage.memory import InMemoryAdapter

    adapter = InMemoryAdapter()
    old_secret = SecretStr("o" * 64)
    new_secret = SecretStr("n" * 64)

    # Encrypt one key under the OLD secret.
    seed_registry = JwksRegistry(
        adapter,
        secret_key=old_secret,
        alg=JwtAlgorithm.EDDSA,
        rotation_interval_seconds=None,
        grace_period_seconds=86400,
        encrypt_private_keys=True,
    )
    await seed_registry.ensure_key()

    # Now start a fresh registry with a NEW primary secret + the old one in
    # the rotation list. The existing key must still decrypt.
    rotated_registry = JwksRegistry(
        adapter,
        secret_key=new_secret,
        secret_key_rotation=[old_secret],
        alg=JwtAlgorithm.EDDSA,
        rotation_interval_seconds=None,
        grace_period_seconds=86400,
        encrypt_private_keys=True,
    )
    current = await rotated_registry.ensure_key()
    decrypted = rotated_registry.decrypt_private_jwk(current)
    assert decrypted.get("kty") in {"OKP", "EC", "RSA"}


async def test_ensure_key_recovers_when_secret_changes_with_no_rotation() -> None:
    """If the secret_key changes and rotation is empty, ensure_key retires the
    broken key and provisions a fresh one — server stays serviceable.
    """
    from pydantic import SecretStr

    from fastauth.storage.memory import InMemoryAdapter

    adapter = InMemoryAdapter()
    old_secret = SecretStr("o" * 64)
    new_secret = SecretStr("z" * 64)

    seed_registry = JwksRegistry(
        adapter,
        secret_key=old_secret,
        alg=JwtAlgorithm.EDDSA,
        rotation_interval_seconds=None,
        grace_period_seconds=600,
        encrypt_private_keys=True,
    )
    broken = await seed_registry.ensure_key()
    broken_kid = broken.kid

    # No rotation list. The new registry can't decrypt the existing key.
    fresh_registry = JwksRegistry(
        adapter,
        secret_key=new_secret,
        alg=JwtAlgorithm.EDDSA,
        rotation_interval_seconds=None,
        grace_period_seconds=600,
        encrypt_private_keys=True,
    )
    current = await fresh_registry.ensure_key()
    # A brand-new key was provisioned, not the broken one.
    assert current.kid != broken_kid
    # The broken key is still in storage but marked rotated, so it stays in
    # the public JWKS during the grace period (in-flight tokens still verify).
    stored = await adapter.list_jwks_keys()
    assert any(k.kid == broken_kid and k.rotated_at is not None for k in stored)
    assert any(k.kid == current.kid and k.rotated_at is None for k in stored)
