from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import BaseModel

from fastauth.domain.enums import AuditEventType, JwtAlgorithm, ProviderId, VerificationPurpose
from fastauth.domain.models import (
    Account,
    ApiKey,
    AuditLog,
    JwksKey,
    RateLimit,
    RefreshToken,
    Session,
    User,
    Verification,
)
from fastauth.storage.memory import InMemoryAdapter


@pytest.mark.parametrize(
    "kind,model,getter,args,field,replacement",
    [
        (
            "user",
            User(email="isolation@example.com", name="original"),
            "get_user_by_email",
            ("isolation@example.com",),
            "name",
            "changed",
        ),
        (
            "account",
            Account(
                user_id="user",
                provider_id=ProviderId.CREDENTIAL,
                account_id="user",
                password="original",
            ),
            "get_account_for_user",
            ("user", ProviderId.CREDENTIAL),
            "password",
            "changed",
        ),
        (
            "session",
            Session(user_id="user", token_hash="original", expires_at=datetime.now(UTC)),
            "get_session_by_token_hash",
            ("original",),
            "user_agent",
            "changed",
        ),
        (
            "refresh_token",
            RefreshToken(
                user_id="user",
                session_id="session",
                token_hash="original",
                family_id="family",
                family_created_at=datetime.now(UTC),
                expires_at=datetime.now(UTC),
            ),
            "get_refresh_token_by_hash",
            ("original",),
            "user_agent",
            "changed",
        ),
        (
            "verification",
            Verification(
                identifier="isolation@example.com",
                value_hash="original",
                purpose=VerificationPurpose.PASSWORD_RESET,
                expires_at=datetime.now(UTC) + timedelta(minutes=5),
            ),
            "get_active_verification",
            ("isolation@example.com", VerificationPurpose.PASSWORD_RESET),
            "attempt_count",
            9,
        ),
        (
            "api_key",
            ApiKey(user_id="user", name="original", key_hash="original", key_prefix="key"),
            "get_api_key_by_hash",
            ("original",),
            "name",
            "changed",
        ),
        (
            "jwks_key",
            JwksKey(
                kid="key",
                alg=JwtAlgorithm.ED25519,
                public_key="original",
                private_key_encrypted=b"original",
            ),
            "list_jwks_keys",
            (),
            "public_key",
            "changed",
        ),
        (
            "audit_log",
            AuditLog(event_type=AuditEventType.USER_CREATED, identifier="original"),
            "list_audit_logs",
            (),
            "identifier",
            "changed",
        ),
        (
            "rate_limit",
            RateLimit(key="key", count=1, last_request_ms=0),
            "get_rate_limit",
            ("key",),
            "count",
            9,
        ),
    ],
)
@pytest.mark.parametrize("boundary", ["input", "create", "read"])
async def test_models_are_isolated_from_persisted_state(
    kind: str,
    model: BaseModel,
    getter: str,
    args: tuple[object, ...],
    field: str,
    replacement: object,
    boundary: str,
) -> None:
    adapter = InMemoryAdapter()
    source = model.model_copy(deep=True)
    expected = getattr(source, field)
    writer = "upsert_rate_limit" if kind == "rate_limit" else f"create_{kind}"
    created = await getattr(adapter, writer)(source)

    async def read() -> BaseModel:
        if kind == "audit_log":
            rows, count = await adapter.list_audit_logs(
                user_id=None,
                event_type=None,
                identifier=None,
                limit=10,
                offset=0,
            )
            assert count == 1
            return rows[0]
        if kind == "jwks_key":
            return (await adapter.list_jwks_keys())[0]
        loaded = await getattr(adapter, getter)(*args)
        assert isinstance(loaded, BaseModel)
        return loaded

    exposed = source if boundary == "input" else created if boundary == "create" else await read()
    setattr(exposed, field, replacement)
    assert getattr(await read(), field) == expected


async def test_nested_user_metadata_is_isolated_from_reads_and_listings() -> None:
    adapter = InMemoryAdapter()
    user = await adapter.create_user(User(email="nested@example.com", metadata={"a": {"b": 1}}))
    loaded = await adapter.get_user_by_id(user.id)
    assert loaded is not None
    nested = loaded.metadata["a"]
    assert isinstance(nested, dict)
    nested["b"] = 2
    persisted = await adapter.get_user_by_id(user.id)
    assert persisted is not None and persisted.metadata == {"a": {"b": 1}}


async def test_list_models_and_update_return_values_are_isolated() -> None:
    adapter = InMemoryAdapter()
    session = await adapter.create_session(
        Session(
            user_id="user", token_hash="token", expires_at=datetime.now(UTC) + timedelta(days=1)
        )
    )
    session.user_agent = "persisted"
    updated = await adapter.update_session(session)
    updated.user_agent = "not persisted"
    listed = await adapter.list_sessions_for_user("user")
    assert listed[0].user_agent == "persisted"
    listed[0].user_agent = "also not persisted"
    current = await adapter.get_session_by_token_hash("token")
    assert current is not None and current.user_agent == "persisted"
