from __future__ import annotations

from collections.abc import Callable

# pyright: reportUnknownArgumentType=false, reportUnknownLambdaType=false, reportUnknownMemberType=false, reportUnknownParameterType=false, reportUnknownVariableType=false
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from bson import ObjectId

from fastauth.domain.enums import JwtAlgorithm, ProviderId, VerificationPurpose
from fastauth.domain.models import (
    Account,
    ApiKey,
    JwksKey,
    RefreshToken,
    Session,
    User,
    Verification,
)
from fastauth.storage.beanie.adapter import BeanieAdapter
from fastauth.storage.beanie.documents import (
    AccountDoc,
    ApiKeyDoc,
    JwksKeyDoc,
    RefreshTokenDoc,
    SessionDoc,
    UserDoc,
    VerificationDoc,
)


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("method_name", "document_class", "make_doc", "make_model", "mutate_model"),
    [
        (
            "update_user",
            UserDoc,
            lambda: UserDoc.model_construct(
                id=ObjectId(),
                email="user-update@example.com",
                username=None,
                name="Original",
                image=None,
                email_verified=False,
                pending_email_change=None,
                metadata={},
                created_at=datetime.now(UTC) - timedelta(days=1),
                updated_at=datetime.now(UTC) - timedelta(days=1),
            ),
            lambda doc: User(
                id=str(doc.id),
                email=doc.email,
                username=doc.username,
                name=doc.name,
                image=doc.image,
                email_verified=doc.email_verified,
                pending_email_change=doc.pending_email_change,
                metadata=doc.metadata,
                created_at=doc.created_at,
                updated_at=doc.updated_at,
            ),
            lambda model: setattr(model, "name", "Updated"),
        ),
        (
            "update_session",
            SessionDoc,
            lambda: SessionDoc.model_construct(
                id=ObjectId(),
                user_id=ObjectId(),
                token_hash="session-update",
                expires_at=datetime.now(UTC) + timedelta(days=1),
                ip_address=None,
                user_agent=None,
                created_at=datetime.now(UTC) - timedelta(days=1),
                updated_at=datetime.now(UTC) - timedelta(days=1),
            ),
            lambda doc: Session(
                id=str(doc.id),
                user_id=str(doc.user_id),
                token_hash=doc.token_hash,
                expires_at=doc.expires_at,
                ip_address=doc.ip_address,
                user_agent=doc.user_agent,
                created_at=doc.created_at,
                updated_at=doc.updated_at,
            ),
            lambda model: setattr(model, "user_agent", "updated-agent"),
        ),
        (
            "update_refresh_token",
            RefreshTokenDoc,
            lambda: RefreshTokenDoc.model_construct(
                id=ObjectId(),
                user_id=ObjectId(),
                token_hash="refresh-update",
                family_id=ObjectId(),
                expires_at=datetime.now(UTC) + timedelta(days=1),
                consumed_at=None,
                replaced_by=None,
                ip_address=None,
                user_agent=None,
                created_at=datetime.now(UTC) - timedelta(days=1),
                updated_at=datetime.now(UTC) - timedelta(days=1),
            ),
            lambda doc: RefreshToken(
                id=str(doc.id),
                user_id=str(doc.user_id),
                token_hash=doc.token_hash,
                family_id=str(doc.family_id),
                expires_at=doc.expires_at,
                consumed_at=doc.consumed_at,
                replaced_by=None if doc.replaced_by is None else str(doc.replaced_by),
                ip_address=doc.ip_address,
                user_agent=doc.user_agent,
                created_at=doc.created_at,
                updated_at=doc.updated_at,
            ),
            lambda model: setattr(model, "user_agent", "updated-agent"),
        ),
        (
            "update_account",
            AccountDoc,
            lambda: AccountDoc.model_construct(
                id=ObjectId(),
                user_id=ObjectId(),
                provider_id=ProviderId.CREDENTIAL,
                account_id="acct-update",
                password="argon2",
                access_token=None,
                refresh_token=None,
                access_token_expires_at=None,
                refresh_token_expires_at=None,
                scope=None,
                id_token=None,
                created_at=datetime.now(UTC) - timedelta(days=1),
                updated_at=datetime.now(UTC) - timedelta(days=1),
            ),
            lambda doc: Account(
                id=str(doc.id),
                user_id=str(doc.user_id),
                provider_id=doc.provider_id,
                account_id=doc.account_id,
                password=doc.password,
                access_token=doc.access_token,
                refresh_token=doc.refresh_token,
                access_token_expires_at=doc.access_token_expires_at,
                refresh_token_expires_at=doc.refresh_token_expires_at,
                scope=doc.scope,
                id_token=doc.id_token,
                created_at=doc.created_at,
                updated_at=doc.updated_at,
            ),
            lambda model: setattr(model, "scope", "updated"),
        ),
        (
            "update_api_key",
            ApiKeyDoc,
            lambda: ApiKeyDoc.model_construct(
                id=ObjectId(),
                user_id=ObjectId(),
                name="api-key-update",
                key_hash="api-key-update",
                key_prefix="ak_",
                enabled=True,
                expires_at=None,
                remaining=None,
                refill_amount=None,
                refill_interval_ms=None,
                rate_limit_enabled=False,
                rate_limit_max=None,
                rate_limit_window_ms=None,
                last_refill_at=None,
                last_request_at=None,
                request_count=0,
                metadata={},
                permissions={},
                created_at=datetime.now(UTC) - timedelta(days=1),
                updated_at=datetime.now(UTC) - timedelta(days=1),
            ),
            lambda doc: ApiKey(
                id=str(doc.id),
                user_id=str(doc.user_id),
                name=doc.name,
                key_hash=doc.key_hash,
                key_prefix=doc.key_prefix,
                enabled=doc.enabled,
                expires_at=doc.expires_at,
                remaining=doc.remaining,
                refill_amount=doc.refill_amount,
                refill_interval_ms=doc.refill_interval_ms,
                rate_limit_enabled=doc.rate_limit_enabled,
                rate_limit_max=doc.rate_limit_max,
                rate_limit_window_ms=doc.rate_limit_window_ms,
                last_refill_at=doc.last_refill_at,
                last_request_at=doc.last_request_at,
                request_count=doc.request_count,
                metadata=doc.metadata,
                permissions=doc.permissions,
                created_at=doc.created_at,
                updated_at=doc.updated_at,
            ),
            lambda model: setattr(model, "name", "updated-name"),
        ),
        (
            "update_verification",
            VerificationDoc,
            lambda: VerificationDoc.model_construct(
                id=ObjectId(),
                identifier="verification-update@example.com",
                value_hash="verification-update",
                purpose=VerificationPurpose.EMAIL_VERIFICATION,
                expires_at=datetime.now(UTC) + timedelta(days=1),
                attempt_count=0,
                created_at=datetime.now(UTC) - timedelta(days=1),
                updated_at=datetime.now(UTC) - timedelta(days=1),
            ),
            lambda doc: Verification(
                id=str(doc.id),
                identifier=doc.identifier,
                value_hash=doc.value_hash,
                purpose=doc.purpose,
                expires_at=doc.expires_at,
                attempt_count=doc.attempt_count,
                created_at=doc.created_at,
                updated_at=doc.updated_at,
            ),
            lambda model: setattr(model, "attempt_count", 1),
        ),
        (
            "update_jwks_key",
            JwksKeyDoc,
            lambda: JwksKeyDoc.model_construct(
                id=ObjectId(),
                kid="signing-key",
                alg=JwtAlgorithm.EDDSA,
                public_key="{}",
                private_key_encrypted=b"\x00",
                created_at=datetime.now(UTC) - timedelta(days=1),
                expires_at=None,
                rotated_at=None,
            ),
            lambda doc: JwksKey(
                id=str(doc.id),
                kid=doc.kid,
                alg=doc.alg,
                public_key=doc.public_key,
                private_key_encrypted=doc.private_key_encrypted,
                created_at=doc.created_at,
                expires_at=doc.expires_at,
                rotated_at=doc.rotated_at,
            ),
            lambda model: setattr(model, "alg", JwtAlgorithm.RS256),
        ),
    ],
)
async def test_update_methods_replace_documents(
    monkeypatch: pytest.MonkeyPatch,
    method_name: str,
    document_class: type[Any],
    make_doc: Callable[[], Any],
    make_model: Callable[[Any], Any],
    mutate_model: Callable[[Any], None],
) -> None:
    doc = make_doc()
    model = make_model(doc)
    mutate_model(model)

    set_calls: list[dict[str, Any]] = []
    replace_calls: list[bool] = []

    async def fake_find_one(*args: Any, **kwargs: Any) -> Any:
        return doc

    async def fake_set(self: Any, payload: dict[str, Any]) -> Any:
        set_calls.append(payload)
        return doc

    async def fake_replace(self: Any, *args: Any, **kwargs: Any) -> Any:
        replace_calls.append(True)
        return doc

    monkeypatch.setattr(document_class, "find_one", fake_find_one)
    monkeypatch.setattr(document_class, "id", object(), raising=False)
    monkeypatch.setattr(document_class, "set", fake_set)
    monkeypatch.setattr(document_class, "replace", fake_replace)

    adapter = BeanieAdapter(database=object())  # type: ignore[arg-type]
    result = await getattr(adapter, method_name)(model)

    assert result == model
    assert replace_calls == [True]
    assert set_calls == []

    object_id_fields = {
        "update_session": ["user_id"],
        "update_refresh_token": ["user_id", "family_id"],
        "update_account": ["user_id"],
        "update_api_key": ["user_id"],
    }
    for field_name in object_id_fields.get(method_name, []):
        assert isinstance(getattr(doc, field_name), ObjectId)
