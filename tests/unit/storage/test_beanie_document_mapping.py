from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from bson import ObjectId

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
from fastauth.storage.beanie import documents


def test_beanie_documents_do_not_subclass_domain_models() -> None:
    doc_domain_pairs: list[tuple[type[Any], type[Any]]] = [
        (documents.UserDoc, User),
        (documents.SessionDoc, Session),
        (documents.RefreshTokenDoc, RefreshToken),
        (documents.AccountDoc, Account),
        (documents.VerificationDoc, Verification),
        (documents.ApiKeyDoc, ApiKey),
        (documents.JwksKeyDoc, JwksKey),
        (documents.AuditLogDoc, AuditLog),
        (documents.RateLimitDoc, RateLimit),
    ]

    for doc_class, domain_class in doc_domain_pairs:
        assert not issubclass(doc_class, domain_class)


def test_beanie_document_mappers_preserve_objectid_and_bytes_boundaries() -> None:
    now = datetime.now(UTC)
    user_id = str(ObjectId())
    session_id = str(ObjectId())
    refresh_id = str(ObjectId())
    replacement_id = str(ObjectId())
    account_id = str(ObjectId())
    verification_id = str(ObjectId())
    api_key_id = str(ObjectId())
    jwks_id = str(ObjectId())
    audit_id = str(ObjectId())
    rate_limit_id = str(ObjectId())

    user = User(id=user_id, email="mapping@example.com", name="Mapping")
    session = Session(
        id=session_id,
        user_id=user_id,
        token_hash="session-hash",
        expires_at=now + timedelta(days=1),
    )
    refresh_token = RefreshToken(
        id=refresh_id,
        user_id=user_id,
        token_hash="refresh-hash",
        family_id=refresh_id,
        replaced_by=replacement_id,
        expires_at=now + timedelta(days=30),
    )
    account = Account(
        id=account_id,
        user_id=user_id,
        provider_id=ProviderId.CREDENTIAL,
        account_id="provider-account-id",
        password="argon2",
    )
    verification = Verification(
        id=verification_id,
        identifier="mapping@example.com",
        value_hash="verification-hash",
        purpose=VerificationPurpose.EMAIL_VERIFICATION,
        expires_at=now + timedelta(minutes=15),
    )
    api_key = ApiKey(
        id=api_key_id,
        user_id=user_id,
        name="Mapping key",
        key_hash="api-key-hash",
        key_prefix="ak_",
    )
    jwks_key = JwksKey(
        id=jwks_id,
        kid="mapping-key",
        alg=JwtAlgorithm.EDDSA,
        public_key="{}",
        private_key_encrypted=b"\x00\xff",
    )
    audit_log = AuditLog(
        id=audit_id,
        event_type=AuditEventType.USER_SIGNED_IN,
        user_id=user_id,
        event_data={"ip": "127.0.0.1"},
    )
    rate_limit = RateLimit(id=rate_limit_id, key="ip:path", count=3, last_request_ms=123)

    user_doc = documents.from_user(user)
    session_doc = documents.from_session(session)
    refresh_doc = documents.from_refresh_token(refresh_token)
    account_doc = documents.from_account(account)
    verification_doc = documents.from_verification(verification)
    api_key_doc = documents.from_api_key(api_key)
    jwks_doc = documents.from_jwks_key(jwks_key)
    audit_doc = documents.from_audit_log(audit_log)
    rate_limit_doc = documents.from_rate_limit(rate_limit)

    assert isinstance(user_doc.id, ObjectId)
    assert isinstance(session_doc.id, ObjectId)
    assert isinstance(session_doc.user_id, ObjectId)
    assert isinstance(refresh_doc.family_id, ObjectId)
    assert isinstance(refresh_doc.replaced_by, ObjectId)
    assert isinstance(account_doc.user_id, ObjectId)
    assert isinstance(api_key_doc.user_id, ObjectId)
    assert isinstance(audit_doc.user_id, ObjectId)
    assert jwks_doc.private_key_encrypted == b"\x00\xff"

    assert documents.to_user(user_doc) == user
    assert documents.to_session(session_doc) == session
    assert documents.to_refresh_token(refresh_doc) == refresh_token
    assert documents.to_account(account_doc) == account
    assert documents.to_verification(verification_doc) == verification
    assert documents.to_api_key(api_key_doc) == api_key
    assert documents.to_jwks_key(jwks_doc) == jwks_key
    assert documents.to_audit_log(audit_doc) == audit_log
    assert documents.to_rate_limit(rate_limit_doc) == rate_limit
