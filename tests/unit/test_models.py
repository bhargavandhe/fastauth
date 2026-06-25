from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from authkit.domain.enums import AuditEventType, ProviderId, VerificationPurpose
from authkit.domain.models import (
    Account,
    ApiKey,
    AuditLog,
    EmailMessage,
    JwksKey,
    RateLimit,
    Session,
    User,
    Verification,
    new_id,
)


def test_new_id_returns_hex_uuid() -> None:
    value = new_id()
    assert len(value) == 32
    assert all(character in "0123456789abcdef" for character in value)


def test_user_round_trip() -> None:
    user = User(email="alice@example.com", name="Alice")
    assert user.id  # auto-generated
    assert user.email_verified is False
    payload = user.model_dump_json()
    restored = User.model_validate_json(payload)
    assert restored == user


def test_user_rejects_invalid_email() -> None:
    with pytest.raises(ValidationError):
        User(email="not-an-email")


def test_session_requires_user_id_and_token_hash() -> None:
    now = datetime.now(UTC)
    session = Session(
        user_id="user-1",
        token_hash="abc",
        expires_at=now + timedelta(hours=1),
    )
    assert session.id
    assert session.created_at <= now + timedelta(seconds=1)


def test_account_provider_is_enum() -> None:
    account = Account(
        user_id="user-1",
        provider_id=ProviderId.CREDENTIAL,
        account_id="user-1",
        password="argon2-hash",
    )
    assert account.provider_id is ProviderId.CREDENTIAL


def test_verification_purpose_enum() -> None:
    verification = Verification(
        identifier="alice@example.com",
        value_hash="hash",
        purpose=VerificationPurpose.EMAIL_VERIFICATION,
        expires_at=datetime.now(UTC) + timedelta(minutes=15),
    )
    assert verification.purpose is VerificationPurpose.EMAIL_VERIFICATION


def test_api_key_defaults() -> None:
    key = ApiKey(user_id="user-1", name="ci-key", key_hash="h", key_prefix="ak_")
    assert key.enabled is True
    assert key.remaining is None
    assert key.metadata == {}
    assert key.permissions == {}


def test_jwks_key_minimum_fields() -> None:
    key = JwksKey(
        public_key='{"kty":"OKP"}',
        private_key_encrypted=b"\x00",
        alg="EdDSA",
        kid="k1",
    )
    assert key.id


def test_rate_limit_zero_default() -> None:
    rl = RateLimit(key="ip:127.0.0.1:/sign-in/email", count=0, last_request_ms=0)
    assert rl.count == 0


def test_audit_log_event_type_enum() -> None:
    row = AuditLog(
        event_type=AuditEventType.USER_SIGNED_IN,
        identifier="alice@example.com",
        user_id="user-1",
        ip_address="127.0.0.1",
        user_agent="pytest",
        event_data={},
    )
    assert row.event_type is AuditEventType.USER_SIGNED_IN


def test_email_message_is_pydantic() -> None:
    message = EmailMessage(
        to="alice@example.com",
        subject="Verify your email",
        html="<p>hi</p>",
        text="hi",
    )
    assert message.to == "alice@example.com"


def test_user_metadata_defaults_to_empty_dict() -> None:
    """User.metadata is a free-form dict for application-side extension fields."""
    user = User(email="alice@example.com")
    assert user.metadata == {}


def test_user_metadata_round_trips_arbitrary_payload() -> None:
    user = User(
        email="bob@example.com",
        metadata={"preferred_locale": "fr-FR", "avatar_url": "https://x/y.png", "is_beta": True},
    )
    payload = user.model_dump_json()
    restored = User.model_validate_json(payload)
    assert restored.metadata == user.metadata
    assert restored.metadata["preferred_locale"] == "fr-FR"
