"""Reusable contract tests for built-in all-capability adapters."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Protocol

import pytest

from fastauth.domain.enums import AuditEventType, ProviderId, VerificationPurpose
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
from fastauth.storage.base import (
    ApiKeyStore,
    AuditLogStore,
    DatabaseAdapter,
    JwksKeyStore,
    RateLimitStore,
)


class ContractAdapter(
    DatabaseAdapter,
    ApiKeyStore,
    JwksKeyStore,
    AuditLogStore,
    RateLimitStore,
    Protocol,
):
    """All capabilities expected from fastauth's first-party adapters."""


class AdapterContract:
    """Subclasses must override `adapter` as a fixture yielding a fresh full adapter."""

    @pytest.fixture
    async def adapter(self) -> ContractAdapter:  # pragma: no cover - override
        raise NotImplementedError

    async def test_user_crud(self, adapter: ContractAdapter) -> None:
        user = await adapter.create_user(User(email="alice@example.com"))
        fetched = await adapter.get_user_by_id(user.id)
        assert fetched == user
        by_email = await adapter.get_user_by_email("alice@example.com")
        assert by_email == user
        user.name = "Alice"
        updated = await adapter.update_user(user)
        assert updated.name == "Alice"
        await adapter.delete_user(user.id)
        assert await adapter.get_user_by_id(user.id) is None

    async def test_user_email_is_unique(self, adapter: ContractAdapter) -> None:
        from fastauth.exceptions import DuplicateError

        await adapter.create_user(User(email="bob@example.com"))
        with pytest.raises(DuplicateError):
            await adapter.create_user(User(email="bob@example.com"))

    async def test_find_user_by_pending_email_change(
        self,
        adapter: ContractAdapter,
    ) -> None:
        user = await adapter.create_user(User(email="orig@example.com"))
        # Nobody has a pending change yet.
        assert await adapter.find_user_by_pending_email_change("new@example.com") is None
        # Apply a pending change and confirm the lookup hits.
        user.pending_email_change = "new@example.com"
        await adapter.update_user(user)
        found = await adapter.find_user_by_pending_email_change("new@example.com")
        assert found is not None
        assert found.id == user.id

    async def test_session_lifecycle(self, adapter: ContractAdapter) -> None:
        user = await adapter.create_user(User(email="carol@example.com"))
        session = Session(
            user_id=user.id,
            token_hash="hash-1",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
        await adapter.create_session(session)
        assert await adapter.get_session_by_token_hash("hash-1") == session
        sessions = await adapter.list_sessions_for_user(user.id)
        assert sessions == [session]
        await adapter.delete_session(session.id)
        assert await adapter.get_session_by_token_hash("hash-1") is None

    async def test_delete_sessions_for_user(self, adapter: ContractAdapter) -> None:
        user = await adapter.create_user(User(email="d@example.com"))
        for index in range(3):
            await adapter.create_session(
                Session(
                    user_id=user.id,
                    token_hash=f"hash-{index}",
                    expires_at=datetime.now(UTC) + timedelta(hours=1),
                )
            )
        deleted = await adapter.delete_sessions_for_user(user.id)
        assert deleted == 3

    async def test_account_round_trip(self, adapter: ContractAdapter) -> None:
        user = await adapter.create_user(User(email="e@example.com"))
        account = Account(
            user_id=user.id,
            provider_id=ProviderId.CREDENTIAL,
            account_id=user.id,
            password="argon2",
        )
        await adapter.create_account(account)
        fetched = await adapter.get_account_for_user(user.id, ProviderId.CREDENTIAL)
        assert fetched == account

    async def test_delete_user_removes_auth_state_but_preserves_audit_logs(
        self,
        adapter: ContractAdapter,
    ) -> None:
        user = await adapter.create_user(User(email="delete@example.com"))
        await adapter.create_account(
            Account(
                user_id=user.id,
                provider_id=ProviderId.CREDENTIAL,
                account_id=user.id,
                password="argon2",
            )
        )
        session = await adapter.create_session(
            Session(
                user_id=user.id,
                token_hash="delete-session",
                expires_at=datetime.now(UTC) + timedelta(hours=1),
            )
        )
        await adapter.create_refresh_token(
            RefreshToken(
                user_id=user.id,
                token_hash="delete-refresh",
                family_id="delete-family",
                expires_at=datetime.now(UTC) + timedelta(days=1),
            )
        )
        await adapter.create_api_key(
            ApiKey(user_id=user.id, name="delete-key", key_hash="delete-key", key_prefix="ak_")
        )
        await adapter.create_verification(
            Verification(
                identifier=user.email,
                value_hash="delete-verification",
                purpose=VerificationPurpose.ACCOUNT_DELETION,
                expires_at=datetime.now(UTC) + timedelta(minutes=15),
            )
        )
        await adapter.create_audit_log(
            AuditLog(
                event_type=AuditEventType.USER_DELETED,
                identifier=user.email,
                user_id=user.id,
            )
        )

        await adapter.delete_user(user.id)

        assert await adapter.get_user_by_id(user.id) is None
        assert await adapter.get_account_for_user(user.id, ProviderId.CREDENTIAL) is None
        assert await adapter.get_session_by_token_hash(session.token_hash) is None
        assert await adapter.get_refresh_token_by_hash("delete-refresh") is None
        assert await adapter.get_active_verification(
            user.email,
            VerificationPurpose.ACCOUNT_DELETION,
        ) is None
        _api_keys, api_key_total = await adapter.list_api_keys_for_user(user.id)
        assert api_key_total == 0
        audit_logs, audit_total = await adapter.list_audit_logs(
            user_id=user.id,
            event_type=AuditEventType.USER_DELETED,
            identifier=None,
            limit=10,
            offset=0,
        )
        assert audit_total == 1
        assert audit_logs[0].identifier == user.email

    async def test_verification_round_trip(self, adapter: ContractAdapter) -> None:
        verification = Verification(
            identifier="f@example.com",
            value_hash="vh",
            purpose=VerificationPurpose.EMAIL_VERIFICATION,
            expires_at=datetime.now(UTC) + timedelta(minutes=15),
        )
        await adapter.create_verification(verification)
        found = await adapter.get_verification(
            "f@example.com",
            VerificationPurpose.EMAIL_VERIFICATION,
            "vh",
        )
        assert found == verification
        await adapter.delete_verification(verification.id)
        assert (
            await adapter.get_verification(
                "f@example.com",
                VerificationPurpose.EMAIL_VERIFICATION,
                "vh",
            )
            is None
        )

    async def test_get_active_verification_and_update(
        self,
        adapter: ContractAdapter,
    ) -> None:
        # No row → None.
        assert (
            await adapter.get_active_verification(
                "otp@example.com",
                VerificationPurpose.EMAIL_OTP_SIGN_IN,
            )
            is None
        )
        verification = Verification(
            identifier="otp@example.com",
            value_hash="hashed_otp",
            purpose=VerificationPurpose.EMAIL_OTP_SIGN_IN,
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )
        await adapter.create_verification(verification)
        # get_active returns the row without needing the value_hash.
        active = await adapter.get_active_verification(
            "otp@example.com",
            VerificationPurpose.EMAIL_OTP_SIGN_IN,
        )
        assert active is not None
        assert active.id == verification.id
        assert active.attempt_count == 0
        # update_verification persists changes.
        active.attempt_count = 2
        await adapter.update_verification(active)
        reloaded = await adapter.get_active_verification(
            "otp@example.com",
            VerificationPurpose.EMAIL_OTP_SIGN_IN,
        )
        assert reloaded is not None
        assert reloaded.attempt_count == 2
        # Cleanup so the next test in the suite starts clean against shared Mongo.
        await adapter.delete_verification(verification.id)

    async def test_api_key_pagination(self, adapter: ContractAdapter) -> None:
        user = await adapter.create_user(User(email="g@example.com"))
        for index in range(5):
            await adapter.create_api_key(
                ApiKey(
                    user_id=user.id,
                    name=f"key-{index}",
                    key_hash=f"h-{index}",
                    key_prefix="ak_",
                )
            )
        items, total = await adapter.list_api_keys_for_user(user.id, limit=2, offset=0)
        assert total == 5
        assert len(items) == 2

    async def test_jwks_key_round_trip(self, adapter: ContractAdapter) -> None:
        key = JwksKey(kid="k1", alg="EdDSA", public_key="{}", private_key_encrypted=b"\x00")
        await adapter.create_jwks_key(key)
        keys = await adapter.list_jwks_keys()
        assert key in keys

    async def test_audit_log_filtering(self, adapter: ContractAdapter) -> None:
        # FK fields are real ObjectIds in MongoDB; the contract uses a valid 24-char
        # hex literal so the test is interchangeable between InMemoryAdapter and
        # BeanieAdapter without coupling the contract module to ``bson``.
        actor_id = "507f1f77bcf86cd799439011"
        await adapter.create_audit_log(
            AuditLog(
                event_type=AuditEventType.USER_SIGNED_IN,
                identifier="x",
                user_id=actor_id,
            )
        )
        await adapter.create_audit_log(
            AuditLog(
                event_type=AuditEventType.USER_SIGNED_OUT,
                identifier="x",
                user_id=actor_id,
            )
        )
        rows, total = await adapter.list_audit_logs(
            user_id=actor_id,
            event_type=AuditEventType.USER_SIGNED_IN,
            identifier=None,
            limit=10,
            offset=0,
        )
        assert total == 1
        assert rows[0].event_type is AuditEventType.USER_SIGNED_IN

    async def test_rate_limit_upsert(self, adapter: ContractAdapter) -> None:
        await adapter.upsert_rate_limit(RateLimit(key="k", count=1, last_request_ms=1))
        await adapter.upsert_rate_limit(RateLimit(key="k", count=2, last_request_ms=2))
        rl = await adapter.get_rate_limit("k")
        assert rl is not None
        assert rl.count == 2
