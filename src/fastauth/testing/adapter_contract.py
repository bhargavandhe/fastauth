"""Reusable pytest contract tests for FastAuth storage adapters."""

from __future__ import annotations

import asyncio
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
    new_id,
)
from fastauth.storage.base import (
    AccountStore,
    ApiKeyStore,
    AuditLogStore,
    DatabaseAdapter,
    JwksKeyStore,
    PasswordRehashStore,
    RateLimitStore,
    RefreshTokenStore,
    SessionStore,
    UserStatusStore,
    UserStore,
    VerificationStore,
)

__all__ = [
    "AdapterContract",
    "ApiKeyAdapterContract",
    "AuditLogAdapterContract",
    "ContractAdapter",
    "CoreAdapterContract",
    "CreationAdapterContract",
    "FullAdapterContract",
    "JwksAdapterContract",
    "MaintenanceAdapterContract",
    "PasswordRehashAdapterContract",
    "RateLimitAdapterContract",
    "RefreshTokenAdapterContract",
    "UserStatusAdapterContract",
]


class ContractAdapter(
    DatabaseAdapter,
    ApiKeyStore,
    JwksKeyStore,
    AuditLogStore,
    RateLimitStore,
    Protocol,
):
    """All capabilities expected from fastauth's first-party adapters."""


class UserStatusContractAdapter(UserStore, UserStatusStore, Protocol):
    """User storage plus privileged activation changes."""


class PasswordRehashContractAdapter(UserStore, AccountStore, PasswordRehashStore, Protocol):
    """Setup stores for optional optimistic credential upgrades."""


class CoreContractAdapter(
    UserStore,
    SessionStore,
    AccountStore,
    VerificationStore,
    Protocol,
):
    """Core non-refresh capabilities used by the core adapter contract."""


class RefreshTokenContractAdapter(
    UserStore,
    SessionStore,
    RefreshTokenStore,
    Protocol,
):
    """Refresh-token capabilities plus setup stores needed by the contract."""


class ApiKeyContractAdapter(
    UserStore,
    ApiKeyStore,
    Protocol,
):
    """API-key capabilities plus setup stores needed by the contract."""


class AdapterContractBase:
    """Subclasses must override `adapter` as a fixture yielding a fresh adapter."""

    @pytest.fixture
    async def adapter(self) -> object:  # pragma: no cover - override
        raise NotImplementedError


class CoreAdapterContract(AdapterContractBase):
    """Contract tests for users, sessions, accounts, and verifications."""

    async def test_user_crud(self, adapter: CoreContractAdapter) -> None:
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

    async def test_user_email_is_unique(self, adapter: CoreContractAdapter) -> None:
        from fastauth.exceptions import DuplicateError

        await adapter.create_user(User(email="bob@example.com"))
        with pytest.raises(DuplicateError):
            await adapter.create_user(User(email="bob@example.com"))

    async def test_user_username_is_unique(self, adapter: CoreContractAdapter) -> None:
        from fastauth.exceptions import DuplicateError

        await adapter.create_user(User(email="bob@example.com", username="shared"))
        with pytest.raises(DuplicateError) as exc_info:
            await adapter.create_user(User(email="alice@example.com", username="shared"))
        assert exc_info.value.message == "user with duplicate username"

    async def test_user_username_remains_unique_on_update(
        self,
        adapter: CoreContractAdapter,
    ) -> None:
        from fastauth.exceptions import DuplicateError

        first = await adapter.create_user(User(email="first@example.com", username="first"))
        await adapter.create_user(User(email="second@example.com", username="second"))
        first.username = "second"

        with pytest.raises(DuplicateError) as exc_info:
            await adapter.update_user(first)
        assert exc_info.value.message == "user with duplicate username"

    async def test_find_user_by_pending_email_change(
        self,
        adapter: CoreContractAdapter,
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

    async def test_session_lifecycle(self, adapter: CoreContractAdapter) -> None:
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

    async def test_delete_sessions_for_user(self, adapter: CoreContractAdapter) -> None:
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

    async def test_account_round_trip(self, adapter: CoreContractAdapter) -> None:
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

    async def test_verification_round_trip(self, adapter: CoreContractAdapter) -> None:
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

    async def test_nullable_usernames_coexist(self, adapter: CoreContractAdapter) -> None:
        first = await adapter.create_user(User(email="null-one@example.com"))
        second = await adapter.create_user(User(email="null-two@example.com"))
        assert first.id != second.id

    async def test_atomic_verification_has_exactly_one_concurrent_winner(
        self,
        adapter: CoreContractAdapter,
    ) -> None:
        row = await adapter.create_verification(
            Verification(
                identifier="atomic@example.com",
                purpose=VerificationPurpose.EMAIL_OTP_SIGN_IN,
                value_hash="valid",
                expires_at=datetime.now(UTC) + timedelta(minutes=5),
            )
        )
        results = await asyncio.gather(
            *(
                adapter.attempt_verification(
                    row.identifier,
                    row.purpose,
                    "valid",
                    now=attempt_time,
                    max_attempts=3,
                )
                for attempt_time in [datetime.now(UTC)] * 12
            )
        )
        assert sum(result.status == "accepted" for result in results) == 1
        assert await adapter.get_active_verification(row.identifier, row.purpose) is None

    async def test_atomic_verification_counts_concurrent_misses_and_burns_code(
        self,
        adapter: CoreContractAdapter,
    ) -> None:
        row = await adapter.create_verification(
            Verification(
                identifier="attempts@example.com",
                purpose=VerificationPurpose.EMAIL_OTP_SIGN_IN,
                value_hash="valid",
                expires_at=datetime.now(UTC) + timedelta(minutes=5),
            )
        )
        results = await asyncio.gather(
            *(
                adapter.attempt_verification(
                    row.identifier,
                    row.purpose,
                    "wrong",
                    now=attempt_time,
                    max_attempts=3,
                )
                for attempt_time in [datetime.now(UTC)] * 3
            )
        )
        assert sorted(result.attempt_count for result in results) == [1, 2, 3]
        result = await adapter.attempt_verification(
            row.identifier,
            row.purpose,
            "valid",
            now=datetime.now(UTC),
            max_attempts=3,
        )
        assert result.status != "accepted"
        assert await adapter.get_active_verification(row.identifier, row.purpose) is None

    async def test_new_verification_supersedes_old_even_after_consumption(
        self,
        adapter: CoreContractAdapter,
    ) -> None:
        old = await adapter.create_verification(
            Verification(
                identifier="superseded@example.com",
                purpose=VerificationPurpose.PASSWORD_RESET,
                value_hash="old",
                expires_at=datetime.now(UTC) + timedelta(minutes=5),
            )
        )
        await adapter.create_verification(old.model_copy(update={"value_hash": "new"}))
        rejected = await adapter.attempt_verification(
            old.identifier,
            old.purpose,
            "old",
            now=datetime.now(UTC),
        )
        assert rejected.status == "invalid"
        accepted = await adapter.attempt_verification(
            old.identifier,
            old.purpose,
            "new",
            now=datetime.now(UTC),
        )
        assert accepted.status == "accepted"
        replay = await adapter.attempt_verification(
            old.identifier,
            old.purpose,
            "old",
            now=datetime.now(UTC),
        )
        assert replay.status != "accepted"

    async def test_atomic_check_preserves_valid_code_but_counts_failed_attempts(
        self,
        adapter: CoreContractAdapter,
    ) -> None:
        now = datetime.now(UTC)
        row = await adapter.create_verification(
            Verification(
                identifier="check@example.com",
                purpose=VerificationPurpose.EMAIL_OTP_SIGN_IN,
                value_hash="valid",
                expires_at=now + timedelta(minutes=5),
            )
        )
        checked = await adapter.attempt_verification(
            row.identifier,
            row.purpose,
            "valid",
            now=now,
            max_attempts=3,
            consume=False,
        )
        assert checked.status == "accepted"
        assert await adapter.get_active_verification(row.identifier, row.purpose) is not None
        missed = await adapter.attempt_verification(
            row.identifier,
            row.purpose,
            "wrong",
            now=now,
            max_attempts=3,
            consume=False,
        )
        assert missed.attempt_count == 1
        expired = await adapter.attempt_verification(
            row.identifier,
            row.purpose,
            "valid",
            now=now + timedelta(minutes=6),
            max_attempts=3,
        )
        assert expired.status == "expired"

    async def test_get_active_verification_and_update(
        self,
        adapter: CoreContractAdapter,
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


class ApiKeyAdapterContract(AdapterContractBase):
    """Contract tests for ``ApiKeyStore`` implementations."""

    async def test_api_key_pagination(self, adapter: ApiKeyContractAdapter) -> None:
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


class JwksAdapterContract(AdapterContractBase):
    """Contract tests for ``JwksKeyStore`` implementations."""

    async def test_jwks_key_round_trip(self, adapter: JwksKeyStore) -> None:
        key = JwksKey(kid="k1", alg="Ed25519", public_key="{}", private_key_encrypted=b"\x00")
        await adapter.create_jwks_key(key)
        keys = await adapter.list_jwks_keys()
        assert key in keys


class AuditLogAdapterContract(AdapterContractBase):
    """Contract tests for ``AuditLogStore`` implementations."""

    async def test_audit_log_filtering(self, adapter: AuditLogStore) -> None:
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


class MaintenanceAdapterContract(AdapterContractBase):
    """Contract tests for bounded retention operations."""

    async def test_ping(self, adapter: ContractAdapter) -> None:
        await adapter.ping()

    async def test_cleanup_operations_are_bounded_and_idempotent(
        self,
        adapter: ContractAdapter,
    ) -> None:
        now = datetime.now(UTC)
        cutoff = now + timedelta(days=10)
        user = await adapter.create_user(User(email="maintenance-contract@example.com"))
        expired_sessions: list[Session] = []
        for index in range(2):
            expired_sessions.append(
                await adapter.create_session(
                    Session(
                        user_id=user.id,
                        token_hash=f"maintenance-expired-session-{index}",
                        expires_at=now + timedelta(days=1),
                    )
                )
            )
        live_session = await adapter.create_session(
            Session(
                user_id=user.id,
                token_hash="maintenance-live-session",
                expires_at=now + timedelta(days=20),
            )
        )

        assert await adapter.delete_expired_sessions(cutoff=cutoff, limit=1) == 1
        assert await adapter.delete_expired_sessions(cutoff=cutoff, limit=1) == 1
        assert await adapter.delete_expired_sessions(cutoff=cutoff, limit=1) == 0
        assert await adapter.get_session_by_token_hash(live_session.token_hash) is not None
        for row in expired_sessions:
            assert await adapter.get_session_by_token_hash(row.token_hash) is None

        expired_refresh_id = new_id()
        expired_refresh = await adapter.create_refresh_token(
            RefreshToken(
                id=expired_refresh_id,
                user_id=user.id,
                session_id=live_session.id,
                token_hash="maintenance-expired-refresh",
                family_id=expired_refresh_id,
                family_created_at=now,
                expires_at=now + timedelta(days=1),
            )
        )
        live_refresh_id = new_id()
        live_refresh = await adapter.create_refresh_token(
            RefreshToken(
                id=live_refresh_id,
                user_id=user.id,
                session_id=live_session.id,
                token_hash="maintenance-live-refresh",
                family_id=live_refresh_id,
                family_created_at=now,
                expires_at=now + timedelta(days=20),
            )
        )
        assert await adapter.delete_expired_refresh_tokens(cutoff=cutoff, limit=1) == 1
        assert await adapter.get_refresh_token_by_hash(expired_refresh.token_hash) is None
        assert await adapter.get_refresh_token_by_hash(live_refresh.token_hash) is not None

        expired_verification = await adapter.create_verification(
            Verification(
                identifier=user.email,
                value_hash="maintenance-expired-verification",
                purpose=VerificationPurpose.EMAIL_VERIFICATION,
                expires_at=now + timedelta(days=1),
            )
        )
        live_verification = await adapter.create_verification(
            Verification(
                identifier=user.email,
                value_hash="maintenance-live-verification",
                purpose=VerificationPurpose.PASSWORD_RESET,
                expires_at=now + timedelta(days=20),
            )
        )
        assert await adapter.delete_expired_verifications(cutoff=cutoff, limit=1) == 1
        assert (
            await adapter.get_verification(
                expired_verification.identifier,
                expired_verification.purpose,
                expired_verification.value_hash,
            )
            is None
        )
        assert (
            await adapter.get_verification(
                live_verification.identifier,
                live_verification.purpose,
                live_verification.value_hash,
            )
            is not None
        )

        expired_api_key = await adapter.create_api_key(
            ApiKey(
                user_id=user.id,
                name="maintenance-expired",
                key_hash="maintenance-expired-key",
                key_prefix="ak_expired",
                expires_at=now + timedelta(days=1),
            )
        )
        live_api_key = await adapter.create_api_key(
            ApiKey(
                user_id=user.id,
                name="maintenance-live",
                key_hash="maintenance-live-key",
                key_prefix="ak_live",
                expires_at=now + timedelta(days=20),
            )
        )
        assert await adapter.delete_expired_api_keys(cutoff=cutoff, limit=1) == 1
        assert await adapter.get_api_key_by_id(expired_api_key.id) is None
        assert await adapter.get_api_key_by_id(live_api_key.id) is not None

        old_log = await adapter.create_audit_log(
            AuditLog(event_type=AuditEventType.USER_CREATED, created_at=now - timedelta(days=20))
        )
        new_log = await adapter.create_audit_log(
            AuditLog(event_type=AuditEventType.USER_CREATED, created_at=now)
        )
        assert (
            await adapter.delete_audit_logs_before(
                cutoff=now - timedelta(days=10),
                limit=1,
            )
            == 1
        )
        rows, _ = await adapter.list_audit_logs(
            user_id=None,
            event_type=AuditEventType.USER_CREATED,
            identifier=None,
            limit=100,
            offset=0,
        )
        assert old_log.id not in {row.id for row in rows}
        assert new_log.id in {row.id for row in rows}


class RateLimitAdapterContract(AdapterContractBase):
    """Contract tests for ``RateLimitStore`` implementations."""

    async def test_rate_limit_upsert(self, adapter: RateLimitStore) -> None:
        await adapter.upsert_rate_limit(RateLimit(key="k", count=1, last_request_ms=1))
        await adapter.upsert_rate_limit(RateLimit(key="k", count=2, last_request_ms=2))
        rl = await adapter.get_rate_limit("k")
        assert rl is not None
        assert rl.count == 2

    async def test_rate_limit_increment_uses_original_window_start(
        self,
        adapter: RateLimitStore,
    ) -> None:
        assert await adapter.increment_rate_limit("k", window_ms=10_000, now_ms=0) == (1, 0)
        assert await adapter.increment_rate_limit("k", window_ms=10_000, now_ms=5_000) == (
            2,
            0,
        )
        assert await adapter.increment_rate_limit("k", window_ms=10_000, now_ms=11_000) == (
            1,
            11_000,
        )

    async def test_rate_limit_rekey_merges_active_buckets(
        self,
        adapter: RateLimitStore,
    ) -> None:
        await adapter.upsert_rate_limit(RateLimit(key="old", count=4, last_request_ms=1_000))
        await adapter.upsert_rate_limit(RateLimit(key="new", count=5, last_request_ms=2_000))

        await adapter.rekey_rate_limit(
            "old",
            "new",
            window_ms=60_000,
            now_ms=10_000,
        )

        assert await adapter.get_rate_limit("old") is None
        destination = await adapter.get_rate_limit("new")
        assert destination is not None
        assert destination.count == 5
        assert destination.last_request_ms == 2_000


class RefreshTokenAdapterContract(AdapterContractBase):
    """Contract tests for ``RefreshTokenStore`` implementations."""

    async def test_refresh_token_rotation_contract(
        self,
        adapter: RefreshTokenContractAdapter,
    ) -> None:
        user = await adapter.create_user(User(email="refresh-contract@example.com"))
        session = await adapter.create_session(
            Session(
                user_id=user.id,
                token_hash="refresh-contract-session",
                expires_at=datetime.now(UTC) + timedelta(hours=1),
            )
        )
        root_id = new_id()
        family_created_at = datetime.now(UTC)
        root = await adapter.create_refresh_token(
            RefreshToken(
                id=root_id,
                user_id=user.id,
                session_id=session.id,
                token_hash="refresh-contract-root",
                family_id=root_id,
                family_created_at=family_created_at,
                expires_at=datetime.now(UTC) + timedelta(days=1),
            )
        )
        assert root.family_id == root.id

        consumed_at = datetime.now(UTC)
        successor = RefreshToken(
            user_id=user.id,
            session_id=session.id,
            token_hash="refresh-contract-successor",
            family_id=root.family_id,
            family_created_at=family_created_at,
            expires_at=datetime.now(UTC) + timedelta(days=1),
        )
        rotated = await adapter.rotate_refresh_token(
            current_token_id=root.id,
            new_token=successor,
            consumed_at=consumed_at,
        )
        assert rotated is not None
        assert rotated.user_id == user.id
        assert rotated.family_id == root.family_id

        consumed_root = await adapter.get_refresh_token_by_hash("refresh-contract-root")
        assert consumed_root is not None
        assert consumed_root.consumed_at is not None
        assert consumed_root.replaced_by == rotated.id

        stored_successor = await adapter.get_refresh_token_by_hash("refresh-contract-successor")
        assert stored_successor == rotated

        second_rotate = await adapter.rotate_refresh_token(
            current_token_id=root.id,
            new_token=RefreshToken(
                user_id=user.id,
                session_id=session.id,
                token_hash="refresh-contract-loser",
                family_id=root.family_id,
                family_created_at=family_created_at,
                expires_at=datetime.now(UTC) + timedelta(days=1),
            ),
            consumed_at=datetime.now(UTC),
        )
        assert second_rotate is None

    @pytest.mark.parametrize(
        "entrypoint", ["session", "user", "user_except", "family", "legacy_family"]
    )
    async def test_family_revocation_removes_access_sessions(
        self, adapter: RefreshTokenContractAdapter, entrypoint: str
    ) -> None:
        user = await adapter.create_user(User(email="revoke-family@example.com"))
        other = await adapter.create_user(User(email="unrelated-family@example.com"))
        now = datetime.now(UTC)
        families: dict[str, list[RefreshToken]] = {}
        sessions: dict[str, list[Session]] = {}
        for label, owner in (("target", user), ("kept", user), ("unrelated", other)):
            sessions[label] = [
                await adapter.create_session(
                    Session(
                        user_id=owner.id,
                        token_hash=f"{label}-session-{index}",
                        expires_at=now + timedelta(hours=1),
                    )
                )
                for index in range(2)
            ]
            root_id = new_id()
            root = await adapter.create_refresh_token(
                RefreshToken(
                    id=root_id,
                    user_id=owner.id,
                    session_id=sessions[label][0].id,
                    token_hash=f"{label}-root",
                    family_id=root_id,
                    family_created_at=now,
                    expires_at=now + timedelta(days=1),
                )
            )
            successor = await adapter.rotate_refresh_token(
                current_token_id=root.id,
                new_token=RefreshToken(
                    user_id=owner.id,
                    session_id=sessions[label][1].id,
                    token_hash=f"{label}-successor",
                    family_id=root.family_id,
                    family_created_at=now,
                    expires_at=now + timedelta(days=1),
                ),
                consumed_at=now,
            )
            assert successor is not None
            families[label] = [root, successor]

        # Adapters may remove replaced access sessions during rotation (for example Mongo).
        existing_session_ids: dict[str, set[str]] = {}
        for label, family_sessions in sessions.items():
            existing_session_ids[label] = {
                session.id
                for session in family_sessions
                if await adapter.get_session_by_token_hash(session.token_hash) is not None
            }
            assert family_sessions[1].id in existing_session_ids[label]

        if entrypoint == "session":
            deleted = await adapter.delete_refresh_tokens_for_session(sessions["target"][0].id)
        elif entrypoint == "user":
            deleted = await adapter.delete_refresh_tokens_for_user(user.id)
        elif entrypoint == "user_except":
            deleted = await adapter.delete_refresh_tokens_for_user(
                user.id, except_session_id=sessions["kept"][1].id
            )
        elif entrypoint == "family":
            result = await adapter.delete_refresh_token_family(families["target"][0].family_id)
            deleted = result.deleted_tokens
            assert result.deleted_sessions == len(existing_session_ids["target"])
            assert result.session_ids == frozenset(session.id for session in sessions["target"])
        else:
            deleted = await adapter.delete_refresh_tokens_in_family(families["target"][0].family_id)
        assert deleted == (4 if entrypoint == "user" else 2)
        for label in families:
            retained = label == "unrelated" or (label == "kept" and entrypoint != "user")
            for token in families[label]:
                assert (
                    await adapter.get_refresh_token_by_hash(token.token_hash) is not None
                ) == retained
            for session in sessions[label]:
                assert (
                    await adapter.get_session_by_token_hash(session.token_hash) is not None
                ) == (retained and session.id in existing_session_ids[label])


class PasswordRehashAdapterContract(AdapterContractBase):
    """Contract for the optional PasswordRehashStore capability."""

    async def test_password_rehash_compare_and_swap_preserves_concurrent_password_change(
        self,
        adapter: PasswordRehashContractAdapter,
    ) -> None:
        user = await adapter.create_user(User(email="rehash-cas@example.com"))
        account = await adapter.create_account(
            Account(
                user_id=user.id,
                provider_id=ProviderId.CREDENTIAL,
                account_id=user.id,
                password="old",
            )
        )
        assert await adapter.replace_account_password(
            account.id,
            expected_hash="old",
            new_hash="new",
        )
        assert not await adapter.replace_account_password(
            account.id,
            expected_hash="old",
            new_hash="obsolete-rehash",
        )
        current = await adapter.get_account_for_user(user.id, ProviderId.CREDENTIAL)
        assert current is not None and current.password == "new"  # noqa: S105 - test hash sentinel


class UserStatusAdapterContract(AdapterContractBase):
    """Protected activation changes cannot be undone by stale profile writes."""

    async def test_stale_user_update_cannot_undo_suspension(
        self,
        adapter: UserStatusContractAdapter,
    ) -> None:
        created = await adapter.create_user(User(email="status-race@example.com"))
        stale = await adapter.get_user_by_id(created.id)
        assert stale is not None
        suspended = await adapter.set_user_active(created.id, active=False)
        assert not suspended.active
        stale.name = "A concurrent profile edit"
        result = await adapter.update_user(stale)
        assert not result.active
        current = await adapter.get_user_by_id(created.id)
        assert current is not None and not current.active
        assert current.name == "A concurrent profile edit"
        restored = await adapter.set_user_active(created.id, active=True)
        assert restored.active


class CreationAdapterContract(AdapterContractBase):
    """Real-backend failure and cancellation checks for identity persistence."""

    async def test_account_insert_failure_is_compensated_and_retryable(
        self,
        adapter: DatabaseAdapter,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from fastauth.flows.creation import persist_user_account

        original_create = adapter.create_account

        async def fail_after_insert(account: Account) -> Account:
            await original_create(account)
            raise RuntimeError("injected lost account acknowledgement")

        monkeypatch.setattr(adapter, "create_account", fail_after_insert)
        with pytest.raises(RuntimeError, match="lost account acknowledgement"):
            await persist_user_account(
                adapter,
                User(email="rollback@example.com"),
                provider_id=ProviderId.CREDENTIAL,
                password_hash="hash",
            )
        assert await adapter.get_user_by_email("rollback@example.com") is None
        monkeypatch.setattr(adapter, "create_account", original_create)
        created = await persist_user_account(
            adapter,
            User(email="rollback@example.com"),
            provider_id=ProviderId.CREDENTIAL,
            password_hash="hash",
        )
        assert await adapter.get_account_for_user(created.id, ProviderId.CREDENTIAL) is not None

    async def test_cancellation_finishes_identity_consistency_section(
        self,
        adapter: DatabaseAdapter,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from fastauth.flows.creation import persist_user_account

        original_create = adapter.create_account
        started = asyncio.Event()
        release = asyncio.Event()

        async def delayed_create(account: Account) -> Account:
            started.set()
            await release.wait()
            return await original_create(account)

        monkeypatch.setattr(adapter, "create_account", delayed_create)
        task = asyncio.create_task(
            persist_user_account(
                adapter,
                User(email="cancelled-creation@example.com"),
                provider_id=ProviderId.CREDENTIAL,
                password_hash="hash",
            )
        )
        await asyncio.wait_for(started.wait(), timeout=10)
        task.cancel()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        user = await adapter.get_user_by_email("cancelled-creation@example.com")
        assert user is not None
        assert await adapter.get_account_for_user(user.id, ProviderId.CREDENTIAL) is not None


class FullAdapterContract(
    CreationAdapterContract,
    UserStatusAdapterContract,
    PasswordRehashAdapterContract,
    CoreAdapterContract,
    RefreshTokenAdapterContract,
    ApiKeyAdapterContract,
    JwksAdapterContract,
    AuditLogAdapterContract,
    MaintenanceAdapterContract,
    RateLimitAdapterContract,
):
    """Full first-party adapter contract covering core and optional stores."""

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
        refresh_root_id = new_id()
        await adapter.create_refresh_token(
            RefreshToken(
                id=refresh_root_id,
                user_id=user.id,
                session_id=session.id,
                token_hash="delete-refresh",
                family_id=refresh_root_id,
                family_created_at=datetime.now(UTC),
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
        assert (
            await adapter.get_active_verification(
                user.email,
                VerificationPurpose.ACCOUNT_DELETION,
            )
            is None
        )
        api_keys, api_key_total = await adapter.list_api_keys_for_user(user.id)
        assert api_keys == []
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


AdapterContract = FullAdapterContract
