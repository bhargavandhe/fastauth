from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import SecretStr

from fastauth import FastAuth
from fastauth.domain.enums import AuditEventType, VerificationPurpose
from fastauth.domain.models import (
    ApiKey,
    AuditLog,
    RefreshToken,
    Session,
    Verification,
)
from fastauth.options import FastAuthOptions, MaintenanceOptions
from fastauth.runtime.maintenance import MaintenanceError, MaintenanceManager
from fastauth.storage.memory import InMemoryAdapter

NOW = datetime(2026, 8, 10, 12, 0, tzinfo=UTC)


async def seed_retained_and_expired_rows(adapter: InMemoryAdapter) -> None:
    await adapter.create_session(
        Session(user_id="user-1", token_hash="expired-session", expires_at=NOW - timedelta(days=1))
    )
    await adapter.create_session(
        Session(user_id="user-1", token_hash="live-session", expires_at=NOW + timedelta(days=1))
    )
    await adapter.create_refresh_token(
        RefreshToken(
            user_id="user-1",
            session_id="session-1",
            token_hash="expired-refresh",
            family_id="family-1",
            family_created_at=NOW - timedelta(days=2),
            expires_at=NOW - timedelta(days=1),
        )
    )
    await adapter.create_refresh_token(
        RefreshToken(
            user_id="user-1",
            session_id="session-2",
            token_hash="live-refresh",
            family_id="family-2",
            family_created_at=NOW,
            expires_at=NOW + timedelta(days=1),
        )
    )
    await adapter.create_verification(
        Verification(
            identifier="expired@example.com",
            value_hash="expired-verification",
            purpose=VerificationPurpose.EMAIL_VERIFICATION,
            expires_at=NOW - timedelta(days=1),
        )
    )
    await adapter.create_verification(
        Verification(
            identifier="live@example.com",
            value_hash="live-verification",
            purpose=VerificationPurpose.EMAIL_VERIFICATION,
            expires_at=NOW + timedelta(days=1),
        )
    )
    await adapter.create_api_key(
        ApiKey(
            user_id="user-1",
            name="expired",
            key_hash="expired-api-key",
            key_prefix="ak_expired",
            expires_at=NOW - timedelta(days=1),
        )
    )
    await adapter.create_api_key(
        ApiKey(
            user_id="user-1",
            name="live",
            key_hash="live-api-key",
            key_prefix="ak_live",
            expires_at=NOW + timedelta(days=1),
        )
    )
    await adapter.create_audit_log(
        AuditLog(event_type=AuditEventType.USER_CREATED, created_at=NOW - timedelta(days=91))
    )
    await adapter.create_audit_log(
        AuditLog(event_type=AuditEventType.USER_CREATED, created_at=NOW - timedelta(days=89))
    )


async def test_maintenance_deletes_only_expired_and_retention_eligible_rows() -> None:
    adapter = InMemoryAdapter()
    await seed_retained_and_expired_rows(adapter)
    manager = MaintenanceManager(
        adapter,
        MaintenanceOptions(batch_size=1, audit_log_retention=timedelta(days=90)),
    )

    result = await manager.run(now=NOW)

    assert result.ok is True
    assert result.deleted_sessions == 1
    assert result.deleted_refresh_tokens == 1
    assert result.deleted_verifications == 1
    assert result.deleted_api_keys == 1
    assert result.deleted_audit_logs == 1
    assert result.failures == ()
    assert {row.token_hash for row in adapter.sessions.values()} == {"live-session"}
    assert {row.token_hash for row in adapter.refresh_tokens.values()} == {"live-refresh"}
    assert {row.value_hash for row in adapter.verifications.values()} == {"live-verification"}
    assert {row.key_hash for row in adapter.api_keys.values()} == {"live-api-key"}
    assert len(adapter.audit_logs) == 1


async def test_maintenance_stops_each_resource_at_the_configured_batch_bound() -> None:
    adapter = InMemoryAdapter()
    for index in range(5):
        await adapter.create_session(
            Session(
                user_id="user-1",
                token_hash=f"expired-{index}",
                expires_at=NOW - timedelta(days=1),
            )
        )
    manager = MaintenanceManager(adapter, MaintenanceOptions(batch_size=2, max_batches=2))

    result = await manager.run(now=NOW)

    assert result.deleted_sessions == 4
    assert len(adapter.sessions) == 1


class FailingSessionCleanupAdapter(InMemoryAdapter):
    async def delete_expired_sessions(self, *, cutoff: datetime, limit: int) -> int:
        del cutoff, limit
        raise RuntimeError("database DSN and private detail must not escape")


async def test_maintenance_continue_mode_returns_sanitized_partial_failures() -> None:
    adapter = FailingSessionCleanupAdapter()
    await adapter.create_verification(
        Verification(
            identifier="expired@example.com",
            value_hash="expired-verification",
            purpose=VerificationPurpose.EMAIL_VERIFICATION,
            expires_at=NOW - timedelta(days=1),
        )
    )
    manager = MaintenanceManager(adapter, MaintenanceOptions(continue_on_error=True))

    result = await manager.run(now=NOW)

    assert result.ok is False
    assert result.deleted_verifications == 1
    assert len(result.failures) == 1
    assert result.failures[0].resource == "sessions"
    assert result.failures[0].code == "cleanup_failed"
    assert "database" not in result.failures[0].message.lower()


async def test_maintenance_is_fail_fast_by_default() -> None:
    manager = MaintenanceManager(FailingSessionCleanupAdapter(), MaintenanceOptions())

    with pytest.raises(MaintenanceError) as exc_info:
        await manager.run(now=NOW)

    assert exc_info.value.code == "MAINTENANCE_CLEANUP_FAILED"
    assert exc_info.value.resource == "sessions"
    assert "database DSN" not in str(exc_info.value)
    assert isinstance(exc_info.value.__cause__, RuntimeError)


async def test_maintenance_rejects_invalid_adapter_counts_with_typed_error() -> None:
    manager = MaintenanceManager(InMemoryAdapter(), MaintenanceOptions(batch_size=10))

    async def invalid_count(cutoff: datetime, limit: int) -> int:
        del cutoff, limit
        return 11

    with pytest.raises(MaintenanceError) as exc_info:
        await manager.drain(invalid_count, cutoff=NOW)

    assert exc_info.value.code == "MAINTENANCE_INVALID_DELETE_COUNT"


async def test_fastauth_exposes_bound_maintenance_manager() -> None:
    auth = FastAuth(FastAuthOptions(secret_key=SecretStr("a" * 64)))

    result = await auth.maintenance.run(now=NOW)

    assert result.ok is True
