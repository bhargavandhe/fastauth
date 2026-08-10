"""Bounded, explicit cleanup for expired authentication data."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import TYPE_CHECKING, cast

from pydantic import ConfigDict

from fastauth.domain.models import WireModel
from fastauth.exceptions import MaintenanceError
from fastauth.options import MaintenanceOptions
from fastauth.storage.base import ApiKeyStore, AuditLogStore, DatabaseAdapter

if TYPE_CHECKING:
    from fastauth.runtime.observability import ObservabilityManager

__all__ = [
    "MaintenanceError",
    "MaintenanceFailure",
    "MaintenanceManager",
    "MaintenanceResult",
]

CleanupOperation = Callable[[datetime, int], Awaitable[int]]


class MaintenanceFailure(WireModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    resource: str
    code: str = "cleanup_failed"
    message: str = "Cleanup failed. Check server logs for details."


class MaintenanceResult(WireModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    ok: bool
    deleted_sessions: int = 0
    deleted_refresh_tokens: int = 0
    deleted_verifications: int = 0
    deleted_api_keys: int = 0
    deleted_audit_logs: int = 0
    failures: tuple[MaintenanceFailure, ...] = ()


class MaintenanceManager:
    """Run adapter cleanup operations in bounded, idempotent batches."""

    def __init__(
        self,
        adapter: DatabaseAdapter,
        options: MaintenanceOptions,
        *,
        observability: ObservabilityManager | None = None,
    ) -> None:
        self.adapter = adapter
        self.options = options
        self.observability = observability

    async def drain(
        self,
        cleanup: CleanupOperation,
        *,
        cutoff: datetime,
    ) -> int:
        total = 0
        for _ in range(self.options.max_batches):
            deleted = await cleanup(cutoff, self.options.batch_size)
            if deleted < 0 or deleted > self.options.batch_size:
                raise MaintenanceError(
                    code="MAINTENANCE_INVALID_DELETE_COUNT",
                    message="adapter returned an invalid maintenance deletion count",
                )
            total += deleted
            if deleted < self.options.batch_size:
                break
        return total

    async def run(self, *, now: datetime | None = None) -> MaintenanceResult:
        cutoff = now or datetime.now(UTC)
        if cutoff.tzinfo is None or cutoff.utcoffset() is None:
            raise MaintenanceError(
                code="MAINTENANCE_INVALID_CUTOFF",
                message="maintenance cutoff must be timezone-aware",
            )
        cutoff = cutoff.astimezone(UTC)
        if self.observability is not None:
            await self.observability.emit(
                "maintenance.started",
                outcome="started",
                component="maintenance",
            )

        operations: list[tuple[str, CleanupOperation, datetime]] = [
            (
                "refresh_tokens",
                lambda value, limit: self.adapter.delete_expired_refresh_tokens(
                    cutoff=value,
                    limit=limit,
                ),
                cutoff,
            ),
            (
                "sessions",
                lambda value, limit: self.adapter.delete_expired_sessions(
                    cutoff=value,
                    limit=limit,
                ),
                cutoff,
            ),
            (
                "verifications",
                lambda value, limit: self.adapter.delete_expired_verifications(
                    cutoff=value,
                    limit=limit,
                ),
                cutoff,
            ),
        ]
        if isinstance(self.adapter, ApiKeyStore):
            api_key_store = cast(ApiKeyStore, self.adapter)
            operations.append(
                (
                    "api_keys",
                    lambda value, limit: api_key_store.delete_expired_api_keys(
                        cutoff=value,
                        limit=limit,
                    ),
                    cutoff,
                )
            )
        if self.options.audit_log_retention is not None and isinstance(self.adapter, AuditLogStore):
            audit_log_store = cast(AuditLogStore, self.adapter)
            operations.append(
                (
                    "audit_logs",
                    lambda value, limit: audit_log_store.delete_audit_logs_before(
                        cutoff=value,
                        limit=limit,
                    ),
                    cutoff - self.options.audit_log_retention,
                )
            )

        deleted: dict[str, int] = {}
        failures: list[MaintenanceFailure] = []
        for resource, operation, resource_cutoff in operations:
            try:
                deleted[resource] = await self.drain(operation, cutoff=resource_cutoff)
            except Exception as exc:
                if self.observability is not None:
                    await self.observability.emit(
                        "maintenance.resource.failed",
                        outcome="failure",
                        component="maintenance",
                        resource=resource,
                    )
                if not self.options.continue_on_error:
                    if isinstance(exc, MaintenanceError):
                        raise
                    raise MaintenanceError(
                        resource=resource,
                        code="MAINTENANCE_CLEANUP_FAILED",
                    ) from exc
                failures.append(MaintenanceFailure(resource=resource))

        result = MaintenanceResult(
            ok=not failures,
            deleted_sessions=deleted.get("sessions", 0),
            deleted_refresh_tokens=deleted.get("refresh_tokens", 0),
            deleted_verifications=deleted.get("verifications", 0),
            deleted_api_keys=deleted.get("api_keys", 0),
            deleted_audit_logs=deleted.get("audit_logs", 0),
            failures=tuple(failures),
        )
        if self.observability is not None:
            await self.observability.emit(
                "maintenance.completed",
                outcome="success" if result.ok else "partial",
                component="maintenance",
                deleted_sessions=result.deleted_sessions,
                deleted_refresh_tokens=result.deleted_refresh_tokens,
                deleted_verifications=result.deleted_verifications,
                deleted_api_keys=result.deleted_api_keys,
                deleted_audit_logs=result.deleted_audit_logs,
            )
        return result
