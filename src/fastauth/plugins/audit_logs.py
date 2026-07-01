"""AuditLogsPlugin: auto-collect ``AuthEvent`` publications into ``audit_logs``.

Subscribes a single handler to the ``AuthEvent`` base class on the ``EventBus``
so that every concrete subclass (``UserSignedUp``, ``SessionCreated``, etc.)
triggers a row insertion in the configured ``DatabaseAdapter``. Also contributes
two read-only HTTP endpoints:

* ``GET /audit-logs`` — paginated, scoped to the current session's user.
* ``GET /audit-logs/all`` — paginated, requires the caller's user id to be
  listed in ``AuditLogsOptions.admin_user_ids``.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import ClassVar

from fastapi import Request
from pydantic import Field

from fastauth.domain.enums import AuditEventType
from fastauth.domain.events import AuthEvent
from fastauth.domain.models import AuditLog, WireModel
from fastauth.exceptions import ConfigError, CsrfError, InvalidCredentialsError
from fastauth.plugins.base import EndpointSpec, Plugin, PluginOptions
from fastauth.runtime.context import AuthContext
from fastauth.storage.base import AuditLogStore

__all__ = ["AuditLogsOptions", "AuditLogsPlugin", "AuditLogsResponse"]


class AuditLogsOptions(PluginOptions):
    """Static configuration for ``AuditLogsPlugin``."""

    admin_user_ids: tuple[str, ...] = Field(default_factory=tuple)


class AuditLogsResponse(WireModel):
    """Paginated response body for the audit-log query endpoints."""

    events: list[AuditLog]
    total: int
    limit: int
    offset: int


class AuditLogsPlugin(Plugin):
    """Plugin contributing audit-log capture and paginated query endpoints."""

    id: ClassVar[str] = "fastauth-audit-logs"

    def __init__(self, options: AuditLogsOptions | None = None) -> None:
        self.options = options or AuditLogsOptions()
        self.context: AuthContext | None = None
        self.store: AuditLogStore | None = None

    def bind(self, context: AuthContext) -> None:
        """Attach the assembled ``AuthContext`` and subscribe the catch-all handler."""
        if not isinstance(context.adapter, AuditLogStore):
            raise ConfigError(
                message="AuditLogsPlugin requires an adapter implementing AuditLogStore",
            )
        self.context = context
        self.store = context.adapter
        context.event_bus.subscribe(AuthEvent, self.record_event)  # type: ignore[arg-type]

    def assert_bound(self) -> AuthContext:
        """Return the bound ``AuthContext`` or raise if ``bind`` was never invoked."""
        if self.context is None:
            raise RuntimeError("AuditLogsPlugin is not bound to an AuthContext")
        return self.context

    def assert_store(self) -> AuditLogStore:
        """Return the bound audit-log store or raise if ``bind`` was never invoked."""
        if self.store is None:
            raise RuntimeError("AuditLogsPlugin is not bound to an AuditLogStore")
        return self.store

    async def record_event(self, event: AuthEvent) -> None:
        """Normalise ``event`` into an ``AuditLog`` row and persist it."""
        from fastauth.domain.events import OtpGenerated

        if isinstance(event, OtpGenerated):
            # OtpGenerated carries the plaintext token; never persist it.
            return
        self.assert_bound()
        store = self.assert_store()
        payload = event.model_dump(mode="json")
        # Meta fields live as top-level columns on AuditLog (or are inherent
        # to the event identity) — strip them from the event_data blob.
        payload.pop("audit_event_type", None)
        payload.pop("event_id", None)
        payload.pop("occurred_at", None)
        user_id = payload.pop("user_id", None)
        identifier = payload.pop("identifier", None)
        ip_address = payload.pop("ip_address", None)
        user_agent = payload.pop("user_agent", None)
        row = AuditLog(
            event_type=event.audit_event_type,
            user_id=user_id,
            identifier=identifier,
            ip_address=ip_address,
            user_agent=user_agent,
            event_data=payload,
            created_at=event.occurred_at,
        )
        await store.create_audit_log(row)

    def endpoints(self) -> Sequence[EndpointSpec]:
        return [
            EndpointSpec(
                method="GET",
                path="/audit-logs",
                name="audit_logs_list",
                tags=["AuditLogs"],
                handler=self.list_handler,
                response_model=AuditLogsResponse,
            ),
            EndpointSpec(
                method="GET",
                path="/audit-logs/all",
                name="audit_logs_list_all",
                tags=["AuditLogs"],
                handler=self.list_all_handler,
                response_model=AuditLogsResponse,
            ),
        ]

    async def current_user_id(self, request: Request) -> str:
        """Resolve the authenticated user via the session strategy.

        The import is local to avoid a circular dependency between
        ``fastauth.web.fastapi`` and ``fastauth.plugins.audit_logs``.
        """
        from fastauth.web.fastapi import extract_session_token

        context = self.assert_bound()
        token = extract_session_token(request, context)
        if token is None:
            raise InvalidCredentialsError()
        session_context = await context.session_strategy.read(token)
        if session_context is None:
            raise InvalidCredentialsError()
        return session_context.user.id

    async def list_handler(
        self,
        request: Request,
        event_type: str | None = None,
        identifier: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> AuditLogsResponse:
        """``GET /auth/audit-logs`` — list rows for the current session's user."""
        self.assert_bound()
        store = self.assert_store()
        user_id = await self.current_user_id(request)
        parsed_event_type = AuditEventType(event_type) if event_type else None
        events, total = await store.list_audit_logs(
            user_id=user_id,
            event_type=parsed_event_type,
            identifier=identifier,
            limit=limit,
            offset=offset,
        )
        return AuditLogsResponse(events=events, total=total, limit=limit, offset=offset)

    async def list_all_handler(
        self,
        request: Request,
        event_type: str | None = None,
        identifier: str | None = None,
        user_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> AuditLogsResponse:
        """``GET /auth/audit-logs/all`` — admin-only, unrestricted query."""
        self.assert_bound()
        store = self.assert_store()
        caller_user_id = await self.current_user_id(request)
        if caller_user_id not in self.options.admin_user_ids:
            # CsrfError maps to HTTP 403 via EXCEPTION_HTTP_STATUS; reused here
            # as the project's canonical 403 carrier until a dedicated
            # ``ForbiddenError`` is introduced.
            raise CsrfError(message="admin access required")
        parsed_event_type = AuditEventType(event_type) if event_type else None
        events, total = await store.list_audit_logs(
            user_id=user_id,
            event_type=parsed_event_type,
            identifier=identifier,
            limit=limit,
            offset=offset,
        )
        return AuditLogsResponse(events=events, total=total, limit=limit, offset=offset)
