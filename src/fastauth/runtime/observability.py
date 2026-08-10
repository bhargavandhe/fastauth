"""Dependency-free, privacy-safe operational event boundaries."""

from __future__ import annotations

import inspect
import logging
import re
import secrets
import time
from collections.abc import Awaitable, Callable
from contextvars import ContextVar, Token
from datetime import UTC, datetime
from typing import Any, Literal, Protocol, TypeVar, cast

from pydantic import ConfigDict, Field, JsonValue
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from fastauth.domain.models import WireModel

__all__ = [
    "LoggingObservabilitySink",
    "ObservabilityManager",
    "ObservabilityMiddleware",
    "ObservabilitySink",
    "OperationalEvent",
    "OperationalEventHandler",
    "OperationalOutcome",
    "current_request_id",
    "new_request_id",
    "valid_request_id",
]

LOGGER = logging.getLogger("fastauth.observability")
REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
FORBIDDEN_ATTRIBUTE_KEYS = frozenset(
    {
        "email",
        "exception",
        "exception_message",
        "ip",
        "ip_address",
        "password",
        "raw_path",
        "token",
        "user_id",
    }
)
request_id_context: ContextVar[str | None] = ContextVar("fastauth_request_id", default=None)
OperationalOutcome = Literal[
    "failure",
    "not_ready",
    "partial",
    "ready",
    "rejected",
    "started",
    "success",
]


class OperationalEvent(WireModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1, max_length=128, pattern=r"^[a-z][a-z0-9_.-]*$")
    occurred_at: datetime
    request_id: str | None = Field(default=None, max_length=128)
    outcome: OperationalOutcome | None = None
    duration_ms: float | None = Field(default=None, ge=0)
    status_code: int | None = Field(default=None, ge=100, le=599)
    component: str | None = Field(default=None, min_length=1, max_length=128)
    route: str | None = Field(default=None, min_length=1, max_length=128)
    attributes: dict[str, JsonValue] = Field(default_factory=dict)


class ObservabilitySink(Protocol):
    async def emit(self, event: OperationalEvent) -> None: ...


OperationalEventHandler = Callable[[OperationalEvent], Awaitable[None] | None]
HandlerT = TypeVar("HandlerT", bound=OperationalEventHandler)


class LoggingObservabilitySink:
    async def emit(self, event: OperationalEvent) -> None:
        LOGGER.info(event.model_dump_json(by_alias=True))


def valid_request_id(value: str | None) -> bool:
    return value is not None and REQUEST_ID_PATTERN.fullmatch(value) is not None


def new_request_id() -> str:
    return secrets.token_urlsafe(18)


def current_request_id() -> str | None:
    return request_id_context.get()


class ObservabilityManager:
    def __init__(self, sink: ObservabilitySink | None = None) -> None:
        self.sink = sink or LoggingObservabilitySink()
        self._subscribers: dict[str, list[OperationalEventHandler]] = {}

    def subscribe(self, name: str, handler: OperationalEventHandler) -> None:
        self._subscribers.setdefault(name, []).append(handler)

    def on(self, name: str) -> Callable[[HandlerT], HandlerT]:
        def decorator(handler: HandlerT) -> HandlerT:
            self.subscribe(name, handler)
            return handler

        return decorator

    async def emit(
        self,
        name: str,
        *,
        outcome: OperationalOutcome | None = None,
        duration_ms: float | None = None,
        status_code: int | None = None,
        component: str | None = None,
        route: str | None = None,
        **attributes: JsonValue,
    ) -> None:
        forbidden = FORBIDDEN_ATTRIBUTE_KEYS.intersection(attributes)
        if forbidden:
            raise ValueError("operational event contains a forbidden attribute")
        bounded: dict[str, JsonValue] = {}
        for key, value in attributes.items():
            if isinstance(value, str):
                bounded[key] = value[:128]
            elif value is None or isinstance(value, bool | int | float):
                bounded[key] = value
            else:
                raise ValueError("operational event attributes must be scalar values")
        event = OperationalEvent(
            name=name,
            occurred_at=datetime.now(UTC),
            request_id=current_request_id(),
            outcome=outcome,
            duration_ms=duration_ms,
            status_code=status_code,
            component=component,
            route=route,
            attributes=bounded,
        )
        try:
            await self.sink.emit(event)
        except Exception:
            LOGGER.error("observability sink failed")
        for handler in self._subscribers.get(name, ()):
            try:
                result = handler(event)
                if inspect.isawaitable(result):
                    await result
            except Exception:
                LOGGER.error("observability subscriber failed")


class ObservabilityMiddleware:
    """Attach request IDs and emit bounded HTTP completion events."""

    def __init__(self, app: ASGIApp, *, manager: ObservabilityManager) -> None:
        self.app = app
        self.manager = manager

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        inbound = next(
            (
                value.decode("latin-1")
                for key, value in scope.get("headers", [])
                if key.lower() == b"x-request-id"
            ),
            None,
        )
        request_id = (
            inbound if inbound is not None and valid_request_id(inbound) else new_request_id()
        )
        context_token: Token[str | None] = request_id_context.set(request_id)
        status_code = 500
        started_at = time.perf_counter()

        async def send_with_request_id(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = int(message["status"])
                headers = list(message.get("headers", []))
                headers = [item for item in headers if item[0].lower() != b"x-request-id"]
                headers.append((b"x-request-id", request_id.encode("ascii")))
                message["headers"] = headers
            await send(message)

        try:
            await self.app(scope, receive, send_with_request_id)
        finally:
            route = cast(Any, scope.get("route"))
            route_name = getattr(route, "name", "unmatched")
            route_template = getattr(route, "path", "unmatched")
            relative_paths = getattr(route, "relative_paths", {})
            relative_key = (str(scope.get("method", "GET")).upper(), route_name)
            route_template = relative_paths.get(relative_key, route_template)
            duration_ms = round((time.perf_counter() - started_at) * 1000, 3)
            await self.manager.emit(
                "http.request.completed",
                outcome="success" if status_code < 400 else "failure",
                duration_ms=duration_ms,
                status_code=status_code,
                component="http",
                route=str(route_template),
                method=str(scope.get("method", "GET")),
            )
            if getattr(route, "fastauth_context", None) is not None:
                await self.manager.emit(
                    "auth.request.completed",
                    outcome="success" if status_code < 400 else "failure",
                    status_code=status_code,
                    component="auth",
                    route=str(route_template),
                    method=str(scope.get("method", "GET")),
                )
            request_id_context.reset(context_token)
