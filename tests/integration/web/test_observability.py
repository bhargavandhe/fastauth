from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import httpx
import pytest
from fastapi import FastAPI
from pydantic import SecretStr

from fastauth.options import CookieOptions, CsrfOptions, FastAuthOptions, RateLimitOptions
from fastauth.runtime.auth import FastAuth
from fastauth.runtime.observability import (
    ObservabilityManager,
    ObservabilitySink,
    OperationalEvent,
)


class RecordingSink:
    def __init__(self) -> None:
        self.events: list[OperationalEvent] = []

    async def emit(self, event: OperationalEvent) -> None:
        self.events.append(event)


class FailingSink:
    async def emit(self, event: OperationalEvent) -> None:
        del event
        raise RuntimeError("private sink failure")


@asynccontextmanager
async def observed_client(
    sink: ObservabilitySink,
) -> AsyncGenerator[httpx.AsyncClient]:
    auth = FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("a" * 64),
            csrf=CsrfOptions(enabled=False),
            cookie=CookieOptions(secure=False),
            rate_limit=RateLimitOptions(enabled=False),
        ),
        observability_sink=sink,
    )
    app = FastAPI()
    app.include_router(auth.router, prefix="/auth")
    auth.add_middleware(app)
    async with auth.lifespan(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as http:
            yield http


async def test_request_id_is_preserved_and_attached_to_bounded_route_events() -> None:
    sink = RecordingSink()
    async with observed_client(sink) as http:
        response = await http.get(
            "/auth/health/live",
            headers={"X-Request-ID": "request-123"},
        )

    assert response.headers["X-Request-ID"] == "request-123"
    completed = [event for event in sink.events if event.name == "http.request.completed"]
    assert len(completed) == 1
    assert completed[0].request_id == "request-123"
    assert completed[0].route == "/health/live"
    assert "http://testserver" not in completed[0].model_dump_json()
    auth_completed = [event for event in sink.events if event.name == "auth.request.completed"]
    assert len(auth_completed) == 1
    assert auth_completed[0].outcome == "success"


async def test_invalid_request_id_is_replaced() -> None:
    sink = RecordingSink()
    async with observed_client(sink) as http:
        response = await http.get(
            "/auth/health/live",
            headers={"X-Request-ID": "bad request id with spaces"},
        )

    request_id = response.headers["X-Request-ID"]
    assert request_id != "bad request id with spaces"
    assert 16 <= len(request_id) <= 128


async def test_readiness_emits_a_bounded_result() -> None:
    sink = RecordingSink()
    async with observed_client(sink) as http:
        response = await http.get("/auth/health/ready")

    assert response.status_code == 200
    readiness = [event for event in sink.events if event.name == "readiness.checked"]
    assert len(readiness) == 1
    assert readiness[0].outcome == "ready"
    assert readiness[0].component == "database"
    assert readiness[0].attributes == {}


async def test_forbidden_or_structured_attributes_are_rejected() -> None:
    manager = ObservabilityManager(RecordingSink())

    with pytest.raises(ValueError, match="forbidden attribute"):
        await manager.emit("unsafe", user_id="secret")
    with pytest.raises(ValueError, match="scalar values"):
        await manager.emit("unsafe", payload={"email": "secret@example.com"})


async def test_sink_failure_does_not_break_auth_requests() -> None:
    async with observed_client(FailingSink()) as http:
        response = await http.get("/auth/health/live")

    assert response.status_code == 200


async def test_manager_supports_imperative_and_decorator_subscriptions() -> None:
    manager = ObservabilityManager(RecordingSink())
    received: list[tuple[str, str]] = []

    async def imperative(event: OperationalEvent) -> None:
        received.append(("imperative", event.name))

    manager.subscribe("auth.request.completed", imperative)

    @manager.on("auth.request.completed")
    async def decorated(  # pyright: ignore[reportUnusedFunction]
        event: OperationalEvent,
    ) -> None:
        received.append(("decorated", event.name))

    await manager.emit(
        "auth.request.completed",
        outcome="success",
        duration_ms=1.5,
        status_code=200,
        component="http",
        route="/health/live",
    )

    assert received == [
        ("imperative", "auth.request.completed"),
        ("decorated", "auth.request.completed"),
    ]


async def test_operational_fields_are_explicit_and_bounded() -> None:
    sink = RecordingSink()
    manager = ObservabilityManager(sink)

    await manager.emit(
        "http.request.completed",
        outcome="success",
        duration_ms=2.5,
        status_code=204,
        component="http",
        route="/sessions/{session_id}",
        method="DELETE",
    )

    event = sink.events[0]
    assert event.outcome == "success"
    assert event.duration_ms == 2.5
    assert event.status_code == 204
    assert event.component == "http"
    assert event.route == "/sessions/{session_id}"
    assert event.attributes == {"method": "DELETE"}
