"""Integration tests for explicit liveness and readiness semantics."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import httpx
import pytest
from fastapi import FastAPI
from pydantic import SecretStr

from fastauth.database import custom
from fastauth.exceptions import ServiceUnavailableError
from fastauth.options import CookieOptions, CsrfOptions, FastAuthOptions, RateLimitOptions
from fastauth.runtime.auth import FastAuth
from fastauth.storage.memory import InMemoryAdapter


async def test_health_endpoints_have_explicit_semantics(client: httpx.AsyncClient) -> None:
    live = await client.get("/auth/health/live")
    ready = await client.get("/auth/health/ready")
    ambiguous = await client.get("/auth/health")

    assert live.status_code == 200
    assert live.json() == {"status": "alive", "name": "fastauth"}
    assert ready.status_code == 200
    assert ready.json() == {"status": "ready", "name": "fastauth"}
    assert ambiguous.status_code == 404


async def test_health_operations_are_available_from_server_api(
    auth: FastAuth,
) -> None:
    liveness = await auth.api.liveness()
    async with auth.lifespan():
        readiness = await auth.api.readiness()

    assert liveness.status == "alive"
    assert readiness.status == "ready"


async def test_readiness_requires_completed_runtime_startup(auth: FastAuth) -> None:
    with pytest.raises(ServiceUnavailableError):
        await auth.api.readiness()


class UnavailableAdapter(InMemoryAdapter):
    async def ping(self) -> None:
        raise RuntimeError("postgresql://user:password@private-host/database")


@asynccontextmanager
async def unavailable_client() -> AsyncGenerator[httpx.AsyncClient]:
    auth = FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("a" * 64),
            database=custom(adapter=UnavailableAdapter()),
            csrf=CsrfOptions(enabled=False),
            cookie=CookieOptions(secure=False),
            rate_limit=RateLimitOptions(enabled=False),
        )
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


async def test_readiness_failure_is_503_and_sanitized() -> None:
    async with unavailable_client() as http:
        response = await http.get("/auth/health/ready")

    assert response.status_code == 503
    assert response.json() == {
        "code": "SERVICE_UNAVAILABLE",
        "message": "authentication service is not ready",
    }
    assert "private-host" not in response.text


async def test_liveness_does_not_touch_an_unavailable_database() -> None:
    async with unavailable_client() as http:
        response = await http.get("/auth/health/live")

    assert response.status_code == 200
