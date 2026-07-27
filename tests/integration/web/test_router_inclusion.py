from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import timedelta

import httpx
from fastapi import FastAPI, Request, Response
from pydantic import SecretStr

from fastauth import FastAuth, FastAuthOptions
from fastauth.database import memory
from fastauth.options import AppOptions
from fastauth.plugins.base import Plugin, PluginMiddlewareSpec, RateLimitRule


def make_auth(*, base_path: str = "/auth") -> FastAuth:
    return FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("r" * 64),
            database=memory(),
            app=AppOptions(base_path=base_path),
        )
    )


class HealthRateLimitPlugin(Plugin):
    id = "health-rate-limit"

    def rate_limit_rules(self) -> list[RateLimitRule]:
        return [
            RateLimitRule(
                path="/health",
                window=timedelta(minutes=1),
                max_requests=1,
            )
        ]


class HealthMiddlewarePlugin(Plugin):
    id = "health-middleware"

    def middlewares(self) -> list[PluginMiddlewareSpec]:
        async def add_header(
            call_next: Callable[[Request | None], Awaitable[Response]],
        ) -> Response:
            response = await call_next(None)
            response.headers["X-Health-Middleware"] = "applied"
            return response

        return [
            PluginMiddlewareSpec(
                path="/health",
                handler=add_header,
            )
        ]


async def test_router_can_be_included_at_consumer_selected_prefix() -> None:
    auth = make_auth()
    app = FastAPI()
    app.include_router(auth.router, prefix="/api/auth", tags=["auth"])

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        response = await client.get("/api/auth/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "name": "fastauth"}
    assert auth.router.prefix == ""


async def test_explicit_integration_uses_consumer_selected_prefix() -> None:
    auth = make_auth(base_path="/configured/auth")
    app = FastAPI()
    app.include_router(auth.router, prefix="/configured/auth")
    auth.add_middleware(app)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        mounted = await client.get("/configured/auth/health")
        unprefixed = await client.get("/health")

    assert mounted.status_code == 200
    assert unprefixed.status_code == 404


async def test_add_middleware_does_not_include_routes() -> None:
    auth = make_auth()
    app = FastAPI()
    auth.add_middleware(app)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        response = await client.get("/health")

    assert response.status_code == 404


async def test_rate_limit_rules_use_relative_path_under_custom_prefix() -> None:
    auth = FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("l" * 64),
            database=memory(),
        ),
        plugins=[HealthRateLimitPlugin()],
    )
    app = FastAPI()
    app.include_router(auth.router, prefix="/api/auth")

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        first = await client.get("/api/auth/health")
        second = await client.get("/api/auth/health")

    assert first.status_code == 200
    assert second.status_code == 429


async def test_plugin_middleware_matches_relative_path_under_custom_prefix() -> None:
    auth = FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("m" * 64),
            database=memory(),
        ),
        plugins=[HealthMiddlewarePlugin()],
    )
    app = FastAPI()
    app.include_router(auth.router, prefix="/api/auth")

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        response = await client.get("/api/auth/health")

    assert response.status_code == 200
    assert response.headers["X-Health-Middleware"] == "applied"
