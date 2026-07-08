from __future__ import annotations

from collections.abc import Awaitable, Callable

import httpx
from fastapi import Request, Response
from fastapi.responses import JSONResponse

from fastauth.plugins.base import (
    EndpointHookSpec,
    EndpointSpec,
    Plugin,
    PluginMiddlewareSpec,
    RequestHookSpec,
    ResponseHookSpec,
)
from fastauth.runtime.auth import FastAuth


class HookContractPlugin(Plugin):
    id = "hook-contract-plugin"

    def __init__(self, events: list[str], *, short_circuit: bool = False) -> None:
        self.events = events
        self.short_circuit = short_circuit

    def endpoints(self) -> list[EndpointSpec]:
        async def ping(response: Response) -> dict[str, bool]:
            self.events.append("handler")
            response.headers["X-Handler"] = "yes"
            return {"ok": True}

        return [
            EndpointSpec.get(
                "/hook-contract/ping",
                name="hook_contract_ping",
                handler=ping,
            )
        ]

    def middlewares(self) -> list[PluginMiddlewareSpec]:
        async def middleware(
            call_next: Callable[[Request | None], Awaitable[Response]],
        ) -> Response:
            self.events.append("middleware-before")
            result = await call_next(None)
            self.events.append("middleware-after")
            return result

        return [
            PluginMiddlewareSpec(
                path="/hook-contract/**",
                handler=middleware,
            )
        ]

    def request_hooks(self) -> list[RequestHookSpec]:
        async def request_hook() -> Response | None:
            self.events.append("request")
            if self.short_circuit:
                return JSONResponse({"short": True}, status_code=202)
            return None

        return [RequestHookSpec(name="request", handler=request_hook)]

    def response_hooks(self) -> list[ResponseHookSpec]:
        async def response_hook(response: Response) -> None:
            self.events.append("response")
            response.headers["X-Plugin-Response"] = "mutated"

        return [ResponseHookSpec(name="response", handler=response_hook)]

    def endpoint_hooks(self) -> list[EndpointHookSpec]:
        async def before_hook(endpoint: dict[str, object]) -> None:
            self.events.append(f"endpoint-before:{endpoint['name']}")

        async def after_hook(response: Response, endpoint: dict[str, object]) -> None:
            self.events.append(f"endpoint-after:{endpoint['name']}")
            response.headers["X-Endpoint-After"] = "yes"

        return [
            EndpointHookSpec(
                phase="before",
                matcher_name="hook_contract_ping",
                handler=before_hook,
            ),
            EndpointHookSpec(
                phase="after",
                matcher_name="hook_contract_ping",
                handler=after_hook,
            ),
        ]


async def test_plugin_hooks_execute_in_route_order(
    auth_factory: Callable[..., FastAuth],
) -> None:
    events: list[str] = []
    auth = auth_factory(plugins=[HookContractPlugin(events)])
    app = auth.as_asgi()

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        response = await client.get("/auth/hook-contract/ping")

    assert response.status_code == 200
    assert response.json() == {"ok": True}
    assert events == [
        "request",
        "endpoint-before:hook_contract_ping",
        "middleware-before",
        "handler",
        "middleware-after",
        "endpoint-after:hook_contract_ping",
        "response",
    ]


async def test_request_hook_can_short_circuit_and_response_hook_can_mutate_response(
    auth_factory: Callable[..., FastAuth],
) -> None:
    events: list[str] = []
    auth = auth_factory(plugins=[HookContractPlugin(events, short_circuit=True)])
    app = auth.as_asgi()

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        response = await client.get("/auth/hook-contract/ping")

    assert response.status_code == 202
    assert response.json() == {"short": True}
    assert response.headers["X-Plugin-Response"] == "mutated"
    assert "X-Handler" not in response.headers
    assert "X-Endpoint-After" not in response.headers
    assert events == ["request", "response"]


async def test_response_and_endpoint_hooks_mutate_route_response_headers(
    auth_factory: Callable[..., FastAuth],
) -> None:
    events: list[str] = []
    auth = auth_factory(plugins=[HookContractPlugin(events)])
    app = auth.as_asgi()

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        response = await client.get("/auth/hook-contract/ping")

    assert response.headers["X-Handler"] == "yes"
    assert response.headers["X-Endpoint-After"] == "yes"
    assert response.headers["X-Plugin-Response"] == "mutated"
