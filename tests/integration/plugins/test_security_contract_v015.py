"""Mounted route behavior, rather than descriptive endpoint metadata."""

from collections.abc import Sequence
from typing import ClassVar

import httpx
import pytest
from fastapi import FastAPI
from pydantic import SecretStr

from fastauth import FastAuth, email_password
from fastauth.api.commands import BearerCredentialDelivery
from fastauth.database import custom
from fastauth.flows.credentials import EmptyResponse
from fastauth.options import CookieOptions, CsrfOptions, FastAuthOptions, RateLimitOptions
from fastauth.plugins.base import EndpointSpec, Plugin
from fastauth.storage.memory import InMemoryAdapter


class ContractPlugin(Plugin):
    id: ClassVar[str] = "contract"

    async def handler(self) -> EmptyResponse:
        return EmptyResponse(success=True)

    def endpoints(self) -> Sequence[EndpointSpec]:
        return [
            EndpointSpec.post(
                "/protected",
                name="protected",
                handler=self.handler,
                auth_required=True,
                operation_id="custom_protected",
                error_codes=("INVALID_CREDENTIALS",),
                csrf_policy="required",
            ),
            EndpointSpec.get("/private", name="private", handler=self.handler, server_only=True),
        ]


def contract_auth() -> FastAuth:
    return FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("a" * 64),
            database=custom(adapter=InMemoryAdapter()),
            csrf=CsrfOptions(enabled=False, trusted_origins=("https://trusted.test",)),
            cookie=CookieOptions(secure=False),
            rate_limit=RateLimitOptions(enabled=False),
        ),
        plugins=[email_password(), ContractPlugin()],
    )


@pytest.mark.asyncio
async def test_declared_security_is_enforced_on_mounted_routes() -> None:
    auth = contract_auth()
    app = FastAPI()
    app.include_router(auth.router, prefix="/custom")
    result = await auth.sign_up.email(
        "route@example.com", SecretStr("Password123!"), delivery=BearerCredentialDelivery()
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        anonymous = await client.post("/custom/protected")
        assert anonymous.status_code == 401
        assert (await client.get("/custom/private")).status_code == 404
        assert result.credentials is not None
        token = result.credentials.token.root
        assert (
            await client.post("/custom/protected", headers={"Authorization": f"Bearer {token}"})
        ).status_code == 200
        client.cookies.set(auth.options.cookie.name, auth.context.signed_cookie.pack(token))
        assert (
            await client.post("/custom/protected", headers={"Origin": "https://evil.test"})
        ).status_code == 403
        assert (
            await client.post("/custom/protected", headers={"Origin": "https://trusted.test"})
        ).status_code == 200


def test_openapi_security_operation_id_and_errors() -> None:
    auth = contract_auth()
    app = FastAPI()
    app.include_router(auth.router, prefix="/custom")
    schema = app.openapi()
    operation = schema["paths"]["/custom/protected"]["post"]
    assert operation["operationId"] == "custom_protected"
    assert operation["security"] == [{"SessionCookie": []}, {"SessionBearer": []}]
    assert (
        schema["components"]["securitySchemes"]["SessionCookie"]["name"] == auth.options.cookie.name
    )
    assert operation["responses"]["401"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "/ErrorResponse"
    )
    assert operation["x-fastauth-error-codes"] == ["INVALID_CREDENTIALS"]
    assert "/custom/private" not in schema["paths"]


def test_unsupported_csrf_policy_is_rejected() -> None:
    class InvalidPlugin(ContractPlugin):
        def endpoints(self) -> Sequence[EndpointSpec]:
            return [
                EndpointSpec.post(
                    "/invalid", name="invalid", handler=self.handler, csrf_policy="bypass"
                )
            ]

    with pytest.raises(ValueError, match="csrf_policy"):
        FastAuth(contract_auth().options, plugins=[InvalidPlugin()])


@pytest.mark.asyncio
async def test_protected_hooks_cannot_short_circuit_authentication() -> None:
    from fastapi.responses import JSONResponse

    from fastauth.plugins.base import PluginMiddlewareSpec

    class ShortCircuitPlugin(ContractPlugin):
        async def middleware(self) -> JSONResponse:
            return JSONResponse({"sensitive": "protected data"})

        def middlewares(self) -> Sequence[PluginMiddlewareSpec]:
            return [PluginMiddlewareSpec(path="/protected", handler=self.middleware)]

    auth = FastAuth(contract_auth().options, plugins=[ShortCircuitPlugin()])
    app = FastAPI()
    app.include_router(auth.router)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        assert (await client.post("/protected")).status_code == 401


@pytest.mark.asyncio
async def test_global_api_key_maintenance_is_server_only() -> None:
    from fastauth import api_key

    auth = FastAuth(contract_auth().options, plugins=[api_key()])
    app = FastAPI()
    app.include_router(auth.router)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        assert (await client.post("/api-key/delete-all-expired")).status_code == 404


@pytest.mark.asyncio
async def test_rate_limit_cannot_be_bypassed_by_plugin_middleware() -> None:
    from fastapi.responses import JSONResponse

    from fastauth.plugins.base import PluginMiddlewareSpec

    class PublicPlugin(Plugin):
        id = "limited"

        async def handler(self) -> EmptyResponse:
            return EmptyResponse(success=True)

        async def middleware(self) -> JSONResponse:
            return JSONResponse({"success": True})

        def endpoints(self) -> Sequence[EndpointSpec]:
            return [EndpointSpec.get("/public", name="public", handler=self.handler)]

        def middlewares(self) -> Sequence[PluginMiddlewareSpec]:
            return [PluginMiddlewareSpec(path="/public", handler=self.middleware)]

    options = contract_auth().options.model_copy(
        update={"rate_limit": RateLimitOptions(max_requests=1)}
    )
    auth = FastAuth(options, plugins=[PublicPlugin()])
    app = FastAPI()
    app.include_router(auth.router)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        assert (await client.get("/public")).status_code == 200
        assert (await client.get("/public")).status_code == 429


def test_operation_ids_do_not_depend_on_mount_prefix() -> None:
    auth = contract_auth()
    first, second = FastAPI(), FastAPI()
    first.include_router(auth.router, prefix="/one")
    second.include_router(auth.router, prefix="/two")
    a, b = first.openapi(), second.openapi()
    assert a["paths"]["/one/refresh"]["post"]["operationId"] == "refresh_session"
    assert b["paths"]["/two/refresh"]["post"]["operationId"] == "refresh_session"


def test_repeated_route_names_cannot_alias_security_metadata() -> None:
    class AmbiguousPlugin(ContractPlugin):
        def endpoints(self) -> Sequence[EndpointSpec]:
            return [
                EndpointSpec.get("/first", name="same", handler=self.handler, auth_required=True),
                EndpointSpec.get("/second", name="same", handler=self.handler),
            ]

    with pytest.raises(ValueError, match="name"):
        FastAuth(contract_auth().options, plugins=[AmbiguousPlugin()])
