"""Custom entry points must deliberately opt into the network action boundary."""

from datetime import timedelta

import httpx
import pytest
from fastapi import Depends, FastAPI
from pydantic import AnyHttpUrl, SecretStr

from fastauth import FastAuth, api_key, email_password
from fastauth.api.commands import RequestContext
from fastauth.api.responses import ApiKeyView
from fastauth.database import memory
from fastauth.domain.value_objects import PermissionSet
from fastauth.exceptions import InvalidRequestError, RateLimitError
from fastauth.flows.credentials import EmptyResponse
from fastauth.options import AppOptions, FastAuthOptions, ProductionSafetyOptions, RateLimitOptions
from fastauth.plugins.api_key import ApiKeysApi, CreateApiKeyRequest


@pytest.mark.asyncio
async def test_action_boundary_enforces_limit_before_operation() -> None:
    auth = FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("a" * 64),
            database=memory(),
            rate_limit=RateLimitOptions(window=timedelta(minutes=1), max_requests=1),
        )
    )
    called: list[str] = []

    async def operation() -> EmptyResponse:
        called.append("run")
        return EmptyResponse(success=True)

    context = RequestContext(ip_address="127.0.0.1")
    assert (await auth.actions.run("/custom-action", operation, context=context)).success
    with pytest.raises(RateLimitError):
        await auth.actions.run("/custom-action", operation, context=context)
    assert called == ["run"]
    with pytest.raises(InvalidRequestError, match="ip_address"):
        await auth.actions.check("/custom-action", context=RequestContext())


def test_production_memory_limit_diagnostic() -> None:
    auth = FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("a" * 64),
            database=memory(),
            deployment="production",
            app=AppOptions(base_url=AnyHttpUrl("https://auth.example.com")),
            production_safety=ProductionSafetyOptions(
                forbid_console_email_sender=False, forbid_memory_database=False
            ),
        )
    )
    assert any(
        "rate limit" in warning and "process" in warning
        for warning in auth.inspect().production_warnings
    )


@pytest.mark.asyncio
async def test_api_key_dependency_permissions_and_openapi() -> None:
    auth = FastAuth(
        FastAuthOptions(secret_key=SecretStr("a" * 64), database=memory()),
        plugins=[email_password(), api_key()],
    )
    user = await auth.api.create_user(email="api@example.com", password="Password123!")
    keys = auth.plugins.get(ApiKeysApi)
    created = await keys.create(
        user.id,
        CreateApiKeyRequest(
            name="read key", permissions=PermissionSet({"files": frozenset({"read"})})
        ),
    )
    app = FastAPI()
    auth.add_middleware(app)

    dependency = Depends(
        auth.depends.api_key(required_permissions=PermissionSet({"files": frozenset({"read"})}))
    )

    async def protected(key: ApiKeyView = dependency) -> ApiKeyView:
        return key

    app.get("/files")(protected)
    schema = app.openapi()
    assert schema["components"]["securitySchemes"]["ApiKey"] == {
        "type": "apiKey",
        "in": "header",
        "name": "x-api-key",
    }
    assert schema["paths"]["/files"]["get"]["security"] == [{"ApiKey": []}]
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        assert (await client.get("/files")).status_code == 401
        assert (await client.get("/files", headers={"x-api-key": "wrong"})).status_code == 401
        assert (await client.get("/files", headers={"x-api-key": created.key})).status_code == 200


@pytest.mark.parametrize("reverse_routes", [False, True])
async def test_api_key_dependencies_keep_each_header_in_mixed_route_schema(
    reverse_routes: bool,
) -> None:
    auth = FastAuth(
        FastAuthOptions(secret_key=SecretStr("a" * 64), database=memory()),
        plugins=[email_password(), api_key()],
    )
    user = await auth.api.create_user(email="mixed-headers@example.com", password="Password123!")
    created = await auth.plugins.get(ApiKeysApi).create(user.id, CreateApiKeyRequest(name="key"))
    app = FastAPI()
    auth.add_middleware(app)
    routes = [
        ("/files", "x-api-key"),
        ("/service", "x-service-key"),
        ("/service-again", "x-service-key"),
        ("/underscore", "x_service_key"),
    ]
    for path, header_name in reversed(routes) if reverse_routes else routes:
        dependency = Depends(auth.depends.api_key(header_name=header_name))

        async def protected(key: ApiKeyView = dependency) -> ApiKeyView:
            return key

        app.get(path)(protected)

    schema = app.openapi()
    schemes = schema["components"]["securitySchemes"]
    assert len(schemes) == 3
    scheme_ids: dict[str, str] = {}
    for path, header_name in routes:
        requirement = schema["paths"][path]["get"]["security"]
        assert len(requirement) == 1
        scheme_id = next(iter(requirement[0]))
        assert schemes[scheme_id] == {"type": "apiKey", "in": "header", "name": header_name}
        if header_name in scheme_ids:
            assert scheme_id == scheme_ids[header_name]
        scheme_ids[header_name] = scheme_id
    assert scheme_ids["x-api-key"] == "ApiKey"
    assert len(set(scheme_ids.values())) == 3

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        for path, header_name in routes:
            assert (await client.get(path, headers={header_name: created.key})).status_code == 200
            for wrong_header in set(scheme_ids) - {header_name}:
                assert (
                    await client.get(path, headers={wrong_header: created.key})
                ).status_code == 401
