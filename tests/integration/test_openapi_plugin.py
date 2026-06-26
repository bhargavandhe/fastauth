"""Integration tests for the OpenApiPlugin (Task 22)."""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from fastauth.plugins.openapi import OpenApiConfig, OpenApiPlugin
from fastauth.runtime.auth import FastAuth


@pytest.fixture
def auth(auth_factory: Callable[..., FastAuth]) -> FastAuth:
    return auth_factory(plugins=[OpenApiPlugin(OpenApiConfig())])


async def test_reference_serves_scalar_html(client: httpx.AsyncClient) -> None:
    response = await client.get("/auth/reference")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")
    assert "@scalar/api-reference" in response.text


async def test_openapi_json_returns_3_1_schema(client: httpx.AsyncClient) -> None:
    response = await client.get("/auth/openapi.json")
    assert response.status_code == 200
    body = response.json()
    assert body["openapi"].startswith("3.")
    paths = body["paths"]
    assert any(path.endswith("/sign-up/email") for path in paths)


async def test_auth_api_generate_schema(auth: FastAuth) -> None:
    schema = await auth.api.generate_openapi_schema()
    assert schema["info"]["title"] == "fastauth API"
