"""Integration tests for the /auth/health endpoint and AuthApi.health()."""

from __future__ import annotations

import httpx

from authkit.runtime.auth import AuthKit


async def test_health_endpoint_via_router(client: httpx.AsyncClient) -> None:
    response = await client.get("/auth/health")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["name"] == "authkit"


async def test_health_endpoint_via_auth_api(
    client: httpx.AsyncClient,
    auth: AuthKit,
) -> None:
    payload = await auth.api.health()
    assert payload.status == "ok"
    assert payload.name == "authkit"
