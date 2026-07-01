"""Integration tests for the ApiKeyPlugin (Task 19)."""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from fastauth.plugins.api_key import ApiKeyOptions, ApiKeyPlugin
from fastauth.runtime.auth import FastAuth


@pytest.fixture
def auth(auth_factory: Callable[..., FastAuth]) -> FastAuth:
    return auth_factory(plugins=[ApiKeyPlugin(ApiKeyOptions())])


async def signed_in_client(client: httpx.AsyncClient) -> httpx.AsyncClient:
    response = await client.post(
        "/auth/sign-up/email",
        json={"email": "alice@example.com", "password": "correct-horse-staple"},
    )
    assert response.status_code == 200
    return client


async def test_create_api_key_returns_plain_key(client: httpx.AsyncClient) -> None:
    await signed_in_client(client)
    response = await client.post("/auth/api-key/create", json={"name": "ci"})
    assert response.status_code == 200
    body = response.json()
    assert "key" in body
    assert body["key"].startswith("ak_")
    assert body["apiKey"]["name"] == "ci"
    assert "keyHash" not in body["apiKey"]


async def test_verify_round_trip(client: httpx.AsyncClient) -> None:
    await signed_in_client(client)
    created = (await client.post("/auth/api-key/create", json={"name": "ci"})).json()
    verify = await client.post(
        "/auth/api-key/verify",
        json={"key": created["key"]},
    )
    assert verify.status_code == 200
    assert verify.json()["valid"] is True


async def test_verify_invalid_key(client: httpx.AsyncClient) -> None:
    response = await client.post("/auth/api-key/verify", json={"key": "ak_garbage"})
    assert response.status_code == 200
    assert response.json()["valid"] is False


async def test_list_and_delete(client: httpx.AsyncClient) -> None:
    await signed_in_client(client)
    for index in range(3):
        await client.post("/auth/api-key/create", json={"name": f"key-{index}"})
    listed = await client.get("/auth/api-key/list", params={"limit": 10, "offset": 0})
    assert listed.status_code == 200
    body = listed.json()
    assert body["total"] == 3
    assert len(body["items"]) == 3
    api_key_id = body["items"][0]["id"]
    deleted = await client.post("/auth/api-key/delete", json={"id": api_key_id})
    assert deleted.status_code == 200
    listed_again = (await client.get("/auth/api-key/list")).json()
    assert listed_again["total"] == 2


async def test_remaining_decrements(client: httpx.AsyncClient) -> None:
    await signed_in_client(client)
    created = await client.post(
        "/auth/api-key/create",
        json={"name": "limited", "remaining": 2},
    )
    plain_key = created.json()["key"]
    first = await client.post("/auth/api-key/verify", json={"key": plain_key})
    second = await client.post("/auth/api-key/verify", json={"key": plain_key})
    third = await client.post("/auth/api-key/verify", json={"key": plain_key})
    assert first.json()["valid"] is True
    assert second.json()["valid"] is True
    assert third.json()["valid"] is False
    assert third.json()["error"]["code"] == "API_KEY_EXHAUSTED"


async def test_create_with_expires_in_one_hour_is_valid(
    client: httpx.AsyncClient,
) -> None:
    """Regression: a freshly-created key with a 1-hour TTL must verify as valid.

    Reproduces the live-only "API_KEY_EXPIRED on a fresh key" report. The
    request-model validators reject zero/negative TTLs (see below); this test
    locks in the happy path.
    """
    await signed_in_client(client)
    created = (
        await client.post(
            "/auth/api-key/create",
            json={"name": "ttl-1h", "expiresIn": "PT1H"},
        )
    ).json()
    assert created["apiKey"]["expiresAt"] is not None
    response = await client.post("/auth/api-key/verify", json={"key": created["key"]})
    assert response.status_code == 200
    body = response.json()
    assert body["valid"] is True, body
    assert body["error"] is None


@pytest.mark.parametrize(
    "field,bad_value",
    [
        ("expiresIn", 0),
        ("expiresIn", -1),
        ("remaining", 0),
        ("remaining", -5),
        ("refillAmount", 0),
        ("refillInterval", 0),
        ("rateLimitMax", 0),
        ("rateLimitWindow", 0),
    ],
)
async def test_create_rejects_non_positive_quota_fields(
    client: httpx.AsyncClient,
    field: str,
    bad_value: int,
) -> None:
    """Quota/interval fields must be positive; 0 and negatives are 422-rejected.

    Without this validation, ``expiresIn=-N`` would create an
    instantly-expired key and ``remaining=0`` (the Scalar UI default) would
    create a key that's exhausted on first verify.
    """
    await signed_in_client(client)
    response = await client.post(
        "/auth/api-key/create",
        json={"name": "bad", field: bad_value},
    )
    assert response.status_code == 422, response.text
