"""Integration tests for the ApiKeyPlugin (Task 19)."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from fastauth.plugins.api_key import ApiKeyOptions, ApiKeyPlugin
from fastauth.runtime.auth import FastAuth
from fastauth.storage.memory import InMemoryAdapter


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


async def test_list_rejects_invalid_pagination(client: httpx.AsyncClient) -> None:
    await signed_in_client(client)

    negative_offset = await client.get("/auth/api-key/list", params={"offset": -1})
    zero_limit = await client.get("/auth/api-key/list", params={"limit": 0})

    assert negative_offset.status_code == 422
    assert zero_limit.status_code == 422


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


async def test_refill_restores_remaining_quota(
    client: httpx.AsyncClient,
    adapter: InMemoryAdapter,
) -> None:
    await signed_in_client(client)
    created = await client.post(
        "/auth/api-key/create",
        json={
            "name": "refill",
            "remaining": 1,
            "refillAmount": 1,
            "refillInterval": "PT1S",
        },
    )
    body = created.json()
    plain_key = body["key"]
    api_key_id = body["apiKey"]["id"]
    first = await client.post("/auth/api-key/verify", json={"key": plain_key})
    second = await client.post("/auth/api-key/verify", json={"key": plain_key})
    assert first.json()["valid"] is True
    assert second.json()["valid"] is False
    assert second.json()["error"]["code"] == "API_KEY_EXHAUSTED"

    stored = adapter.api_keys[api_key_id]
    assert stored.last_refill_at is not None
    stored.last_refill_at = datetime.now(UTC) - timedelta(seconds=2)
    await adapter.update_api_key(stored)

    third = await client.post("/auth/api-key/verify", json={"key": plain_key})
    assert third.json()["valid"] is True


async def test_rate_limit_is_enforced(client: httpx.AsyncClient) -> None:
    await signed_in_client(client)
    created = await client.post(
        "/auth/api-key/create",
        json={"name": "limited", "rateLimitMax": 1, "rateLimitWindow": "PT1M"},
    )
    plain_key = created.json()["key"]
    first = await client.post("/auth/api-key/verify", json={"key": plain_key})
    second = await client.post("/auth/api-key/verify", json={"key": plain_key})

    assert first.json()["valid"] is True
    assert second.json()["valid"] is False
    assert second.json()["error"]["code"] == "API_KEY_RATE_LIMITED"


async def test_insufficient_permission_does_not_consume_remaining_quota(
    client: httpx.AsyncClient,
) -> None:
    await signed_in_client(client)
    created = await client.post(
        "/auth/api-key/create",
        json={
            "name": "limited",
            "remaining": 1,
            "permissions": {"deploy": ["read"]},
        },
    )
    plain_key = created.json()["key"]
    denied = await client.post(
        "/auth/api-key/verify",
        json={"key": plain_key, "permissions": {"deploy": ["write"]}},
    )
    allowed = await client.post(
        "/auth/api-key/verify",
        json={"key": plain_key, "permissions": {"deploy": ["read"]}},
    )
    exhausted = await client.post("/auth/api-key/verify", json={"key": plain_key})

    assert denied.json()["valid"] is False
    assert denied.json()["error"]["code"] == "INSUFFICIENT_PERMISSIONS"
    assert allowed.json()["valid"] is True
    assert exhausted.json()["valid"] is False
    assert exhausted.json()["error"]["code"] == "API_KEY_EXHAUSTED"


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


async def test_update_rejects_empty_name(client: httpx.AsyncClient) -> None:
    await signed_in_client(client)
    created = (await client.post("/auth/api-key/create", json={"name": "ci"})).json()
    response = await client.post(
        "/auth/api-key/update",
        json={"id": created["apiKey"]["id"], "name": ""},
    )
    assert response.status_code == 422


@pytest.mark.parametrize(
    "payload",
    [
        {"name": "bad", "refillAmount": 1},
        {"name": "bad", "refillInterval": "PT1M"},
        {"name": "bad", "rateLimitMax": 10},
        {"name": "bad", "rateLimitWindow": "PT1M"},
    ],
)
async def test_create_rejects_incomplete_paired_options(
    client: httpx.AsyncClient,
    payload: dict[str, object],
) -> None:
    await signed_in_client(client)
    response = await client.post("/auth/api-key/create", json=payload)
    assert response.status_code == 422


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
