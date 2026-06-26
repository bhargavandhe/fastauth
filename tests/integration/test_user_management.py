"""Integration tests for authenticated user-management endpoints."""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx

from authkit.domain.enums import ProviderId
from authkit.messaging.email import ConsoleEmailSender
from authkit.runtime.auth import AuthKit
from authkit.storage.memory import InMemoryAdapter

SIGNUP = {"email": "alice@example.com", "password": "correct-horse-staple", "name": "Alice"}


async def sign_up(client: httpx.AsyncClient) -> dict[str, Any]:
    response = await client.post("/auth/sign-up/email", json=SIGNUP)
    assert response.status_code == 200, response.text
    return response.json()


def extract_token_from_outbox(email_outbox: ConsoleEmailSender) -> str:
    assert len(email_outbox.outbox) == 1
    parsed = next(
        urlparse(line.strip())
        for line in email_outbox.outbox[0].text.splitlines()
        if line.strip().startswith("http")
    )
    return parse_qs(parsed.query)["token"][0]


async def test_update_profile_replaces_metadata_and_preserves_omitted_fields(
    client: httpx.AsyncClient,
    adapter: InMemoryAdapter,
) -> None:
    body = await sign_up(client)
    user_id = body["user"]["id"]

    response = await client.patch(
        "/auth/user",
        json={
            "name": "Alicia",
            "image": "https://example.com/avatar.png",
            "metadata": {"plan": "pro"},
        },
    )
    assert response.status_code == 200, response.text
    updated = response.json()
    assert updated["email"] == SIGNUP["email"]
    assert updated["name"] == "Alicia"
    assert updated["image"] == "https://example.com/avatar.png"
    assert updated["metadata"] == {"plan": "pro"}

    response = await client.patch("/auth/user", json={"metadata": {}})
    assert response.status_code == 200, response.text
    updated = response.json()
    assert updated["name"] == "Alicia"
    assert updated["image"] == "https://example.com/avatar.png"
    assert updated["metadata"] == {}

    response = await client.patch("/auth/user", json={"metadata": None})
    assert response.status_code == 422

    persisted = await adapter.get_user_by_id(str(user_id))
    assert persisted is not None
    assert persisted.name == "Alicia"


async def test_set_password_for_passwordless_user_allows_credential_sign_in(
    client: httpx.AsyncClient,
    adapter: InMemoryAdapter,
    auth: AuthKit,
) -> None:
    body = await sign_up(client)
    user_id = str(body["user"]["id"])
    account = await adapter.get_account_for_user(user_id, ProviderId.CREDENTIAL)
    assert account is not None
    account.password = None
    await adapter.update_account(account)
    user = await adapter.get_user_by_id(user_id)
    assert user is not None
    other = await auth.context.session_strategy.create(user, ip=None, user_agent=None)

    response = await client.post(
        "/auth/set-password",
        json={"new_password": "new-secret-42-aaa"},
    )
    assert response.status_code == 200, response.text
    assert response.json() == {"success": True}

    sessions = await adapter.list_sessions_for_user(user_id)
    assert len(sessions) == 1
    assert sessions[0].id != other.session.id
    assert (await client.get("/auth/get-session")).status_code == 200

    response = await client.post(
        "/auth/set-password",
        json={"new_password": "another-secret-42"},
    )
    assert response.status_code == 409

    client.cookies.clear()
    response = await client.post(
        "/auth/sign-in/email",
        json={"email": SIGNUP["email"], "password": "new-secret-42-aaa"},
    )
    assert response.status_code == 200, response.text


async def test_verify_password_success_and_lockout(
    client: httpx.AsyncClient,
) -> None:
    await sign_up(client)

    response = await client.post(
        "/auth/verify-password",
        json={"password": SIGNUP["password"]},
    )
    assert response.status_code == 200, response.text
    assert response.json() == {"valid": True}

    for _ in range(5):
        response = await client.post("/auth/verify-password", json={"password": "wrong"})
        assert response.status_code == 401

    response = await client.post("/auth/verify-password", json={"password": "wrong"})
    assert response.status_code == 423


async def test_delete_account_with_password_clears_session_and_auth_state(
    client: httpx.AsyncClient,
    adapter: InMemoryAdapter,
) -> None:
    body = await sign_up(client)
    user_id = str(body["user"]["id"])

    response = await client.post(
        "/auth/delete-account",
        json={"password": SIGNUP["password"]},
    )
    assert response.status_code == 200, response.text
    assert response.json() == {"success": True}
    assert "authkit.session_token" in response.headers.get("set-cookie", "")

    assert await adapter.get_user_by_id(user_id) is None
    assert await adapter.get_account_for_user(user_id, ProviderId.CREDENTIAL) is None
    assert await adapter.list_sessions_for_user(user_id) == []
    assert (await client.get("/auth/get-session")).status_code == 204


async def test_delete_account_with_email_token(
    client: httpx.AsyncClient,
    email_outbox: ConsoleEmailSender,
    adapter: InMemoryAdapter,
) -> None:
    body = await sign_up(client)
    user_id = str(body["user"]["id"])

    response = await client.post("/auth/delete-account/request")
    assert response.status_code == 200, response.text
    assert email_outbox.outbox[0].to == SIGNUP["email"]
    token = extract_token_from_outbox(email_outbox)

    response = await client.post("/auth/delete-account/confirm", json={"token": token})
    assert response.status_code == 200, response.text
    assert response.json() == {"success": True}
    assert await adapter.get_user_by_id(user_id) is None
    assert (await client.get("/auth/get-session")).status_code == 204
