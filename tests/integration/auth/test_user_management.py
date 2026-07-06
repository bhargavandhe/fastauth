"""Integration tests for authenticated user-management endpoints."""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx

from fastauth.domain.enums import ProviderId
from fastauth.messaging.email import ConsoleEmailSender
from fastauth.runtime.auth import FastAuth
from fastauth.storage.memory import InMemoryAdapter

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
    auth: FastAuth,
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


async def test_set_password_revokes_existing_refresh_tokens(
    client: httpx.AsyncClient,
    adapter: InMemoryAdapter,
) -> None:
    response = await client.post(
        "/auth/sign-up/email",
        json={**SIGNUP, "delivery": {"kind": "bearer"}},
    )
    assert response.status_code == 200
    body = response.json()
    user_id = str(body["user"]["id"])
    refresh_token = body["credentials"]["refreshToken"]
    access_token = body["credentials"]["token"]
    account = await adapter.get_account_for_user(user_id, ProviderId.CREDENTIAL)
    assert account is not None
    account.password = None
    await adapter.update_account(account)

    set_password = await client.post(
        "/auth/set-password",
        headers={"authorization": f"Bearer {access_token}"},
        json={"new_password": "new-secret-42-aaa"},
    )
    assert set_password.status_code == 200

    refresh = await client.post(
        "/auth/refresh",
        json={"refreshToken": refresh_token, "delivery": {"kind": "bearer"}},
    )
    assert refresh.status_code == 400
    assert refresh.json()["code"] == "TOKEN_INVALID"


async def test_set_password_clears_lockout_for_email_and_username(
    client: httpx.AsyncClient,
    adapter: InMemoryAdapter,
) -> None:
    payload = {
        "email": "alice@example.com",
        "username": "alice",
        "password": "correct-horse-staple",
    }
    sign_up_response = await client.post("/auth/sign-up/email", json=payload)
    assert sign_up_response.status_code == 200
    user_id = sign_up_response.json()["user"]["id"]

    account = await adapter.get_account_for_user(user_id, ProviderId.CREDENTIAL)
    assert account is not None
    account.password = None
    await adapter.update_account(account)

    email_attempt: httpx.Response | None = None
    username_attempt: httpx.Response | None = None
    for _ in range(6):
        email_attempt = await client.post(
            "/auth/sign-in/email",
            json={"email": payload["email"], "password": "wrong-password"},
        )
        username_attempt = await client.post(
            "/auth/sign-in/username",
            json={"username": payload["username"], "password": "wrong-password"},
        )
    assert email_attempt is not None
    assert username_attempt is not None
    assert email_attempt.status_code == 423
    assert username_attempt.status_code == 423

    set_password = await client.post(
        "/auth/set-password",
        json={"new_password": "new-secret-42-aaa"},
    )
    assert set_password.status_code == 200

    client.cookies.clear()
    email_sign_in = await client.post(
        "/auth/sign-in/email",
        json={"email": payload["email"], "password": "new-secret-42-aaa"},
    )
    assert email_sign_in.status_code == 200

    client.cookies.clear()
    username_sign_in = await client.post(
        "/auth/sign-in/username",
        json={"username": payload["username"], "password": "new-secret-42-aaa"},
    )
    assert username_sign_in.status_code == 200


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
    assert "fastauth.session_token" in response.headers.get("set-cookie", "")

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
