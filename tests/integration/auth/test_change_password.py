"""Integration tests for POST /auth/change-password (authenticated flow)."""

from __future__ import annotations

import httpx
import pytest

from fastauth.runtime.auth import FastAuth
from fastauth.storage.memory import InMemoryAdapter

SIGNUP = {"email": "alice@example.com", "password": "correct-horse-staple", "name": "Alice"}


@pytest.fixture
async def signed_in(client: httpx.AsyncClient) -> httpx.AsyncClient:
    response = await client.post("/auth/sign-up/email", json=SIGNUP)
    assert response.status_code == 200
    return client


async def test_change_password_round_trip(signed_in: httpx.AsyncClient) -> None:
    response = await signed_in.post(
        "/auth/change-password",
        json={
            "current_password": SIGNUP["password"],
            "new_password": "new-secret-42-aaa",
        },
    )
    assert response.status_code == 200
    assert response.json() == {"success": True}

    # Old password no longer works
    signed_in.cookies.clear()
    bad = await signed_in.post(
        "/auth/sign-in/email",
        json={"email": SIGNUP["email"], "password": SIGNUP["password"]},
    )
    assert bad.status_code == 401
    # New password works
    good = await signed_in.post(
        "/auth/sign-in/email",
        json={"email": SIGNUP["email"], "password": "new-secret-42-aaa"},
    )
    assert good.status_code == 200


async def test_change_password_keeps_current_refresh_token(
    client: httpx.AsyncClient,
) -> None:
    sign_up = await client.post(
        "/auth/sign-up/email",
        json={**SIGNUP, "delivery": {"kind": "bearer"}},
    )
    assert sign_up.status_code == 200
    body = sign_up.json()
    refresh_token = body["credentials"]["refreshToken"]
    access_token = body["credentials"]["token"]

    change = await client.post(
        "/auth/change-password",
        headers={"authorization": f"Bearer {access_token}"},
        json={
            "current_password": SIGNUP["password"],
            "new_password": "new-secret-42-aaa",
        },
    )
    assert change.status_code == 200

    refresh = await client.post(
        "/auth/refresh",
        json={"refreshToken": refresh_token, "delivery": {"kind": "bearer"}},
    )
    assert refresh.status_code == 200
    assert refresh.json()["credentials"]["refreshToken"] is not None


async def test_change_password_clears_lockout_for_email_and_username(
    client: httpx.AsyncClient,
) -> None:
    payload = {
        "email": "alice@example.com",
        "username": "alice",
        "password": "correct-horse-staple",
    }
    sign_up = await client.post("/auth/sign-up/email", json=payload)
    assert sign_up.status_code == 200

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

    change = await client.post(
        "/auth/change-password",
        json={
            "current_password": payload["password"],
            "new_password": "new-secret-42-aaa",
        },
    )
    assert change.status_code == 200

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


async def test_change_password_rejects_wrong_current_password(
    signed_in: httpx.AsyncClient,
) -> None:
    response = await signed_in.post(
        "/auth/change-password",
        json={"current_password": "wrong", "new_password": "new-secret-42-aaa"},
    )
    assert response.status_code == 401
    assert response.json()["code"] == "INVALID_CREDENTIALS"


async def test_change_password_rejects_short_new_password(
    signed_in: httpx.AsyncClient,
) -> None:
    response = await signed_in.post(
        "/auth/change-password",
        json={"current_password": SIGNUP["password"], "new_password": "short"},
    )
    assert response.status_code == 400
    assert response.json()["code"] == "INVALID_REQUEST"


async def test_change_password_requires_authentication(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/auth/change-password",
        json={"current_password": "x", "new_password": "long-enough-aaa"},
    )
    assert response.status_code == 401


async def test_change_password_keeps_current_session_revokes_others(
    client: httpx.AsyncClient, adapter: InMemoryAdapter, auth: FastAuth
) -> None:
    """Default ``revoke_other_sessions=True`` invalidates other sessions; the
    session that issued the change stays alive."""
    sign_up = await client.post("/auth/sign-up/email", json=SIGNUP)
    assert sign_up.status_code == 200
    user = await adapter.get_user_by_email(SIGNUP["email"])
    assert user is not None
    # Mint a second session out-of-band (simulating "logged in from a 2nd device").
    other = await auth.context.session_strategy.create(user, ip=None, user_agent=None)
    assert len(await adapter.list_sessions_for_user(user.id)) == 2

    change = await client.post(
        "/auth/change-password",
        json={
            "current_password": SIGNUP["password"],
            "new_password": "new-secret-42-aaa",
        },
    )
    assert change.status_code == 200

    remaining = await adapter.list_sessions_for_user(user.id)
    assert len(remaining) == 1
    # The OTHER session was the one revoked; the cookie-bearing session survives.
    assert remaining[0].id != other.session.id
    # The current session still authenticates ``/auth/get-session``.
    assert (await client.get("/auth/get-session")).status_code == 200


async def test_change_password_keeps_all_sessions_when_opted_out(
    client: httpx.AsyncClient, adapter: InMemoryAdapter, auth: FastAuth
) -> None:
    """``revoke_other_sessions=False`` leaves every other session alive."""
    await client.post("/auth/sign-up/email", json=SIGNUP)
    user = await adapter.get_user_by_email(SIGNUP["email"])
    assert user is not None
    await auth.context.session_strategy.create(user, ip=None, user_agent=None)
    await auth.context.session_strategy.create(user, ip=None, user_agent=None)
    assert len(await adapter.list_sessions_for_user(user.id)) == 3

    change = await client.post(
        "/auth/change-password",
        json={
            "current_password": SIGNUP["password"],
            "new_password": "new-secret-42-aaa",
            "revoke_other_sessions": False,
        },
    )
    assert change.status_code == 200
    assert len(await adapter.list_sessions_for_user(user.id)) == 3
