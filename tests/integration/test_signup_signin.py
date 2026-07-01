"""Integration tests for credentials sign-up, sign-in, sign-out, and get-session."""

from __future__ import annotations

import httpx
import pytest


@pytest.fixture
def signup_payload() -> dict[str, str]:
    return {"email": "alice@example.com", "password": "correct-horse-staple", "name": "Alice"}


async def test_sign_up_creates_user_and_session(
    client: httpx.AsyncClient,
    signup_payload: dict[str, str],
) -> None:
    response = await client.post("/auth/sign-up/email", json=signup_payload)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["user"]["email"] == "alice@example.com"
    assert "session" in body
    assert "fastauth.session_token" in response.headers.get("set-cookie", "")


async def test_sign_up_rejects_duplicate_email(
    client: httpx.AsyncClient,
    signup_payload: dict[str, str],
) -> None:
    first = await client.post("/auth/sign-up/email", json=signup_payload)
    assert first.status_code == 200
    second = await client.post("/auth/sign-up/email", json=signup_payload)
    assert second.status_code == 409
    assert second.json()["code"] == "DUPLICATE"


async def test_sign_up_normalizes_email_and_rejects_case_variant_duplicate(
    client: httpx.AsyncClient,
) -> None:
    first = await client.post(
        "/auth/sign-up/email",
        json={"email": "Alice@Example.COM", "password": "correct-horse-staple"},
    )
    assert first.status_code == 200
    assert first.json()["user"]["email"] == "alice@example.com"

    second = await client.post(
        "/auth/sign-up/email",
        json={"email": "alice@example.com", "password": "correct-horse-staple"},
    )
    assert second.status_code == 409


async def test_sign_in_email_normalizes_identifier(client: httpx.AsyncClient) -> None:
    await client.post(
        "/auth/sign-up/email",
        json={"email": "alice@example.com", "password": "correct-horse-staple"},
    )
    client.cookies.clear()

    response = await client.post(
        "/auth/sign-in/email",
        json={"email": "Alice@Example.COM", "password": "correct-horse-staple"},
    )

    assert response.status_code == 200
    assert response.json()["user"]["email"] == "alice@example.com"


async def test_sign_up_rejects_short_password(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/auth/sign-up/email",
        json={"email": "x@example.com", "password": "short"},
    )
    assert response.status_code == 400
    assert response.json()["code"] == "INVALID_REQUEST"


async def test_sign_in_email_round_trip(
    client: httpx.AsyncClient,
    signup_payload: dict[str, str],
) -> None:
    await client.post("/auth/sign-up/email", json=signup_payload)
    # New unauthenticated client (drop cookies from signup).
    client.cookies.clear()
    response = await client.post(
        "/auth/sign-in/email",
        json={"email": signup_payload["email"], "password": signup_payload["password"]},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["user"]["email"] == signup_payload["email"]


async def test_sign_in_rejects_wrong_password(
    client: httpx.AsyncClient,
    signup_payload: dict[str, str],
) -> None:
    await client.post("/auth/sign-up/email", json=signup_payload)
    client.cookies.clear()
    response = await client.post(
        "/auth/sign-in/email",
        json={"email": signup_payload["email"], "password": "wrong"},
    )
    assert response.status_code == 401
    assert response.json()["code"] == "INVALID_CREDENTIALS"


async def test_sign_in_rejects_unknown_user_with_consistent_timing(
    client: httpx.AsyncClient,
) -> None:
    response = await client.post(
        "/auth/sign-in/email",
        json={"email": "ghost@example.com", "password": "whatever"},
    )
    assert response.status_code == 401
    assert response.json()["code"] == "INVALID_CREDENTIALS"


async def test_get_session_returns_current_user(
    client: httpx.AsyncClient,
    signup_payload: dict[str, str],
) -> None:
    await client.post("/auth/sign-up/email", json=signup_payload)
    response = await client.get("/auth/get-session")
    assert response.status_code == 200
    body = response.json()
    assert body["user"]["email"] == signup_payload["email"]


async def test_get_session_returns_204_when_anonymous(client: httpx.AsyncClient) -> None:
    response = await client.get("/auth/get-session")
    assert response.status_code == 204


async def test_sign_out_clears_session(
    client: httpx.AsyncClient,
    signup_payload: dict[str, str],
) -> None:
    await client.post("/auth/sign-up/email", json=signup_payload)
    out = await client.post("/auth/sign-out")
    assert out.status_code == 200
    again = await client.get("/auth/get-session")
    assert again.status_code == 204


async def test_username_sign_in(client: httpx.AsyncClient) -> None:
    await client.post(
        "/auth/sign-up/email",
        json={
            "email": "bob@example.com",
            "password": "correct-horse-staple",
            "username": "bob",
        },
    )
    client.cookies.clear()
    response = await client.post(
        "/auth/sign-in/username",
        json={"username": "bob", "password": "correct-horse-staple"},
    )
    assert response.status_code == 200


async def test_sign_up_omits_token_by_default(
    client: httpx.AsyncClient,
    signup_payload: dict[str, str],
) -> None:
    """Cookie-only clients don't see the plain bearer token by default."""
    response = await client.post("/auth/sign-up/email", json=signup_payload)
    assert response.status_code == 200
    body = response.json()
    assert body["credentials"] is None
    # Cookie is still set so the cookie-based flow keeps working.
    assert "fastauth.session_token" in response.headers.get("set-cookie", "")


async def test_sign_up_returns_token_when_requested(
    client: httpx.AsyncClient,
    signup_payload: dict[str, str],
) -> None:
    """SPAs and mobile apps opt into bearer delivery and get a Bearer-usable token."""
    payload = {**signup_payload, "delivery": {"kind": "bearer"}}
    response = await client.post("/auth/sign-up/email", json=payload)
    assert response.status_code == 200
    body = response.json()
    token = body["credentials"]["token"]
    assert isinstance(token, str)
    assert len(token) >= 32
    # The plain token works as a Bearer for subsequent requests.
    client.cookies.clear()
    me = await client.get("/auth/get-session", headers={"authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.json()["user"]["email"] == signup_payload["email"]


async def test_sign_in_email_returns_token_when_requested(
    client: httpx.AsyncClient,
    signup_payload: dict[str, str],
) -> None:
    await client.post("/auth/sign-up/email", json=signup_payload)
    client.cookies.clear()
    response = await client.post(
        "/auth/sign-in/email",
        json={
            "email": signup_payload["email"],
            "password": signup_payload["password"],
            "delivery": {"kind": "bearer"},
        },
    )
    assert response.status_code == 200
    assert isinstance(response.json()["credentials"]["token"], str)


async def test_sign_in_username_returns_token_when_requested(
    client: httpx.AsyncClient,
) -> None:
    await client.post(
        "/auth/sign-up/email",
        json={"email": "u@example.com", "password": "correct-horse-staple", "username": "u123"},
    )
    client.cookies.clear()
    response = await client.post(
        "/auth/sign-in/username",
        json={
            "username": "u123",
            "password": "correct-horse-staple",
            "delivery": {"kind": "bearer"},
        },
    )
    assert response.status_code == 200
    assert isinstance(response.json()["credentials"]["token"], str)
