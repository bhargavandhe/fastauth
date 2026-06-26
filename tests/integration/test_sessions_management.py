"""Integration tests for ``GET/DELETE /auth/sessions`` endpoints."""

from __future__ import annotations

import httpx
import pytest

COOKIE_NAME = "fastauth.session_token"


async def sign_up_and_capture_cookie(
    client: httpx.AsyncClient,
    *,
    email: str = "owner@example.com",
    password: str = "supersecret123",
) -> str:
    response = await client.post(
        "/auth/sign-up/email",
        json={"email": email, "password": password},
    )
    assert response.status_code == 200, response.text
    cookie = response.cookies.get(COOKIE_NAME)
    assert cookie is not None
    return cookie


async def open_extra_session(
    client: httpx.AsyncClient,
    *,
    email: str = "owner@example.com",
    password: str = "supersecret123",
) -> str:
    """Open a second concurrent session for the user without permanently
    changing the caller's cookie jar. We temporarily clear cookies, perform a
    fresh sign-in, capture the resulting session cookie, then restore the
    caller's original cookies.
    """
    saved = httpx.Cookies(client.cookies)
    client.cookies.clear()
    try:
        response = await client.post(
            "/auth/sign-in/email",
            json={"email": email, "password": password},
        )
        assert response.status_code == 200, response.text
        cookie = response.cookies.get(COOKIE_NAME)
        assert cookie is not None
        return cookie
    finally:
        client.cookies = saved


async def test_list_sessions_returns_only_current_after_signup(
    client: httpx.AsyncClient,
) -> None:
    await sign_up_and_capture_cookie(client)
    response = await client.get("/auth/sessions")
    assert response.status_code == 200
    payload = response.json()
    assert len(payload["sessions"]) == 1
    assert payload["sessions"][0]["is_current"] is True
    # Sensitive fields must not leak.
    assert "token_hash" not in payload["sessions"][0]


async def test_list_sessions_marks_only_current_session(
    client: httpx.AsyncClient,
) -> None:
    await sign_up_and_capture_cookie(client)
    await open_extra_session(client)
    response = await client.get("/auth/sessions")
    assert response.status_code == 200
    sessions = response.json()["sessions"]
    assert len(sessions) == 2
    current_flags = [s["is_current"] for s in sessions]
    assert current_flags.count(True) == 1
    assert current_flags.count(False) == 1


async def test_list_sessions_requires_authentication(
    client: httpx.AsyncClient,
) -> None:
    response = await client.get("/auth/sessions")
    assert response.status_code == 401
    body = response.json()
    assert body["code"] == "INVALID_CREDENTIALS"


async def test_revoke_specific_session(client: httpx.AsyncClient) -> None:
    await sign_up_and_capture_cookie(client)
    await open_extra_session(client)
    listed = (await client.get("/auth/sessions")).json()["sessions"]
    other = next(s for s in listed if not s["is_current"])
    response = await client.delete(f"/auth/sessions/{other['id']}")
    assert response.status_code == 200
    assert response.json() == {"revoked": 1}
    after = (await client.get("/auth/sessions")).json()["sessions"]
    assert len(after) == 1
    assert after[0]["is_current"] is True


async def test_revoke_unknown_session_returns_404(client: httpx.AsyncClient) -> None:
    await sign_up_and_capture_cookie(client)
    response = await client.delete("/auth/sessions/not-a-real-session-id")
    assert response.status_code == 404
    assert response.json()["code"] == "NOT_FOUND"


async def test_revoke_other_users_session_returns_404(
    client: httpx.AsyncClient,
) -> None:
    """Revoking another user's session must not leak its existence."""
    await sign_up_and_capture_cookie(client, email="a@example.com")
    # User B signs up under the same client (cookie-jar swap pattern).
    saved = httpx.Cookies(client.cookies)
    client.cookies.clear()
    await client.post(
        "/auth/sign-up/email",
        json={"email": "b@example.com", "password": "alsosecret123"},
    )
    b_sessions = (await client.get("/auth/sessions")).json()["sessions"]
    b_session_id = b_sessions[0]["id"]
    client.cookies = saved
    response = await client.delete(f"/auth/sessions/{b_session_id}")
    assert response.status_code == 404


async def test_revoke_other_sessions_keeps_current(client: httpx.AsyncClient) -> None:
    await sign_up_and_capture_cookie(client)
    await open_extra_session(client)
    await open_extra_session(client)
    listed = (await client.get("/auth/sessions")).json()["sessions"]
    assert len(listed) == 3
    response = await client.delete("/auth/sessions")
    assert response.status_code == 200
    assert response.json() == {"revoked": 2}
    after = (await client.get("/auth/sessions")).json()["sessions"]
    assert len(after) == 1
    assert after[0]["is_current"] is True


@pytest.mark.parametrize(
    "endpoint,method",
    [
        ("/auth/sessions", "GET"),
        ("/auth/sessions/anything", "DELETE"),
        ("/auth/sessions", "DELETE"),
    ],
)
async def test_session_endpoints_reject_unauthenticated(
    client: httpx.AsyncClient,
    endpoint: str,
    method: str,
) -> None:
    response = await client.request(method, endpoint)
    assert response.status_code == 401
    assert response.json()["code"] == "INVALID_CREDENTIALS"
