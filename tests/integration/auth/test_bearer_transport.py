"""Bearer transport symmetry: cookie and Authorization: Bearer both feed read()."""

from __future__ import annotations

import httpx

from fastauth.runtime.auth import FastAuth
from fastauth.storage.memory import InMemoryAdapter


async def test_get_session_works_with_bearer_only(client: httpx.AsyncClient) -> None:
    sign_up = await client.post(
        "/auth/sign-up/email",
        json={"email": "alice@example.com", "password": "correct-horse-staple"},
    )
    assert sign_up.status_code == 200
    cookie_value = client.cookies.get("fastauth.session_token")
    assert cookie_value is not None

    # Drop cookies entirely; use the raw bearer.
    client.cookies.clear()

    # Server-side: we need the plain token. The sign-up response embeds the session
    # body but not the token (security). For tests, the test-utils plugin (Task 23)
    # provides login helpers. Here we use a bogus token to confirm bearer parsing
    # is wired (an unwired path would silently ignore the header and behave the
    # same as a cookieless request — which also returns 204, so we still want the
    # complementary positive test below).
    response = await client.get(
        "/auth/get-session",
        headers={"authorization": "Bearer not-a-real-token"},
    )
    assert response.status_code == 204  # invalid token → no session


async def test_get_session_with_valid_bearer_via_test_helper(
    client: httpx.AsyncClient,
    auth: FastAuth,
    adapter: InMemoryAdapter,
) -> None:
    sign_up = await client.post(
        "/auth/sign-up/email",
        json={"email": "alice@example.com", "password": "correct-horse-staple"},
    )
    assert sign_up.status_code == 200
    # Read the raw session out of the in-memory adapter and reconstruct the plain token
    # via the SessionStrategy (test helper pattern; production uses TestUtilsPlugin).
    sessions = list(adapter.sessions.values())
    assert len(sessions) == 1
    # The plain token is not retrievable from the hash; we instead create a fresh
    # session via the strategy and assert it reads back via bearer.
    user = next(iter(adapter.users.values()))
    context = await auth.context.session_strategy.create(user, ip=None, user_agent=None)

    client.cookies.clear()
    response = await client.get(
        "/auth/get-session",
        headers={"authorization": f"Bearer {context.token}"},
    )
    assert response.status_code == 200
    assert response.json()["user"]["id"] == user.id
