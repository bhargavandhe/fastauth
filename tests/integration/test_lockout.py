"""Integration tests for the account-lockout policy on sign-in.

The default lockout config is 5 failures within 15 minutes. Tests opt into
a *smaller* window via a custom config so we can exercise the
"window-rolled-off" code path without sleeping for minutes.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import timedelta

import httpx
import pytest
from fastapi import FastAPI
from pydantic import SecretStr

from fastauth.database import custom
from fastauth.messaging.email import ConsoleEmailSender
from fastauth.options import (
    CookieOptions,
    CsrfOptions,
    FastAuthOptions,
    LockoutOptions,
    RateLimitOptions,
)
from fastauth.providers import email_password
from fastauth.runtime.auth import FastAuth
from fastauth.storage.memory import InMemoryAdapter


@pytest.fixture
async def lockout_client() -> AsyncIterator[httpx.AsyncClient]:
    """A fresh FastAuth with a deliberately small lockout window so the test
    runs in milliseconds. Default ``max_failures=3``, ``window=2s``.
    """
    adapter = InMemoryAdapter()
    options = FastAuthOptions(
        secret_key=SecretStr("a" * 64),
        database=custom(adapter),
        plugins=[email_password()],
        csrf=CsrfOptions(enabled=False),
        cookie=CookieOptions(secure=False),
        rate_limit=RateLimitOptions(enabled=False),
        lockout=LockoutOptions(enabled=True, max_failures=3, window=timedelta(seconds=2)),
    )
    auth = FastAuth(options, email_sender=ConsoleEmailSender())
    app = FastAPI(lifespan=auth.lifespan)
    auth.mount(app)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as http:
        # Pre-seed a user.
        signup = await http.post(
            "/auth/sign-up/email",
            json={"email": "alice@example.com", "password": "correct-horse-staple"},
        )
        assert signup.status_code == 200
        http.cookies.clear()
        yield http


async def test_lockout_triggers_after_max_failures(
    lockout_client: httpx.AsyncClient,
) -> None:
    bad = {"email": "alice@example.com", "password": "wrong"}
    statuses: list[int] = []
    for _ in range(3):
        r = await lockout_client.post("/auth/sign-in/email", json=bad)
        statuses.append(r.status_code)
    assert statuses == [401, 401, 401]
    # The fourth attempt against the locked identifier returns 423 Locked
    # with code ACCOUNT_LOCKED and a Retry-After header.
    locked = await lockout_client.post("/auth/sign-in/email", json=bad)
    assert locked.status_code == 423
    assert locked.json()["code"] == "ACCOUNT_LOCKED"
    assert locked.headers.get("retry-after", "").isdigit()


async def test_lockout_rejects_correct_password_when_locked(
    lockout_client: httpx.AsyncClient,
) -> None:
    bad = {"email": "alice@example.com", "password": "wrong"}
    for _ in range(4):  # cross the threshold
        await lockout_client.post("/auth/sign-in/email", json=bad)
    # Even the RIGHT password is rejected while locked.
    good = await lockout_client.post(
        "/auth/sign-in/email",
        json={"email": "alice@example.com", "password": "correct-horse-staple"},
    )
    assert good.status_code == 423


async def test_lockout_releases_after_window(
    lockout_client: httpx.AsyncClient,
) -> None:
    import asyncio

    bad = {"email": "alice@example.com", "password": "wrong"}
    for _ in range(4):
        await lockout_client.post("/auth/sign-in/email", json=bad)
    # Wait for the window (2s) to roll off, then a valid sign-in succeeds.
    await asyncio.sleep(2.1)
    good = await lockout_client.post(
        "/auth/sign-in/email",
        json={"email": "alice@example.com", "password": "correct-horse-staple"},
    )
    assert good.status_code == 200


async def test_lockout_resets_on_successful_sign_in(
    lockout_client: httpx.AsyncClient,
) -> None:
    bad = {"email": "alice@example.com", "password": "wrong"}
    await lockout_client.post("/auth/sign-in/email", json=bad)
    await lockout_client.post("/auth/sign-in/email", json=bad)
    # Two failures recorded — well below the threshold. Successful sign-in
    # MUST clear the counter, otherwise a third subsequent failure would lock.
    good = await lockout_client.post(
        "/auth/sign-in/email",
        json={"email": "alice@example.com", "password": "correct-horse-staple"},
    )
    assert good.status_code == 200
    lockout_client.cookies.clear()
    # Two more failures must not trigger lockout (counter was reset).
    for _ in range(2):
        r = await lockout_client.post("/auth/sign-in/email", json=bad)
        assert r.status_code == 401  # still unlocked


async def test_lockout_disabled_never_triggers() -> None:
    """``lockout.enabled=False`` keeps the historical sign-in behaviour."""
    adapter = InMemoryAdapter()
    options = FastAuthOptions(
        secret_key=SecretStr("a" * 64),
        database=custom(adapter),
        plugins=[email_password()],
        csrf=CsrfOptions(enabled=False),
        cookie=CookieOptions(secure=False),
        rate_limit=RateLimitOptions(enabled=False),
        lockout=LockoutOptions(enabled=False),
    )
    auth = FastAuth(options, email_sender=ConsoleEmailSender())
    app = FastAPI(lifespan=auth.lifespan)
    auth.mount(app)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as http:
        await http.post(
            "/auth/sign-up/email",
            json={"email": "z@example.com", "password": "correct-horse-staple"},
        )
        http.cookies.clear()
        bad = {"email": "z@example.com", "password": "wrong"}
        for _ in range(20):
            r = await http.post("/auth/sign-in/email", json=bad)
            assert r.status_code == 401  # never escalates to 423
