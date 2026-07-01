from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
from fastapi import FastAPI
from pydantic import SecretStr

from fastauth.database import custom
from fastauth.messaging.email import ConsoleEmailSender
from fastauth.options import CookieOptions, CsrfOptions, FastAuthOptions, RateLimitOptions
from fastauth.providers import email_password
from fastauth.runtime.auth import FastAuth
from fastauth.storage.memory import InMemoryAdapter


def csrf_options(adapter: InMemoryAdapter) -> FastAuthOptions:
    return FastAuthOptions(
        secret_key=SecretStr("a" * 64),
        database=custom(adapter),
        plugins=[email_password()],
        csrf=CsrfOptions(enabled=True, trusted_origins=("http://trusted.test",)),
        cookie=CookieOptions(secure=False),
        rate_limit=RateLimitOptions(enabled=False),
    )


@pytest.fixture
async def csrf_client() -> AsyncIterator[httpx.AsyncClient]:
    adapter = InMemoryAdapter()
    sender = ConsoleEmailSender()
    auth = FastAuth(csrf_options(adapter), email_sender=sender)
    app = FastAPI(lifespan=auth.lifespan)
    auth.mount(app)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        yield client


async def test_cross_origin_post_is_blocked(csrf_client: httpx.AsyncClient) -> None:
    response = await csrf_client.post(
        "/auth/sign-up/email",
        json={"email": "x@example.com", "password": "correct-horse-staple"},
        headers={"origin": "http://evil.test"},
    )
    assert response.status_code == 403
    assert response.json()["code"] == "CSRF_FORBIDDEN"


async def test_trusted_origin_post_is_allowed(csrf_client: httpx.AsyncClient) -> None:
    response = await csrf_client.post(
        "/auth/sign-up/email",
        json={"email": "x@example.com", "password": "correct-horse-staple"},
        headers={"origin": "http://trusted.test"},
    )
    assert response.status_code == 200


async def test_bearer_only_post_bypasses_csrf(csrf_client: httpx.AsyncClient) -> None:
    # Bearer-only requests have no cookie attached; CSRF must not block.
    response = await csrf_client.post(
        "/auth/sign-out",
        headers={"authorization": "Bearer fake-token"},
    )
    # 200 (anonymous sign-out is a no-op with success: True); never 403.
    assert response.status_code != 403
