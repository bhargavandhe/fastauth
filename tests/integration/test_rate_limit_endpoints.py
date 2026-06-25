"""Integration tests: rate limiter on /sign-in/email returns 429 with X-Retry-After."""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
from fastapi import FastAPI
from pydantic import SecretStr

from authkit.config import AuthKitConfig
from authkit.messaging.email import ConsoleEmailSender
from authkit.runtime.auth import AuthKit
from authkit.storage.memory import InMemoryAdapter


@pytest.fixture
async def rl_client() -> AsyncIterator[httpx.AsyncClient]:
    auth = AuthKit(
        AuthKitConfig.model_validate(
            {
                "secret_key": SecretStr("a" * 64),
                "csrf": {"enabled": False},
                "cookie": {"secure": False},
                "rate_limit": {"enabled": True, "window_seconds": 60, "max_requests": 100},
            },
        ),
        adapter=InMemoryAdapter(),
        email_sender=ConsoleEmailSender(),
    )
    app = FastAPI()
    app.include_router(auth.router)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        yield client


async def test_sign_in_returns_429_after_three_attempts(rl_client: httpx.AsyncClient) -> None:
    body = {"email": "x@example.com", "password": "wrong"}
    statuses = [
        (await rl_client.post("/auth/sign-in/email", json=body)).status_code for _ in range(4)
    ]
    assert statuses[:3] == [401, 401, 401]
    assert statuses[3] == 429


async def test_429_has_retry_after_header(rl_client: httpx.AsyncClient) -> None:
    body = {"email": "x@example.com", "password": "wrong"}
    response: httpx.Response | None = None
    for _ in range(4):
        response = await rl_client.post("/auth/sign-in/email", json=body)
    assert response is not None
    assert response.status_code == 429
    assert response.headers.get("x-retry-after", "").isdigit()
