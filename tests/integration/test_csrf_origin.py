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
from authkit.web.fastapi import install_csrf


def csrf_config() -> AuthKitConfig:
    return AuthKitConfig.model_validate(
        {
            "secret_key": SecretStr("a" * 64),
            "csrf": {"enabled": True, "trusted_origins": ["http://trusted.test"]},
            "cookie": {"secure": False},
            "rate_limit": {"enabled": False},
        },
    )


@pytest.fixture
async def csrf_client() -> AsyncIterator[httpx.AsyncClient]:
    adapter = InMemoryAdapter()
    sender = ConsoleEmailSender()
    auth = AuthKit(csrf_config(), adapter=adapter, email_sender=sender)
    app = FastAPI()
    app.include_router(auth.router)
    install_csrf(app, auth.context)
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
