"""Integration tests for canonical Pydantic HTTP aliases."""

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


def make_options(adapter: InMemoryAdapter) -> FastAuthOptions:
    return FastAuthOptions(
        secret_key=SecretStr("a" * 64),
        database=custom(adapter),
        plugins=[email_password()],
        csrf=CsrfOptions(enabled=False),
        cookie=CookieOptions(secure=False),
        rate_limit=RateLimitOptions(enabled=False),
    )


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    adapter = InMemoryAdapter()
    auth = FastAuth(
        make_options(adapter),
        email_sender=ConsoleEmailSender(),
    )
    app = FastAPI(lifespan=auth.lifespan)
    auth.mount(app)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as c:
        yield c


async def test_http_responses_emit_camel_case_pydantic_aliases(
    client: httpx.AsyncClient,
) -> None:
    response = await client.post(
        "/auth/sign-up/email",
        json={
            "email": "alice@example.com",
            "password": "supersecret123",
            "delivery": {"kind": "bearer"},
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()

    assert "credentials" in body
    assert "refreshToken" in body["credentials"]
    assert "refresh_token" not in body

    user = body["user"]
    assert "emailVerified" in user
    assert "email_verified" not in user
    assert "createdAt" in user
    assert "created_at" not in user

    session = body["session"]
    assert "userId" in session
    assert "user_id" not in session
    assert "expiresAt" in session
    assert "expires_at" not in session
    assert "tokenHash" not in session
    assert "token_hash" not in session


async def test_http_requests_accept_camel_case_input_aliases(
    client: httpx.AsyncClient,
) -> None:
    response = await client.post(
        "/auth/sign-up/email",
        json={
            "email": "bob@example.com",
            "password": "supersecret123",
            "delivery": {"kind": "bearer", "includeRefreshToken": True},
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["credentials"]["token"] is not None
    assert body["credentials"]["refreshToken"] is not None


async def test_metadata_keys_are_not_recursively_camelized(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/auth/sign-up/email",
        json={
            "email": "carol@example.com",
            "password": "supersecret123",
        },
    )
    assert response.status_code == 200, response.text

    response = await client.patch(
        "/auth/user",
        json={
            "metadata": {
                "preferred_locale": "fr-FR",
                "avatar_url": "https://example.com/avatar.png",
            },
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()

    assert body["metadata"] == {
        "preferred_locale": "fr-FR",
        "avatar_url": "https://example.com/avatar.png",
    }
    assert "preferredLocale" not in body["metadata"]
    assert "avatarUrl" not in body["metadata"]
