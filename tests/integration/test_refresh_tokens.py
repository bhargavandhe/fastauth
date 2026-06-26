"""Integration tests for refresh tokens + ``POST /auth/refresh``."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from fastapi import FastAPI
from pydantic import SecretStr

from fastauth.config import FastAuthConfig
from fastauth.messaging.email import ConsoleEmailSender
from fastauth.runtime.auth import FastAuth
from fastauth.storage.memory import InMemoryAdapter


def build_config(**refresh_overrides: object) -> FastAuthConfig:
    return FastAuthConfig.model_validate(
        {
            "secret_key": SecretStr("a" * 64),
            "csrf": {"enabled": False},
            "cookie": {"secure": False},
            "rate_limit": {"enabled": False},
            "refresh_token": {"enabled": True, **refresh_overrides},
        },
    )


@pytest.fixture
def adapter() -> InMemoryAdapter:
    return InMemoryAdapter()


@pytest.fixture
def auth(adapter: InMemoryAdapter) -> FastAuth:
    return FastAuth(
        build_config(),
        adapter=adapter,
        email_sender=ConsoleEmailSender(),
    )


@pytest.fixture
async def client(auth: FastAuth) -> AsyncIterator[httpx.AsyncClient]:
    app = FastAPI()
    app.include_router(auth.router)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as http:
        yield http


async def sign_up_with_tokens(
    client: httpx.AsyncClient,
    *,
    email: str = "owner@example.com",
    password: str = "supersecret123",
) -> tuple[str, str]:
    response = await client.post(
        "/auth/sign-up/email",
        json={"email": email, "password": password, "include_token": True},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["token"] is not None
    assert body["refresh_token"] is not None
    return body["token"], body["refresh_token"]


async def test_sign_up_returns_refresh_token_when_enabled_and_include_token(
    client: httpx.AsyncClient,
) -> None:
    response = await client.post(
        "/auth/sign-up/email",
        json={
            "email": "owner@example.com",
            "password": "supersecret123",
            "include_token": True,
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body["refresh_token"], str)
    assert len(body["refresh_token"]) >= 32


async def test_sign_up_without_include_token_omits_refresh_token(
    client: httpx.AsyncClient,
) -> None:
    """Refresh tokens piggyback on include_token: cookie-only clients don't
    want a long-lived secret they have nowhere safe to put.
    """
    response = await client.post(
        "/auth/sign-up/email",
        json={"email": "owner@example.com", "password": "supersecret123"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["token"] is None
    assert body["refresh_token"] is None


async def test_disabled_refresh_tokens_never_issued() -> None:
    """When config.refresh_token.enabled=False, even include_token=True
    yields refresh_token=None.
    """
    config = FastAuthConfig.model_validate(
        {
            "secret_key": SecretStr("a" * 64),
            "csrf": {"enabled": False},
            "cookie": {"secure": False},
            "rate_limit": {"enabled": False},
            "refresh_token": {"enabled": False},
        },
    )
    auth = FastAuth(config, adapter=InMemoryAdapter(), email_sender=ConsoleEmailSender())
    app = FastAPI()
    app.include_router(auth.router)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as http:
        response = await http.post(
            "/auth/sign-up/email",
            json={
                "email": "a@example.com",
                "password": "secretpassword",
                "include_token": True,
            },
        )
        assert response.status_code == 200
        assert response.json()["refresh_token"] is None


async def test_refresh_returns_new_session_and_rotated_token(
    client: httpx.AsyncClient,
) -> None:
    _access, refresh = await sign_up_with_tokens(client)
    response = await client.post(
        "/auth/refresh",
        json={"refresh_token": refresh, "include_token": True},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["token"] is not None
    assert body["refresh_token"] is not None
    # The new refresh token is a different opaque string.
    assert body["refresh_token"] != refresh


async def test_refresh_unknown_token_returns_400(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/auth/refresh",
        json={"refresh_token": "not-a-real-token", "include_token": True},
    )
    assert response.status_code == 400
    assert response.json()["code"] == "TOKEN_INVALID"


async def test_refresh_token_reuse_revokes_family(
    client: httpx.AsyncClient,
    adapter: InMemoryAdapter,
) -> None:
    """Presenting an already-rotated refresh token must:
    1. Return 401 with code REFRESH_TOKEN_REUSE.
    2. Revoke every refresh token in the same family, so the new refresh
       token (issued by the legitimate rotation) is also gone.
    """
    _access, original = await sign_up_with_tokens(client)
    # First rotation succeeds and gives us a new token.
    first = await client.post(
        "/auth/refresh",
        json={"refresh_token": original, "include_token": True},
    )
    assert first.status_code == 200
    new_refresh = first.json()["refresh_token"]
    assert len(adapter.refresh_tokens) == 2  # consumed + new
    # Second attempt with the (now consumed) original token: theft detected.
    second = await client.post(
        "/auth/refresh",
        json={"refresh_token": original, "include_token": True},
    )
    assert second.status_code == 401
    assert second.json()["code"] == "REFRESH_TOKEN_REUSE"
    # Family is revoked — the legitimate rotation's new token is also gone.
    assert len(adapter.refresh_tokens) == 0
    # Using the new refresh token afterwards must fail too.
    blocked = await client.post(
        "/auth/refresh",
        json={"refresh_token": new_refresh, "include_token": True},
    )
    assert blocked.status_code == 400


async def test_refresh_expired_token_returns_400(
    client: httpx.AsyncClient,
    adapter: InMemoryAdapter,
) -> None:
    _access, refresh = await sign_up_with_tokens(client)
    # Reach into storage and back-date expires_at to a past timestamp.
    token_row = next(iter(adapter.refresh_tokens.values()))
    token_row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    response = await client.post(
        "/auth/refresh",
        json={"refresh_token": refresh, "include_token": True},
    )
    assert response.status_code == 400
    assert response.json()["code"] == "TOKEN_EXPIRED"


async def test_refresh_endpoint_disabled_returns_400() -> None:
    """When refresh tokens are disabled, the endpoint exists but always rejects."""
    config = FastAuthConfig.model_validate(
        {
            "secret_key": SecretStr("a" * 64),
            "csrf": {"enabled": False},
            "cookie": {"secure": False},
            "rate_limit": {"enabled": False},
            "refresh_token": {"enabled": False},
        },
    )
    auth = FastAuth(config, adapter=InMemoryAdapter(), email_sender=ConsoleEmailSender())
    app = FastAPI()
    app.include_router(auth.router)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as http:
        response = await http.post(
            "/auth/refresh",
            json={"refresh_token": "anything", "include_token": True},
        )
        assert response.status_code == 400
        assert response.json()["code"] == "TOKEN_INVALID"


async def test_refresh_with_absolute_max_age_revokes_chain() -> None:
    """When the chain is older than absolute_max_age_seconds, rotation is
    refused and the family is revoked so the user must sign in fresh.
    """
    config = FastAuthConfig.model_validate(
        {
            "secret_key": SecretStr("a" * 64),
            "csrf": {"enabled": False},
            "cookie": {"secure": False},
            "rate_limit": {"enabled": False},
            "refresh_token": {"enabled": True, "absolute_max_age_seconds": 1},
        },
    )
    adapter = InMemoryAdapter()
    auth = FastAuth(config, adapter=adapter, email_sender=ConsoleEmailSender())
    app = FastAPI()
    app.include_router(auth.router)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as http:
        signup = await http.post(
            "/auth/sign-up/email",
            json={
                "email": "owner@example.com",
                "password": "supersecret123",
                "include_token": True,
            },
        )
        refresh = signup.json()["refresh_token"]
        # Back-date created_at past the absolute window.
        row = next(iter(adapter.refresh_tokens.values()))
        row.created_at = datetime.now(UTC) - timedelta(seconds=120)
        response = await http.post(
            "/auth/refresh",
            json={"refresh_token": refresh, "include_token": True},
        )
        assert response.status_code == 400
        assert response.json()["code"] == "TOKEN_EXPIRED"
        # Family revoked.
        assert len(adapter.refresh_tokens) == 0


async def test_refresh_response_sets_session_cookie(client: httpx.AsyncClient) -> None:
    _access, refresh = await sign_up_with_tokens(client)
    response = await client.post(
        "/auth/refresh",
        json={"refresh_token": refresh, "include_token": True},
    )
    assert response.status_code == 200
    set_cookie = response.headers.get("set-cookie", "")
    assert "fastauth.session_token" in set_cookie
