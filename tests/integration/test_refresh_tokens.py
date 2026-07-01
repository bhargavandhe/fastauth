"""Integration tests for refresh tokens + ``POST /auth/refresh``."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

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
    RateLimitOptions,
    RefreshTokenOptions,
)
from fastauth.providers import email_password
from fastauth.runtime.auth import FastAuth
from fastauth.storage.memory import InMemoryAdapter


def build_options(adapter: InMemoryAdapter, **refresh_overrides: object) -> FastAuthOptions:
    return FastAuthOptions(
        secret_key=SecretStr("a" * 64),
        database=custom(adapter),
        plugins=[email_password()],
        csrf=CsrfOptions(enabled=False),
        cookie=CookieOptions(secure=False),
        rate_limit=RateLimitOptions(enabled=False),
        refresh_token=RefreshTokenOptions.model_validate(
            {"enabled": True, **refresh_overrides},
        ),
    )


@pytest.fixture
def adapter() -> InMemoryAdapter:
    return InMemoryAdapter()


@pytest.fixture
def auth(adapter: InMemoryAdapter) -> FastAuth:
    return FastAuth(
        build_options(adapter),
        email_sender=ConsoleEmailSender(),
    )


@pytest.fixture
async def client(auth: FastAuth) -> AsyncIterator[httpx.AsyncClient]:
    app = FastAPI(lifespan=auth.lifespan)
    auth.mount(app)
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
        json={"email": email, "password": password, "delivery": {"kind": "bearer"}},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["credentials"]["token"] is not None
    assert body["credentials"]["refreshToken"] is not None
    return body["credentials"]["token"], body["credentials"]["refreshToken"]


async def test_sign_up_returns_refresh_token_when_bearer_delivery(
    client: httpx.AsyncClient,
) -> None:
    response = await client.post(
        "/auth/sign-up/email",
        json={
            "email": "owner@example.com",
            "password": "supersecret123",
            "delivery": {"kind": "bearer"},
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body["credentials"]["refreshToken"], str)
    assert len(body["credentials"]["refreshToken"]) >= 32


async def test_cookie_delivery_omits_response_credentials(
    client: httpx.AsyncClient,
) -> None:
    response = await client.post(
        "/auth/sign-up/email",
        json={"email": "owner@example.com", "password": "supersecret123"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["credentials"] is None


async def test_disabled_refresh_tokens_never_issued() -> None:
    """When refresh tokens are disabled, bearer delivery only returns access credentials."""
    adapter = InMemoryAdapter()
    auth = FastAuth(
        build_options(adapter, enabled=False),
        email_sender=ConsoleEmailSender(),
    )
    app = FastAPI(lifespan=auth.lifespan)
    auth.mount(app)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as http:
        response = await http.post(
            "/auth/sign-up/email",
            json={
                "email": "a@example.com",
                "password": "secretpassword",
                "delivery": {"kind": "bearer"},
            },
        )
        assert response.status_code == 200
        assert response.json()["credentials"]["refreshToken"] is None


async def test_refresh_returns_new_session_and_rotated_token(
    client: httpx.AsyncClient,
) -> None:
    _access, refresh = await sign_up_with_tokens(client)
    response = await client.post(
        "/auth/refresh",
        json={"refreshToken": refresh, "delivery": {"kind": "bearer"}},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["credentials"]["token"] is not None
    assert body["credentials"]["refreshToken"] is not None
    # The new refresh token is a different opaque string.
    assert body["credentials"]["refreshToken"] != refresh


async def test_refresh_unknown_token_returns_400(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/auth/refresh",
        json={"refreshToken": "not-a-real-token", "delivery": {"kind": "bearer"}},
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
        json={"refreshToken": original, "delivery": {"kind": "bearer"}},
    )
    assert first.status_code == 200
    new_refresh = first.json()["credentials"]["refreshToken"]
    assert len(adapter.refresh_tokens) == 2  # consumed + new
    # Second attempt with the (now consumed) original token: theft detected.
    second = await client.post(
        "/auth/refresh",
        json={"refreshToken": original, "delivery": {"kind": "bearer"}},
    )
    assert second.status_code == 401
    assert second.json()["code"] == "REFRESH_TOKEN_REUSE"
    # Family is revoked — the legitimate rotation's new token is also gone.
    assert len(adapter.refresh_tokens) == 0
    # Using the new refresh token afterwards must fail too.
    blocked = await client.post(
        "/auth/refresh",
        json={"refreshToken": new_refresh, "delivery": {"kind": "bearer"}},
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
        json={"refreshToken": refresh, "delivery": {"kind": "bearer"}},
    )
    assert response.status_code == 400
    assert response.json()["code"] == "TOKEN_EXPIRED"


async def test_refresh_endpoint_disabled_returns_400() -> None:
    """When refresh tokens are disabled, the endpoint exists but always rejects."""
    adapter = InMemoryAdapter()
    auth = FastAuth(
        build_options(adapter, enabled=False),
        email_sender=ConsoleEmailSender(),
    )
    app = FastAPI(lifespan=auth.lifespan)
    auth.mount(app)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as http:
        response = await http.post(
            "/auth/refresh",
            json={"refreshToken": "anything", "delivery": {"kind": "bearer"}},
        )
        assert response.status_code == 400
        assert response.json()["code"] == "TOKEN_INVALID"


async def test_refresh_with_absolute_max_age_revokes_chain() -> None:
    """When the chain is older than absolute_max_age, rotation is
    refused and the family is revoked so the user must sign in fresh.
    """
    adapter = InMemoryAdapter()
    auth = FastAuth(
        build_options(adapter, absolute_max_age=timedelta(seconds=1)),
        email_sender=ConsoleEmailSender(),
    )
    app = FastAPI(lifespan=auth.lifespan)
    auth.mount(app)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as http:
        signup = await http.post(
            "/auth/sign-up/email",
            json={
                "email": "owner@example.com",
                "password": "supersecret123",
                "delivery": {"kind": "bearer"},
            },
        )
        refresh = signup.json()["credentials"]["refreshToken"]
        # Back-date created_at past the absolute window.
        row = next(iter(adapter.refresh_tokens.values()))
        row.created_at = datetime.now(UTC) - timedelta(seconds=120)
        response = await http.post(
            "/auth/refresh",
            json={"refreshToken": refresh, "delivery": {"kind": "bearer"}},
        )
        assert response.status_code == 400
        assert response.json()["code"] == "TOKEN_EXPIRED"
        # Family revoked.
        assert len(adapter.refresh_tokens) == 0


async def test_cookie_refresh_response_sets_session_cookie(client: httpx.AsyncClient) -> None:
    _access, refresh = await sign_up_with_tokens(client)
    response = await client.post(
        "/auth/refresh",
        json={"refreshToken": refresh, "delivery": {"kind": "cookie"}},
    )
    assert response.status_code == 200
    set_cookie = response.headers.get("set-cookie", "")
    assert "fastauth.session_token" in set_cookie
