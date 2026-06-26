"""Integration tests for ``FastAuthConfig.wire_format``.

Two scenarios:

* ``WireFormat.SNAKE`` (default) — output JSON keys remain snake_case.
* ``WireFormat.CAMEL`` — every key in the response (including embedded
  domain models like ``user`` and ``session``) is emitted as camelCase.

Both modes accept either casing on input, thanks to
``populate_by_name=True`` + ``alias_generator=to_camel`` on
:class:`fastauth.domain.models.WireModel`.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
from fastapi import FastAPI
from pydantic import SecretStr

from fastauth.config import FastAuthConfig
from fastauth.domain.enums import WireFormat
from fastauth.messaging.email import ConsoleEmailSender
from fastauth.runtime.auth import FastAuth
from fastauth.storage.memory import InMemoryAdapter


def make_config(wire_format: WireFormat) -> FastAuthConfig:
    return FastAuthConfig.model_validate(
        {
            "secret_key": SecretStr("a" * 64),
            "csrf": {"enabled": False},
            "cookie": {"secure": False},
            "rate_limit": {"enabled": False},
            "wire_format": wire_format,
        },
    )


async def build_client(wire_format: WireFormat) -> AsyncIterator[httpx.AsyncClient]:
    auth = FastAuth(
        make_config(wire_format),
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


@pytest.fixture
async def snake_client() -> AsyncIterator[httpx.AsyncClient]:
    async for c in build_client(WireFormat.SNAKE):
        yield c


@pytest.fixture
async def camel_client() -> AsyncIterator[httpx.AsyncClient]:
    async for c in build_client(WireFormat.CAMEL):
        yield c


async def test_snake_wire_format_emits_snake_case_keys(
    snake_client: httpx.AsyncClient,
) -> None:
    """SNAKE mode (default) emits snake_case throughout the response tree."""
    response = await snake_client.post(
        "/auth/sign-up/email",
        json={
            "email": "alice@example.com",
            "password": "supersecret123",
            "include_token": True,
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    # Top-level fields.
    assert "user" in body
    assert "session" in body
    assert "refresh_token" in body
    assert "refreshToken" not in body
    # Nested User.
    user = body["user"]
    assert "email_verified" in user
    assert "emailVerified" not in user
    assert "created_at" in user
    assert "createdAt" not in user
    # Nested Session.
    session = body["session"]
    assert "user_id" in session
    assert "userId" not in session
    assert "expires_at" in session
    assert "expiresAt" not in session


async def test_camel_wire_format_emits_camel_case_keys(
    camel_client: httpx.AsyncClient,
) -> None:
    """CAMEL mode emits camelCase recursively, including for embedded models.

    Note that snake_case input is still accepted (we send ``include_token``
    as snake_case here), demonstrating the ``populate_by_name`` behaviour.
    Output shape is camelCase regardless.
    """
    response = await camel_client.post(
        "/auth/sign-up/email",
        json={
            "email": "alice@example.com",
            "password": "supersecret123",
            "include_token": True,
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    # Top-level fields are camelCased.
    assert "refreshToken" in body
    assert "refresh_token" not in body
    # Nested User fields.
    user = body["user"]
    assert "emailVerified" in user
    assert "email_verified" not in user
    assert "createdAt" in user
    assert "created_at" not in user
    # Nested Session fields.
    session = body["session"]
    assert "userId" in session
    assert "user_id" not in session
    assert "expiresAt" in session
    assert "expires_at" not in session
    # Token field has no underscore so transformation is identity.
    assert "token" in body


async def test_camel_wire_format_accepts_camel_case_input(
    camel_client: httpx.AsyncClient,
) -> None:
    """The request body itself can be camelCase too (alias generator on WireModel)."""
    response = await camel_client.post(
        "/auth/sign-up/email",
        json={
            "email": "alice@example.com",
            "password": "supersecret123",
            "includeToken": True,  # camelCase request key
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    # Token was issued because includeToken was honoured.
    assert body["token"] is not None


async def test_snake_wire_format_also_accepts_camel_case_input(
    snake_client: httpx.AsyncClient,
) -> None:
    """SNAKE mode still accepts camelCase request bodies — the input alias
    is universal; only the output casing differs.
    """
    response = await snake_client.post(
        "/auth/sign-up/email",
        json={
            "email": "alice@example.com",
            "password": "supersecret123",
            "includeToken": True,  # camelCase request key
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["token"] is not None
    # But output is still snake_case.
    assert "refresh_token" in body
