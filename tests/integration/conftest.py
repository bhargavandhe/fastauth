"""Fixtures for integration tests: FastAuth factory + httpx.AsyncClient."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from typing import cast

import httpx
import pytest
from fastapi import FastAPI
from pydantic import SecretStr

from fastauth.database import custom
from fastauth.messaging.email import ConsoleEmailSender
from fastauth.options import CookieOptions, CsrfOptions, FastAuthOptions, RateLimitOptions
from fastauth.plugins.base import Plugin
from fastauth.providers import email_password
from fastauth.runtime.auth import FastAuth
from fastauth.storage.memory import InMemoryAdapter


def build_options(adapter: InMemoryAdapter, plugins: list[Plugin] | None = None) -> FastAuthOptions:
    return FastAuthOptions(
        secret_key=SecretStr("a" * 64),
        database=custom(adapter),
        plugins=[email_password(), *(plugins or [])],
        csrf=CsrfOptions(enabled=False),
        cookie=CookieOptions(secure=False),
        rate_limit=RateLimitOptions(enabled=False),
    )


@pytest.fixture
def email_outbox() -> ConsoleEmailSender:
    return ConsoleEmailSender()


@pytest.fixture
def adapter() -> InMemoryAdapter:
    return InMemoryAdapter()


@pytest.fixture
def auth_factory(
    adapter: InMemoryAdapter,
    email_outbox: ConsoleEmailSender,
) -> Callable[..., FastAuth]:
    def factory(**overrides: object) -> FastAuth:
        plugins = cast(list[Plugin], overrides.pop("plugins", []))
        options = build_options(adapter, plugins)
        return FastAuth(
            options,
            email_sender=email_outbox,
            **overrides,  # type: ignore[arg-type]
        )

    return factory


@pytest.fixture
def auth(auth_factory: Callable[..., FastAuth]) -> FastAuth:
    return auth_factory()


@pytest.fixture
async def client(auth: FastAuth) -> AsyncIterator[httpx.AsyncClient]:
    app = FastAPI(lifespan=auth.lifespan)
    auth.mount(app)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as http:
        yield http
