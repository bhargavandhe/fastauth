"""Fixtures for integration tests: FastAuth factory + httpx.AsyncClient."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable

import httpx
import pytest
from fastapi import FastAPI
from pydantic import SecretStr

from fastauth.config import FastAuthConfig
from fastauth.messaging.email import ConsoleEmailSender
from fastauth.runtime.auth import FastAuth
from fastauth.storage.memory import InMemoryAdapter


def build_config() -> FastAuthConfig:
    return FastAuthConfig.model_validate(
        {
            "secret_key": SecretStr("a" * 64),
            "csrf": {"enabled": False},
            "cookie": {"secure": False},
            "rate_limit": {"enabled": False},
        },
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
        config = build_config()
        plugins = overrides.pop("plugins", [])  # type: ignore[assignment]
        return FastAuth(
            config,
            adapter=adapter,
            email_sender=email_outbox,
            plugins=list(plugins),  # type: ignore[arg-type]
            **overrides,  # type: ignore[arg-type]
        )

    return factory


@pytest.fixture
def auth(auth_factory: Callable[..., FastAuth]) -> FastAuth:
    return auth_factory()


@pytest.fixture
async def client(auth: FastAuth) -> AsyncIterator[httpx.AsyncClient]:
    app = FastAPI()
    app.include_router(auth.router)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as http:
        yield http
