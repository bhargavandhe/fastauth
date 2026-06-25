"""Fixtures for integration tests: AuthKit factory + httpx.AsyncClient."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable

import httpx
import pytest
from fastapi import FastAPI
from pydantic import SecretStr

from authkit.config import AuthKitConfig
from authkit.messaging.email import ConsoleEmailSender
from authkit.runtime.auth import AuthKit
from authkit.storage.memory import InMemoryAdapter


def build_config() -> AuthKitConfig:
    return AuthKitConfig.model_validate(
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
) -> Callable[..., AuthKit]:
    def factory(**overrides: object) -> AuthKit:
        config = build_config()
        plugins = overrides.pop("plugins", [])  # type: ignore[assignment]
        return AuthKit(
            config,
            adapter=adapter,
            email_sender=email_outbox,
            plugins=list(plugins),  # type: ignore[arg-type]
            **overrides,  # type: ignore[arg-type]
        )

    return factory


@pytest.fixture
def auth(auth_factory: Callable[..., AuthKit]) -> AuthKit:
    return auth_factory()


@pytest.fixture
async def client(auth: AuthKit) -> AsyncIterator[httpx.AsyncClient]:
    app = FastAPI()
    app.include_router(auth.router)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as http:
        yield http
