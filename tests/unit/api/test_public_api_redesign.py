from __future__ import annotations

import inspect

import httpx
import pytest
from fastapi import FastAPI
from pydantic import SecretStr, ValidationError

from fastauth import FastAuth, FastAuthOptions
from fastauth.database import memory
from fastauth.messaging.email import EmailMessage
from fastauth.options import CookieOptions, CsrfOptions, RateLimitOptions
from fastauth.providers import email_password, openapi


class FakeEmailSender:
    def __init__(self) -> None:
        self.message: EmailMessage | None = None

    async def send(self, message: EmailMessage) -> None:
        self.message = message


def test_fastauth_class_builds_auth_from_pydantic_options() -> None:
    auth = FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("a" * 64),
            database=memory(),
        ),
        plugins=[email_password()],
    )

    assert auth.options.database.kind == "memory"
    assert auth.router.prefix == "/auth"


def test_fastauth_factory_accepts_dependency_overrides() -> None:
    sender = FakeEmailSender()

    auth = FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("a" * 64),
            database=memory(),
        ),
        plugins=[email_password()],
        email_sender=sender,
    )

    assert auth.context.email_sender is sender


def test_options_reject_old_adapter_style() -> None:
    with pytest.raises(ValidationError):
        FastAuthOptions.model_validate(
            {
                "secret_key": "a" * 64,
                "adapter": object(),
                "database": {"kind": "memory"},
                "plugins": [{"id": "email-password"}],
            },
        )


async def test_mount_installs_email_password_plugin_routes() -> None:
    auth = FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("b" * 64),
            database=memory(),
            cookie=CookieOptions(secure=False),
            csrf=CsrfOptions(enabled=False),
            rate_limit=RateLimitOptions(enabled=False),
        ),
        plugins=[email_password()],
    )
    app = FastAPI(lifespan=auth.lifespan)
    auth.mount(app)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        response = await client.post(
            "/auth/sign-up/email",
            json={"email": "alice@example.com", "password": "correct-horse-battery"},
        )

    assert response.status_code == 200, response.text
    assert response.json()["user"]["email"] == "alice@example.com"


async def test_email_password_routes_are_not_core_routes() -> None:
    auth = FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("c" * 64),
            database=memory(),
            cookie=CookieOptions(secure=False),
            csrf=CsrfOptions(enabled=False),
            rate_limit=RateLimitOptions(enabled=False),
        ),
    )
    app = FastAPI(lifespan=auth.lifespan)
    auth.mount(app)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        response = await client.post(
            "/auth/sign-up/email",
            json={"email": "alice@example.com", "password": "correct-horse-battery"},
        )

    assert response.status_code == 404


def test_public_plugins_are_factories_with_pydantic_options() -> None:
    plugin = openapi()

    assert plugin.id == "fastauth-openapi"
    assert hasattr(plugin.options, "model_dump")
    assert not hasattr(plugin, "config")


def test_old_config_names_are_not_exported() -> None:
    import fastauth

    assert not hasattr(fastauth, "FastAuthConfig")
    assert hasattr(fastauth, "FastAuth")


def test_auth_api_public_methods_do_not_expose_transport_kwargs_or_tuple_results() -> None:
    auth = FastAuth(
        FastAuthOptions(secret_key=SecretStr("d" * 64), database=memory()),
        plugins=[email_password()],
    )

    for name, member in inspect.getmembers(auth.api, predicate=inspect.ismethod):
        if name.startswith("_"):
            continue
        assert not name.startswith("internal_")
        signature = inspect.signature(member)
        assert "ip" not in signature.parameters
        assert "user_agent" not in signature.parameters
        assert "tuple[" not in str(signature.return_annotation)
