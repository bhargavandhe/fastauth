from __future__ import annotations

from collections.abc import AsyncIterator
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI
from pydantic import SecretStr

from fastauth import email_password
from fastauth.database import custom
from fastauth.messaging.email import ConsoleEmailSender
from fastauth.options import (
    AppOptions,
    CookieOptions,
    CsrfOptions,
    FastAuthOptions,
    RateLimitOptions,
)
from fastauth.runtime.auth import FastAuth
from fastauth.storage.memory import InMemoryAdapter

SIGNUP = {"email": "alice@example.com", "password": "correct-horse-staple"}


def first_url(message_text: str) -> str:
    return next(line.strip() for line in message_text.splitlines() if line.startswith("http"))


async def configured_client(
    email_outbox: ConsoleEmailSender,
) -> AsyncIterator[httpx.AsyncClient]:
    auth = FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("a" * 64),
            app=AppOptions.model_validate({"base_url": "https://api.example.com"}),
            database=custom(InMemoryAdapter()),
            csrf=CsrfOptions(enabled=False),
            cookie=CookieOptions(secure=False),
            rate_limit=RateLimitOptions(enabled=False),
        ),
        plugins=[email_password()],
        email_sender=email_outbox,
    )
    app = FastAPI(lifespan=auth.lifespan)
    auth.mount(app)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        yield client


async def test_email_callbacks_derive_from_app_base_url_by_default(
    email_outbox: ConsoleEmailSender,
) -> None:
    async for client in configured_client(email_outbox):
        await client.post("/auth/sign-up/email", json=SIGNUP)
        await client.post("/auth/send-verification-email", json={"email": SIGNUP["email"]})
        await client.post("/auth/forgot-password", json={"email": SIGNUP["email"]})
        await client.post(
            "/auth/change-email/request",
            json={"new_email": "alice2@example.com", "password": SIGNUP["password"]},
        )
        await client.post("/auth/delete-account/request")

    urls = [urlparse(first_url(message.text)) for message in email_outbox.outbox]
    assert [(url.scheme, url.netloc, url.path) for url in urls] == [
        ("https", "api.example.com", "/auth/verify-email"),
        ("https", "api.example.com", "/auth/reset-password"),
        ("https", "api.example.com", "/auth/change-email/confirm"),
        ("https", "api.example.com", "/auth/delete-account/confirm"),
    ]
