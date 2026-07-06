"""Integration tests for the email verification flow."""

from __future__ import annotations

from collections.abc import AsyncIterator
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from pydantic import SecretStr

from fastauth.database import custom
from fastauth.messaging.email import ConsoleEmailSender
from fastauth.options import (
    CookieOptions,
    CsrfOptions,
    EmailVerificationOptions,
    FastAuthOptions,
    RateLimitOptions,
)
from fastauth.providers import email_password
from fastauth.runtime.auth import FastAuth
from fastauth.storage.memory import InMemoryAdapter

SIGNUP = {"email": "alice@example.com", "password": "correct-horse-staple", "name": "Alice"}


async def test_signup_then_send_then_verify(
    client: httpx.AsyncClient,
    email_outbox: ConsoleEmailSender,
) -> None:
    sign_up = await client.post("/auth/sign-up/email", json=SIGNUP)
    assert sign_up.status_code == 200
    assert sign_up.json()["user"]["emailVerified"] is False

    sent = await client.post(
        "/auth/send-verification-email",
        json={"email": SIGNUP["email"]},
    )
    assert sent.status_code == 200
    assert len(email_outbox.outbox) == 1
    message = email_outbox.outbox[0]
    assert message.to == SIGNUP["email"]

    # Extract the token from the verify URL inside the text body.
    parsed = next(
        urlparse(line.strip())
        for line in message.text.splitlines()
        if line.strip().startswith("http")
    )
    token = parse_qs(parsed.query)["token"][0]

    verified = await client.post(
        "/auth/verify-email",
        json={"email": SIGNUP["email"], "token": token},
    )
    assert verified.status_code == 200
    assert verified.json()["user"]["emailVerified"] is True


async def test_send_and_verify_accept_mixed_case_email(
    client: httpx.AsyncClient,
    email_outbox: ConsoleEmailSender,
) -> None:
    await client.post("/auth/sign-up/email", json=SIGNUP)
    sent = await client.post(
        "/auth/send-verification-email",
        json={"email": "Alice@Example.COM"},
    )
    assert sent.status_code == 200
    assert len(email_outbox.outbox) == 1
    parsed = next(
        urlparse(line.strip())
        for line in email_outbox.outbox[0].text.splitlines()
        if line.strip().startswith("http")
    )
    token = parse_qs(parsed.query)["token"][0]

    verified = await client.post(
        "/auth/verify-email",
        json={"email": "Alice@Example.COM", "token": token},
    )
    assert verified.status_code == 200
    assert verified.json()["user"]["emailVerified"] is True


async def test_verification_email_includes_redirect_url(
    client: httpx.AsyncClient,
    email_outbox: ConsoleEmailSender,
) -> None:
    await client.post("/auth/sign-up/email", json=SIGNUP)
    response = await client.post(
        "/auth/send-verification-email",
        json={
            "email": SIGNUP["email"],
            "redirect_url": "https://app.example.com/welcome",
        },
    )
    assert response.status_code == 200
    parsed = next(
        urlparse(line.strip())
        for line in email_outbox.outbox[0].text.splitlines()
        if line.strip().startswith("http")
    )
    assert parse_qs(parsed.query)["redirect_url"] == ["https://app.example.com/welcome"]


async def test_verify_email_rejects_invalid_token(client: httpx.AsyncClient) -> None:
    await client.post("/auth/sign-up/email", json=SIGNUP)
    response = await client.post(
        "/auth/verify-email",
        json={"email": SIGNUP["email"], "token": "garbage"},
    )
    assert response.status_code == 400
    assert response.json()["code"] in {"TOKEN_INVALID", "TOKEN_EXPIRED"}


@pytest.fixture
def require_verified_auth(
    adapter: InMemoryAdapter,
    email_outbox: ConsoleEmailSender,
) -> FastAuth:
    return FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("a" * 64),
            database=custom(adapter),
            csrf=CsrfOptions(enabled=False),
            cookie=CookieOptions(secure=False),
            rate_limit=RateLimitOptions(enabled=False),
            email_verification=EmailVerificationOptions(require_verified_for_sign_in=True),
        ),
        plugins=[email_password()],
        email_sender=email_outbox,
    )


@pytest.fixture
async def require_verified_client(
    require_verified_auth: FastAuth,
) -> AsyncIterator[httpx.AsyncClient]:
    from fastapi import FastAPI

    app = FastAPI(lifespan=require_verified_auth.lifespan)
    require_verified_auth.mount(app)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as http:
        yield http


async def test_require_verified_for_sign_in_blocks_unverified_email(
    require_verified_client: httpx.AsyncClient,
    email_outbox: ConsoleEmailSender,
) -> None:
    await require_verified_client.post("/auth/sign-up/email", json=SIGNUP)
    require_verified_client.cookies.clear()

    blocked = await require_verified_client.post(
        "/auth/sign-in/email",
        json={"email": SIGNUP["email"], "password": SIGNUP["password"]},
    )
    assert blocked.status_code == 403
    assert blocked.json()["code"] == "EMAIL_NOT_VERIFIED"

    await require_verified_client.post(
        "/auth/send-verification-email",
        json={"email": SIGNUP["email"]},
    )
    parsed = next(
        urlparse(line.strip())
        for line in email_outbox.outbox[0].text.splitlines()
        if line.strip().startswith("http")
    )
    token = parse_qs(parsed.query)["token"][0]
    verified = await require_verified_client.post(
        "/auth/verify-email",
        json={"email": SIGNUP["email"], "token": token},
    )
    assert verified.status_code == 200
    require_verified_client.cookies.clear()

    allowed = await require_verified_client.post(
        "/auth/sign-in/email",
        json={"email": SIGNUP["email"], "password": SIGNUP["password"]},
    )
    assert allowed.status_code == 200
