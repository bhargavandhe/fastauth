"""Integration tests for the password reset flow."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlparse

import httpx
from fastapi import FastAPI
from pydantic import SecretStr

from fastauth import email_password
from fastauth.database import custom
from fastauth.domain.enums import VerificationPurpose
from fastauth.domain.events import PasswordResetRequested
from fastauth.messaging.email import ConsoleEmailSender
from fastauth.options import (
    CookieOptions,
    CsrfOptions,
    FastAuthOptions,
    PasswordResetOptions,
    RateLimitOptions,
)
from fastauth.runtime.auth import FastAuth
from fastauth.storage.memory import InMemoryAdapter

SIGNUP = {"email": "alice@example.com", "password": "correct-horse-staple", "name": "Alice"}


def extract_reset_token(email_outbox: ConsoleEmailSender) -> str:
    message = email_outbox.outbox[-1]
    parsed = next(
        urlparse(line.strip())
        for line in message.text.splitlines()
        if line.strip().startswith("http")
    )
    return parse_qs(parsed.query)["token"][0]


async def test_full_reset_round_trip(
    client: httpx.AsyncClient,
    email_outbox: ConsoleEmailSender,
) -> None:
    await client.post("/auth/sign-up/email", json=SIGNUP)
    client.cookies.clear()

    forgot = await client.post("/auth/forgot-password", json={"email": SIGNUP["email"]})
    assert forgot.status_code == 200
    assert len(email_outbox.outbox) == 1
    message = email_outbox.outbox[0]
    parsed = next(
        urlparse(line.strip())
        for line in message.text.splitlines()
        if line.strip().startswith("http")
    )
    token = parse_qs(parsed.query)["token"][0]

    reset = await client.post(
        "/auth/reset-password",
        json={
            "email": SIGNUP["email"],
            "token": token,
            "new_password": "new-secret-12345",
        },
    )
    assert reset.status_code == 200
    assert reset.json()["success"] is True

    # Old password no longer works
    response = await client.post(
        "/auth/sign-in/email",
        json={"email": SIGNUP["email"], "password": SIGNUP["password"]},
    )
    assert response.status_code == 401
    # New password works
    response = await client.post(
        "/auth/sign-in/email",
        json={"email": SIGNUP["email"], "password": "new-secret-12345"},
    )
    assert response.status_code == 200


async def test_forgot_password_publishes_request_event_for_unknown_email(
    auth: FastAuth,
    client: httpx.AsyncClient,
) -> None:
    events: list[PasswordResetRequested] = []

    async def capture(event: PasswordResetRequested) -> None:
        events.append(event)

    auth.context.event_bus.subscribe(PasswordResetRequested, capture)

    response = await client.post(
        "/auth/forgot-password",
        json={"email": "missing@example.com"},
    )

    assert response.status_code == 200
    assert [event.identifier for event in events] == ["missing@example.com"]


async def test_forgot_password_includes_redirect_url(
    client: httpx.AsyncClient,
    email_outbox: ConsoleEmailSender,
) -> None:
    await client.post("/auth/sign-up/email", json=SIGNUP)
    response = await client.post(
        "/auth/forgot-password",
        json={
            "email": SIGNUP["email"],
            "redirect_url": "https://app.example.com/password-reset-complete",
        },
    )
    assert response.status_code == 200
    parsed = next(
        urlparse(line.strip())
        for line in email_outbox.outbox[0].text.splitlines()
        if line.strip().startswith("http")
    )
    assert parse_qs(parsed.query)["redirect_url"] == [
        "https://app.example.com/password-reset-complete"
    ]


async def test_reset_revokes_existing_refresh_tokens(
    client: httpx.AsyncClient,
    email_outbox: ConsoleEmailSender,
) -> None:
    sign_up = await client.post(
        "/auth/sign-up/email",
        json={**SIGNUP, "delivery": {"kind": "bearer"}},
    )
    assert sign_up.status_code == 200
    refresh_token = sign_up.json()["credentials"]["refreshToken"]

    forgot = await client.post("/auth/forgot-password", json={"email": SIGNUP["email"]})
    assert forgot.status_code == 200
    token = extract_reset_token(email_outbox)
    reset = await client.post(
        "/auth/reset-password",
        json={
            "email": SIGNUP["email"],
            "token": token,
            "new_password": "new-secret-12345",
        },
    )
    assert reset.status_code == 200

    refresh = await client.post(
        "/auth/refresh",
        json={"refreshToken": refresh_token, "delivery": {"kind": "bearer"}},
    )
    assert refresh.status_code == 400
    assert refresh.json()["code"] == "TOKEN_INVALID"


async def test_global_password_reset_ttl_option_controls_expiry() -> None:
    adapter = InMemoryAdapter()
    email_outbox = ConsoleEmailSender()
    auth = FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("a" * 64),
            database=custom(adapter),
            csrf=CsrfOptions(enabled=False),
            cookie=CookieOptions(secure=False),
            rate_limit=RateLimitOptions(enabled=False),
            password_reset=PasswordResetOptions(expires_in=timedelta(minutes=7)),
        ),
        plugins=[email_password()],
        email_sender=email_outbox,
    )
    app = FastAPI(lifespan=auth.lifespan)
    auth.mount(app)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as custom_client:
        await custom_client.post("/auth/sign-up/email", json=SIGNUP)
        before = datetime.now(UTC)
        response = await custom_client.post(
            "/auth/forgot-password",
            json={"email": SIGNUP["email"]},
        )
        after = datetime.now(UTC)

    assert response.status_code == 200
    verification = await adapter.get_active_verification(
        SIGNUP["email"],
        VerificationPurpose.PASSWORD_RESET,
    )
    assert verification is not None
    assert before + timedelta(minutes=7) <= verification.expires_at <= after + timedelta(minutes=7)


async def test_forgot_password_returns_success_for_unknown_email(
    client: httpx.AsyncClient,
    email_outbox: ConsoleEmailSender,
) -> None:
    response = await client.post(
        "/auth/forgot-password",
        json={"email": "ghost@example.com"},
    )
    assert response.status_code == 200
    assert email_outbox.outbox == []


async def test_reset_revokes_all_existing_sessions(
    client: httpx.AsyncClient,
    email_outbox: ConsoleEmailSender,
) -> None:
    # Create user and an active session
    sign_up = await client.post("/auth/sign-up/email", json=SIGNUP)
    assert sign_up.status_code == 200
    # Active session works
    assert (await client.get("/auth/get-session")).status_code == 200

    forgot = await client.post("/auth/forgot-password", json={"email": SIGNUP["email"]})
    assert forgot.status_code == 200
    token = parse_qs(
        urlparse(
            next(
                line.strip()
                for line in email_outbox.outbox[0].text.splitlines()
                if line.strip().startswith("http")
            ),
        ).query,
    )["token"][0]
    await client.post(
        "/auth/reset-password",
        json={
            "email": SIGNUP["email"],
            "token": token,
            "new_password": "new-secret-12345",
        },
    )
    # Previous session is now invalidated
    assert (await client.get("/auth/get-session")).status_code == 204


async def test_reset_clears_lockout_for_email_and_username(
    client: httpx.AsyncClient,
    email_outbox: ConsoleEmailSender,
) -> None:
    payload = {
        "email": "alice@example.com",
        "username": "alice",
        "password": "correct-horse-staple",
    }
    await client.post("/auth/sign-up/email", json=payload)
    client.cookies.clear()

    email_attempt: httpx.Response | None = None
    username_attempt: httpx.Response | None = None
    for _ in range(6):
        email_attempt = await client.post(
            "/auth/sign-in/email",
            json={"email": payload["email"], "password": "wrong-password"},
        )
        username_attempt = await client.post(
            "/auth/sign-in/username",
            json={"username": payload["username"], "password": "wrong-password"},
        )
    assert email_attempt is not None
    assert username_attempt is not None
    assert email_attempt.status_code == 423
    assert username_attempt.status_code == 423

    forgot = await client.post("/auth/forgot-password", json={"email": payload["email"]})
    assert forgot.status_code == 200
    token = extract_reset_token(email_outbox)

    reset = await client.post(
        "/auth/reset-password",
        json={
            "email": payload["email"],
            "token": token,
            "new_password": "new-secret-12345",
        },
    )
    assert reset.status_code == 200

    email_sign_in = await client.post(
        "/auth/sign-in/email",
        json={"email": payload["email"], "password": "new-secret-12345"},
    )
    assert email_sign_in.status_code == 200

    client.cookies.clear()
    username_sign_in = await client.post(
        "/auth/sign-in/username",
        json={"username": payload["username"], "password": "new-secret-12345"},
    )
    assert username_sign_in.status_code == 200
