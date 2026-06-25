"""Integration tests for the password reset flow."""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import httpx

from authkit.messaging.email import ConsoleEmailSender

SIGNUP = {"email": "alice@example.com", "password": "correct-horse-staple", "name": "Alice"}


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
