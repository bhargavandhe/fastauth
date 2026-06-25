"""Integration tests for the email verification flow."""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import httpx

from authkit.messaging.email import ConsoleEmailSender

SIGNUP = {"email": "alice@example.com", "password": "correct-horse-staple", "name": "Alice"}


async def test_signup_then_send_then_verify(
    client: httpx.AsyncClient,
    email_outbox: ConsoleEmailSender,
) -> None:
    sign_up = await client.post("/auth/sign-up/email", json=SIGNUP)
    assert sign_up.status_code == 200
    assert sign_up.json()["user"]["email_verified"] is False

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
    assert verified.json()["user"]["email_verified"] is True


async def test_verify_email_rejects_invalid_token(client: httpx.AsyncClient) -> None:
    await client.post("/auth/sign-up/email", json=SIGNUP)
    response = await client.post(
        "/auth/verify-email",
        json={"email": SIGNUP["email"], "token": "garbage"},
    )
    assert response.status_code == 400
    assert response.json()["code"] in {"TOKEN_INVALID", "TOKEN_EXPIRED"}
