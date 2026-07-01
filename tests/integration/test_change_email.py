"""Integration tests for the change-email-with-reverification flow."""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import httpx

from fastauth.messaging.email import ConsoleEmailSender
from fastauth.storage.memory import InMemoryAdapter

SIGNUP = {"email": "alice@example.com", "password": "correct-horse-staple", "name": "Alice"}


def extract_change_email_token(message_text: str) -> tuple[str, str]:
    """Pull (token, new_email) out of the captured email body."""
    url = next(
        urlparse(line.strip())
        for line in message_text.splitlines()
        if line.strip().startswith("http")
    )
    qs = parse_qs(url.query)
    return qs["token"][0], qs["new_email"][0]


async def test_change_email_round_trip(
    client: httpx.AsyncClient,
    email_outbox: ConsoleEmailSender,
    adapter: InMemoryAdapter,
) -> None:
    sign_up = await client.post("/auth/sign-up/email", json=SIGNUP)
    assert sign_up.status_code == 200
    user_id = sign_up.json()["user"]["id"]

    req = await client.post(
        "/auth/change-email/request",
        json={"new_email": "alice2@example.com", "password": SIGNUP["password"]},
    )
    assert req.status_code == 200

    # Email is sent to the NEW address.
    assert len(email_outbox.outbox) == 1
    assert email_outbox.outbox[0].to == "alice2@example.com"
    token, new_email = extract_change_email_token(email_outbox.outbox[0].text)
    assert new_email == "alice2@example.com"

    # Until confirmed, get-session still shows the OLD email. The pending
    # change is internal state and must not be exposed in the public DTO.
    me = await client.get("/auth/get-session")
    assert me.status_code == 200
    body = me.json()
    assert body["user"]["email"] == "alice@example.com"
    assert "pendingEmailChange" not in body["user"]
    pending = await adapter.get_user_by_id(user_id)
    assert pending is not None
    assert pending.pending_email_change == "alice2@example.com"

    # Confirm.
    confirm = await client.post(
        "/auth/change-email/confirm",
        json={"new_email": "alice2@example.com", "token": token},
    )
    assert confirm.status_code == 200

    # Now get-session reflects the new email, pending cleared, verified=True.
    me_after = (await client.get("/auth/get-session")).json()
    assert me_after["user"]["email"] == "alice2@example.com"
    assert "pendingEmailChange" not in me_after["user"]
    assert me_after["user"]["emailVerified"] is True

    # The current session stayed alive (no extra revocation).
    persisted = await adapter.get_user_by_id(user_id)
    assert persisted is not None
    assert persisted.email == "alice2@example.com"


async def test_change_email_requires_password(
    client: httpx.AsyncClient,
) -> None:
    await client.post("/auth/sign-up/email", json=SIGNUP)
    response = await client.post(
        "/auth/change-email/request",
        json={"new_email": "alice2@example.com", "password": "wrong"},
    )
    assert response.status_code == 401
    assert response.json()["code"] == "INVALID_CREDENTIALS"


async def test_change_email_rejects_already_taken_address(
    client: httpx.AsyncClient,
) -> None:
    await client.post("/auth/sign-up/email", json=SIGNUP)
    # Sign up a second user to occupy the target email.
    client.cookies.clear()
    await client.post(
        "/auth/sign-up/email",
        json={"email": "taken@example.com", "password": "correct-horse-staple"},
    )
    # Sign back in as Alice.
    client.cookies.clear()
    await client.post(
        "/auth/sign-in/email",
        json={"email": SIGNUP["email"], "password": SIGNUP["password"]},
    )
    response = await client.post(
        "/auth/change-email/request",
        json={"new_email": "taken@example.com", "password": SIGNUP["password"]},
    )
    assert response.status_code == 409
    assert response.json()["code"] == "DUPLICATE"


async def test_change_email_idempotent_when_already_on_target(
    client: httpx.AsyncClient,
    email_outbox: ConsoleEmailSender,
) -> None:
    """Requesting a change to your own current email succeeds silently (no
    email sent, no pending state). Avoids leaking that the address is yours."""
    await client.post("/auth/sign-up/email", json=SIGNUP)
    response = await client.post(
        "/auth/change-email/request",
        json={"new_email": SIGNUP["email"], "password": SIGNUP["password"]},
    )
    assert response.status_code == 200
    assert email_outbox.outbox == []


async def test_change_email_confirm_rejects_invalid_token(
    client: httpx.AsyncClient,
) -> None:
    await client.post("/auth/sign-up/email", json=SIGNUP)
    response = await client.post(
        "/auth/change-email/confirm",
        json={"new_email": "anything@example.com", "token": "garbage"},
    )
    assert response.status_code == 400
    assert response.json()["code"] in {"TOKEN_INVALID", "TOKEN_EXPIRED"}


async def test_change_email_request_requires_auth(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/auth/change-email/request",
        json={"new_email": "x@example.com", "password": "y"},
    )
    assert response.status_code == 401
