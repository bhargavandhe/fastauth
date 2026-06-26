"""End-to-end test exercising every fastauth v1 surface against a live Mongo."""

from __future__ import annotations

import httpx


async def test_full_journey(client: httpx.AsyncClient) -> None:
    # Sign up — creates user and sets the session cookie.
    response = await client.post(
        "/auth/sign-up/email",
        json={"email": "alice@example.com", "password": "correct-horse-staple"},
    )
    assert response.status_code == 200, response.text

    # Get session — verifies the cookie is being honoured.
    response = await client.get("/auth/get-session")
    assert response.status_code == 200, response.text

    # Create an API key while authenticated.
    response = await client.post("/auth/api-key/create", json={"name": "ci"})
    assert response.status_code == 200, response.text
    api_key = response.json()["key"]

    # Verify the API key round-trips.
    response = await client.post("/auth/api-key/verify", json={"key": api_key})
    assert response.status_code == 200, response.text
    assert response.json()["valid"] is True

    # Issue a JWT for the current session.
    response = await client.post("/auth/token")
    assert response.status_code == 200, response.text
    token = response.json()["token"]
    assert token.count(".") == 2

    # JWKS document is publicly served.
    response = await client.get("/auth/jwks")
    assert response.status_code == 200, response.text
    assert "keys" in response.json()

    # Audit logs include the sign-up event.
    response = await client.get("/auth/audit-logs")
    assert response.status_code == 200, response.text
    event_types = {row["event_type"] for row in response.json()["events"]}
    assert "user_signed_up" in event_types

    # Scalar reference page is served at /auth/reference.
    response = await client.get("/auth/reference")
    assert response.status_code == 200, response.text
    assert "@scalar/api-reference" in response.text
