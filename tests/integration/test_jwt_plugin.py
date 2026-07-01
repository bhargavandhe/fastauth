"""Integration tests for the JwtPlugin (Task 20)."""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
from fastapi import FastAPI
from joserfc import jwk, jwt
from pydantic import SecretStr

from fastauth.database import custom
from fastauth.messaging.email import ConsoleEmailSender
from fastauth.options import CookieOptions, CsrfOptions, FastAuthOptions, RateLimitOptions
from fastauth.plugins.jwt import JwtOptions, JwtPlugin
from fastauth.providers import email_password
from fastauth.runtime.auth import FastAuth
from fastauth.storage.memory import InMemoryAdapter


@pytest.fixture
async def jwt_client() -> AsyncIterator[httpx.AsyncClient]:
    adapter = InMemoryAdapter()
    auth = FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("a" * 64),
            database=custom(adapter),
            csrf=CsrfOptions(enabled=False),
            cookie=CookieOptions(secure=False),
            rate_limit=RateLimitOptions(enabled=False),
        ),
        plugins=[
            email_password(),
            JwtPlugin(
                JwtOptions(
                    issuer="http://testserver",
                    audience="http://testserver",
                ),
            ),
        ],
        email_sender=ConsoleEmailSender(),
    )
    app = FastAPI(lifespan=auth.lifespan)
    auth.mount(app)
    # httpx's ASGITransport doesn't drive lifespan events, so run the
    # FastAuth lifespan manually to ensure JwtPlugin's startup hook creates
    # the JWKS key before any request hits the app.
    async with auth.lifespan(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            yield client


async def test_jwks_endpoint_returns_public_keys(jwt_client: httpx.AsyncClient) -> None:
    response = await jwt_client.get("/auth/jwks")
    assert response.status_code == 200
    body = response.json()
    assert "keys" in body
    assert body["keys"][0]["kty"] in {"OKP", "EC", "RSA"}


async def test_token_endpoint_requires_authentication(jwt_client: httpx.AsyncClient) -> None:
    response = await jwt_client.post("/auth/token")
    assert response.status_code == 401


async def test_token_can_be_verified_against_jwks(jwt_client: httpx.AsyncClient) -> None:
    signup = await jwt_client.post(
        "/auth/sign-up/email",
        json={"email": "alice@example.com", "password": "correct-horse-staple"},
    )
    assert signup.status_code == 200
    response = await jwt_client.post("/auth/token")
    assert response.status_code == 200
    token = response.json()["token"]
    jwks = (await jwt_client.get("/auth/jwks")).json()
    key_set = jwk.KeySet([jwk.import_key(item) for item in jwks["keys"]])
    decoded = jwt.decode(token, key_set, algorithms=["EdDSA"])
    assert decoded.claims["iss"] == "http://testserver"
    assert decoded.claims["aud"] == "http://testserver"


async def test_set_auth_jwt_header_on_get_session(jwt_client: httpx.AsyncClient) -> None:
    signup = await jwt_client.post(
        "/auth/sign-up/email",
        json={"email": "bob@example.com", "password": "correct-horse-staple"},
    )
    assert signup.status_code == 200
    response = await jwt_client.get("/auth/get-session")
    assert response.status_code == 200
    assert response.headers.get("set-auth-jwt", "").count(".") == 2


async def test_set_auth_jwt_header_uses_json_serializable_default_audience() -> None:
    auth = FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("a" * 64),
            database=custom(InMemoryAdapter()),
            csrf=CsrfOptions(enabled=False),
            cookie=CookieOptions(secure=False),
            rate_limit=RateLimitOptions(enabled=False),
        ),
        plugins=[email_password(), JwtPlugin()],
        email_sender=ConsoleEmailSender(),
    )
    app = FastAPI(lifespan=auth.lifespan)
    auth.mount(app)

    async with auth.lifespan(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            signup = await client.post(
                "/auth/sign-up/email",
                json={"email": "carol@example.com", "password": "correct-horse-staple"},
            )
            assert signup.status_code == 200

            response = await client.get("/auth/get-session")

    assert response.status_code == 200
    assert response.headers.get("set-auth-jwt", "").count(".") == 2
