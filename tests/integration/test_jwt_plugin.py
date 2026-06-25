"""Integration tests for the JwtPlugin (Task 20)."""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
from fastapi import FastAPI
from joserfc import jwk, jwt
from pydantic import SecretStr

from authkit.config import AuthKitConfig
from authkit.messaging.email import ConsoleEmailSender
from authkit.plugins.jwt import JwtPlugin, JwtPluginConfig
from authkit.runtime.auth import AuthKit
from authkit.storage.memory import InMemoryAdapter


@pytest.fixture
async def jwt_client() -> AsyncIterator[httpx.AsyncClient]:
    auth = AuthKit(
        AuthKitConfig.model_validate(
            {
                "secret_key": SecretStr("a" * 64),
                "csrf": {"enabled": False},
                "cookie": {"secure": False},
                "rate_limit": {"enabled": False},
            },
        ),
        adapter=InMemoryAdapter(),
        email_sender=ConsoleEmailSender(),
        plugins=[
            JwtPlugin(
                JwtPluginConfig(
                    issuer="http://testserver",
                    audience="http://testserver",
                ),
            ),
        ],
    )
    app = FastAPI(lifespan=auth.lifespan)
    app.include_router(auth.router)
    # httpx's ASGITransport doesn't drive lifespan events, so run the
    # AuthKit lifespan manually to ensure JwtPlugin's startup hook creates
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
