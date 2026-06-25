"""Integration tests for SessionConfig.strategy == JWT with JwtPlugin installed.

When the user opts into JWT sessions, AuthKit constructs a JwtSessionStrategy
that shares its JwksRegistry with the installed JwtPlugin. Sign-up issues a
JWT; get-session validates the JWT and rebuilds the SessionContext;
session_strategy.revoke is a no-op (JWTs are stateless until they expire).
"""

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
async def jwt_session_client() -> AsyncIterator[tuple[httpx.AsyncClient, AuthKit]]:
    config = AuthKitConfig.model_validate(
        {
            "secret_key": SecretStr("a" * 64),
            "csrf": {"enabled": False},
            "cookie": {"secure": False},
            "rate_limit": {"enabled": False},
            "lockout": {"enabled": False},
            "session": {"strategy": "jwt"},
        },
    )
    auth = AuthKit(
        config,
        adapter=InMemoryAdapter(),
        email_sender=ConsoleEmailSender(),
        plugins=[JwtPlugin(JwtPluginConfig(issuer="http://t", audience="http://t"))],
    )
    app = FastAPI(lifespan=auth.lifespan)
    app.include_router(auth.router)
    async with (
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver"
        ) as http,
        auth.lifespan(app),
    ):
        yield http, auth


async def test_sign_up_issues_a_jwt_session_token(
    jwt_session_client: tuple[httpx.AsyncClient, AuthKit],
) -> None:
    client, _ = jwt_session_client
    response = await client.post(
        "/auth/sign-up/email",
        json={
            "email": "alice@example.com",
            "password": "correct-horse-staple",
            "include_token": True,
        },
    )
    assert response.status_code == 200
    body = response.json()
    # The plain token is a 3-part JWT, not the opaque 32-char URL-safe string
    # that the DatabaseSessionStrategy issues.
    assert body["token"].count(".") == 2


async def test_get_session_validates_the_jwt(
    jwt_session_client: tuple[httpx.AsyncClient, AuthKit],
) -> None:
    client, _ = jwt_session_client
    sign_up = await client.post(
        "/auth/sign-up/email",
        json={"email": "bob@example.com", "password": "correct-horse-staple"},
    )
    assert sign_up.status_code == 200
    # Cookie carries the signed JWT. get-session decodes it.
    me = await client.get("/auth/get-session")
    assert me.status_code == 200
    assert me.json()["user"]["email"] == "bob@example.com"


async def test_token_is_verifiable_against_jwks(
    jwt_session_client: tuple[httpx.AsyncClient, AuthKit],
) -> None:
    client, _ = jwt_session_client
    sign_up = await client.post(
        "/auth/sign-up/email",
        json={
            "email": "carol@example.com",
            "password": "correct-horse-staple",
            "include_token": True,
        },
    )
    token = sign_up.json()["token"]

    # The JWT carries the same kid that /auth/jwks publishes — the strategy
    # and the plugin share the registry, so verification works end-to-end.
    jwks = (await client.get("/auth/jwks")).json()
    assert len(jwks["keys"]) >= 1
    key_set = jwk.KeySet([jwk.import_key(item) for item in jwks["keys"]])
    decoded = jwt.decode(token, key_set, algorithms=["EdDSA"])
    assert decoded.claims["iss"] == "http://t"
    assert decoded.claims["aud"] == "http://t"
    assert decoded.claims["email"] == "carol@example.com"


async def test_no_db_session_row_under_jwt_strategy(
    jwt_session_client: tuple[httpx.AsyncClient, AuthKit],
) -> None:
    """Sanity check: the JwtSessionStrategy is stateless, so the adapter's
    session collection stays empty after sign-up."""
    client, auth = jwt_session_client
    await client.post(
        "/auth/sign-up/email",
        json={"email": "dan@example.com", "password": "correct-horse-staple"},
    )
    # InMemoryAdapter exposes its raw store as ``.sessions``; the JWT strategy
    # never writes there.
    adapter = auth.context.adapter
    assert isinstance(adapter, InMemoryAdapter)
    assert adapter.sessions == {}


def test_jwt_strategy_without_jwt_plugin_raises() -> None:
    """Misconfiguration: strategy=JWT but JwtPlugin not installed."""
    config = AuthKitConfig.model_validate(
        {
            "secret_key": SecretStr("a" * 64),
            "csrf": {"enabled": False},
            "session": {"strategy": "jwt"},
        },
    )
    with pytest.raises(ValueError, match="requires JwtPlugin"):
        AuthKit(config, adapter=InMemoryAdapter(), email_sender=ConsoleEmailSender())
