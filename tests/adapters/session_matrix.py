"""HTTP strategy/refresh and worker-coherence matrix on each real adapter fixture."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
import pytest
from fastapi import FastAPI
from joserfc import jwk, jwt
from pydantic import SecretStr

from fastauth import email_password
from fastauth.database import custom
from fastauth.domain.enums import JwtAlgorithm, SessionStrategyKind
from fastauth.options import (
    CookieOptions,
    CsrfOptions,
    FastAuthOptions,
    LockoutOptions,
    RateLimitOptions,
    RefreshTokenOptions,
    SessionOptions,
)
from fastauth.plugins.jwt import JwtPlugin
from fastauth.runtime.auth import FastAuth
from fastauth.security.jwt import JwksRegistry, LocalKmsSigner
from fastauth.testing.adapter_contract import ContractAdapter


class SessionMatrixContract:
    @pytest.mark.parametrize("strategy", list(SessionStrategyKind))
    @pytest.mark.parametrize("refresh", [False, True])
    async def test_http_session_refresh_matrix(
        self, adapter: ContractAdapter, strategy: SessionStrategyKind, refresh: bool
    ) -> None:
        auth = FastAuth(
            FastAuthOptions(
                secret_key=SecretStr("k" * 64),
                database=custom(adapter=adapter),
                csrf=CsrfOptions(enabled=False),
                cookie=CookieOptions(secure=False),
                lockout=LockoutOptions(enabled=False),
                rate_limit=RateLimitOptions(enabled=False),
                session=SessionOptions(strategy=strategy),
                refresh_token=RefreshTokenOptions(enabled=refresh),
            ),
            plugins=[email_password(), JwtPlugin()],
        )
        app = FastAPI()
        app.include_router(auth.router, prefix="/auth")
        auth.add_middleware(app)
        async with (
            auth.lifespan(app),
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client,
        ):
            signup = await client.post(
                "/auth/sign-up/email",
                json={
                    "email": "matrix@example.com",
                    "password": "safe-password-123",
                    "delivery": {"kind": "bearer"},
                },
            )
            assert signup.status_code == 200, signup.text
            first = signup.json()
            token = first["credentials"]["token"]
            headers = {"Authorization": f"Bearer {token}"}
            read = await client.get("/auth/get-session", headers=headers)
            assert read.status_code == 200, read.text
            assert read.json()["session"]["id"] == first["session"]["id"]
            if refresh:
                response = await client.post(
                    "/auth/refresh", json={"refreshToken": first["credentials"]["refreshToken"]}
                )
                assert response.status_code == 200, response.text
                active = response.json()
                if strategy == SessionStrategyKind.JWT:
                    assert active["session"]["id"] == first["session"]["id"]
                token = active["credentials"]["token"]
                headers = {"Authorization": f"Bearer {token}"}
                other = await client.post(
                    "/auth/sign-in/email",
                    json={
                        "email": "matrix@example.com",
                        "password": "safe-password-123",
                        "delivery": {"kind": "bearer"},
                    },
                )
                assert other.status_code == 200, other.text
                revoked = await client.delete("/auth/sessions", headers=headers)
                assert revoked.status_code == 200, revoked.text
                other_refresh = await client.post(
                    "/auth/refresh",
                    json={
                        "refreshToken": other.json()["credentials"]["refreshToken"],
                    },
                )
                assert other_refresh.status_code in (400, 401), other_refresh.text
                current_refresh = await client.post(
                    "/auth/refresh",
                    json={
                        "refreshToken": active["credentials"]["refreshToken"],
                    },
                )
                assert current_refresh.status_code == 200, current_refresh.text
                active = current_refresh.json()
                token = active["credentials"]["token"]
                headers = {"Authorization": f"Bearer {token}"}
                signout = await client.post("/auth/sign-out", headers=headers)
                assert signout.status_code == 200, signout.text
                rejected = await client.post(
                    "/auth/refresh", json={"refreshToken": active["credentials"]["refreshToken"]}
                )
                assert rejected.status_code in (400, 401), rejected.text
            else:
                assert first["credentials"]["refreshToken"] is None
                assert (await client.post("/auth/sign-out", headers=headers)).status_code == 200
            still_active = await auth.context.session_strategy.read(token)
            assert (still_active is not None) == (strategy == SessionStrategyKind.JWT)

    async def test_independent_workers_share_rotation(self, adapter: ContractAdapter) -> None:
        registries = [
            JwksRegistry(
                adapter,
                secret_key=SecretStr("k" * 64),
                alg=JwtAlgorithm.ED25519,
                rotation_interval_seconds=60,
                grace_period_seconds=900,
                encrypt_private_keys=True,
            )
            for _ in range(2)
        ]
        first, second = registries
        old = await first.ensure_key()
        await second.ensure_key()
        replacement = await first.rotate_now()
        token = await LocalKmsSigner(second).sign(header={"alg": "Ed25519"}, payload={"sub": "one"})
        keys = jwk.KeySet([jwk.import_key(item) for item in (await first.as_jwks_json()).keys])
        assert jwt.decode(token, keys, algorithms=["Ed25519"]).header["kid"] == replacement.kid
        old.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        old.rotated_at = datetime.now(UTC) - timedelta(seconds=901)
        await adapter.update_jwks_key(old)
        token = await LocalKmsSigner(second).sign(header={"alg": "Ed25519"}, payload={"sub": "two"})
        keys = jwk.KeySet([jwk.import_key(item) for item in (await first.as_jwks_json()).keys])
        assert jwt.decode(token, keys, algorithms=["Ed25519"]).claims["sub"] == "two"
