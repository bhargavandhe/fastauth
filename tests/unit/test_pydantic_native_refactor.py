from __future__ import annotations

from datetime import timedelta

import httpx
import pytest
from fastapi import FastAPI
from pydantic import BaseModel, SecretStr, ValidationError

from fastauth import FastAuth, FastAuthOptions
from fastauth.database import memory
from fastauth.options import (
    CookieOptions,
    CsrfOptions,
    PasswordOptions,
    RateLimitOptions,
    SessionOptions,
)
from fastauth.plugins.email_otp import EmailOtpOptions
from fastauth.providers import email_password
from fastauth.runtime.context import AuthContext


def test_options_are_frozen_after_runtime_construction() -> None:
    options = FastAuthOptions(secret_key=SecretStr("a" * 64), database=memory())
    FastAuth(options)

    with pytest.raises(ValidationError):
        options.session.expires_in = timedelta(seconds=-1)


@pytest.mark.parametrize(
    "factory",
    [
        lambda: SessionOptions(expires_in=timedelta(seconds=-50)),
        lambda: PasswordOptions(min_length=-1),
        lambda: RateLimitOptions(max_requests=0),
        lambda: FastAuthOptions(
            secret_key="a" * 64,  # pyright: ignore[reportArgumentType]
            database=memory(),
        ),
    ],
)
def test_options_reject_invalid_or_coerced_values(factory: object) -> None:
    with pytest.raises(ValidationError):
        factory()  # type: ignore[operator]


def test_email_otp_options_reject_invalid_values_and_extra_fields() -> None:
    with pytest.raises(ValidationError):
        EmailOtpOptions(
            code_length=-1,
            expires_in=timedelta(seconds=0),
            max_attempts=-100,
            extra_typo=True,  # type: ignore[call-arg]
        )


async def test_authentication_response_does_not_expose_internal_fields() -> None:
    auth = FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("b" * 64),
            database=memory(),
            csrf=CsrfOptions(enabled=False),
            cookie=CookieOptions(secure=False),
            rate_limit=RateLimitOptions(enabled=False),
        ),
        plugins=[email_password()],
    )
    app = FastAPI(lifespan=auth.lifespan)
    auth.mount(app)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        response = await client.post(
            "/auth/sign-up/email",
            json={
                "email": "alice@example.com",
                "password": "correct-horse-battery",
                "delivery": {"kind": "bearer"},
            },
        )

    assert response.status_code == 200, response.text
    body = response.json()
    assert "tokenHash" not in body["session"]
    assert "token_hash" not in body["session"]
    assert "pendingEmailChange" not in body["user"]
    assert "pending_email_change" not in body["user"]
    assert "credentials" in body
    assert body["credentials"]["token"]


def test_auth_context_is_not_a_pydantic_model() -> None:
    assert not issubclass(AuthContext, BaseModel)
