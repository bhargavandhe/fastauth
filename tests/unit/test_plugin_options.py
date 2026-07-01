from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import ValidationError

from fastauth.plugins.api_key import ApiKeyOptions, ApiKeyPlugin
from fastauth.plugins.email_otp import EmailChangeOtpOptions, EmailOtpOptions, EmailOtpPlugin
from fastauth.plugins.jwt import JwtOptions, JwtPlugin
from fastauth.providers import api_key, email_otp, jwt


def test_api_key_options_are_strict_frozen_and_duration_native() -> None:
    options = ApiKeyOptions(
        default_prefix="svc_",
        default_remaining=10,
        default_rate_limit_window=timedelta(minutes=1),
        default_expires_in=timedelta(days=30),
    )

    assert options.default_rate_limit_window == timedelta(minutes=1)
    assert options.default_expires_in == timedelta(days=30)

    with pytest.raises(ValidationError):
        ApiKeyOptions(default_remaining="10")  # pyright: ignore[reportArgumentType]
    with pytest.raises(ValidationError):
        ApiKeyOptions(default_prefix="")
    with pytest.raises(ValidationError):
        ApiKeyOptions(default_rate_limit_window=timedelta(0))
    with pytest.raises(ValidationError):
        ApiKeyOptions(unknown=True)  # pyright: ignore[reportCallIssue]
    with pytest.raises(ValidationError):
        options.default_prefix = "other_"


def test_jwt_options_are_strict_frozen_and_duration_native() -> None:
    options = JwtOptions(
        expires_in=timedelta(minutes=20),
        rotation_interval=timedelta(days=1),
        grace_period=timedelta(hours=1),
        jwks_path="/.well-known/jwks.json",
        token_path="/jwt",
    )

    assert options.expires_in == timedelta(minutes=20)
    assert options.rotation_interval == timedelta(days=1)
    assert options.grace_period == timedelta(hours=1)

    with pytest.raises(ValidationError):
        JwtOptions(expires_in=900)  # pyright: ignore[reportArgumentType]
    with pytest.raises(ValidationError):
        JwtOptions(expires_in=timedelta(0))
    with pytest.raises(ValidationError):
        JwtOptions(jwks_path="jwks")
    with pytest.raises(ValidationError):
        JwtOptions(extra_field=True)  # pyright: ignore[reportCallIssue]
    with pytest.raises(ValidationError):
        options.token_path = "/other"


def test_email_otp_options_live_in_plugin_module_and_are_strict_frozen() -> None:
    options = EmailOtpOptions(
        code_length=8,
        expires_in=timedelta(minutes=10),
        max_attempts=4,
        email_change=EmailChangeOtpOptions(enabled=True),
    )

    assert options.expires_in == timedelta(minutes=10)

    with pytest.raises(ValidationError):
        EmailOtpOptions(code_length="6")  # pyright: ignore[reportArgumentType]
    with pytest.raises(ValidationError):
        EmailOtpOptions(code_length=3)
    with pytest.raises(ValidationError):
        EmailOtpOptions(expires_in=timedelta(0))
    with pytest.raises(ValidationError):
        EmailOtpOptions(extra_field=True)  # pyright: ignore[reportCallIssue]
    with pytest.raises(ValidationError):
        options.code_length = 6


def test_provider_factories_accept_standardized_options() -> None:
    api_key_plugin = api_key(ApiKeyOptions(default_expires_in=timedelta(hours=1)))
    email_otp_plugin = email_otp(EmailOtpOptions(expires_in=timedelta(minutes=2)))
    jwt_plugin = jwt(JwtOptions(expires_in=timedelta(minutes=5)))

    assert isinstance(api_key_plugin, ApiKeyPlugin)
    assert isinstance(email_otp_plugin, EmailOtpPlugin)
    assert isinstance(jwt_plugin, JwtPlugin)
