from __future__ import annotations

import pytest
from pydantic import SecretStr

from fastauth import email_otp, email_password
from fastauth import test_utils as make_test_utils_plugin
from fastauth.database import custom
from fastauth.exceptions import FeatureNotEnabledError
from fastauth.options import FastAuthOptions
from fastauth.plugins.email_password import EmailPasswordOptions
from fastauth.runtime.auth import FastAuth
from fastauth.runtime.capabilities import (
    CORE_REFRESH_TOKENS,
    CORE_SESSIONS,
    EMAIL_OTP,
    EMAIL_PASSWORD,
    TEST_UTILS,
    USERNAME_SIGN_IN,
    Capability,
    CapabilityRegistry,
)
from fastauth.storage.memory import InMemoryAdapter


def build_auth(*, username_sign_in: bool = True) -> FastAuth:
    return FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("a" * 64),
            database=custom(adapter=InMemoryAdapter()),
        ),
        plugins=[
            email_password(
                EmailPasswordOptions(
                    allow_username_sign_in=username_sign_in,
                    allow_bearer_tokens=True,
                )
            ),
            email_otp(),
            make_test_utils_plugin(),
        ],
    )


def test_fastauth_exposes_core_and_plugin_capabilities() -> None:
    auth = build_auth()

    ids = {capability.id for capability in auth.capabilities.list()}

    assert str(CORE_SESSIONS) in ids
    assert str(CORE_REFRESH_TOKENS) in ids
    assert str(EMAIL_PASSWORD) in ids
    assert str(USERNAME_SIGN_IN) in ids
    assert str(EMAIL_OTP) in ids
    assert str(TEST_UTILS) in ids
    assert auth.capabilities.has(EMAIL_PASSWORD)
    assert auth.capabilities.require(EMAIL_PASSWORD).plugin_id == "fastauth-email-password"


def test_disabled_nested_feature_is_not_reported_as_capability() -> None:
    auth = build_auth(username_sign_in=False)

    assert not auth.capabilities.has("username-sign-in")
    with pytest.raises(FeatureNotEnabledError):
        auth.capabilities.require("username-sign-in")


def test_capability_registry_rejects_duplicates() -> None:
    with pytest.raises(ValueError, match="duplicate capability id"):
        CapabilityRegistry(
            [
                Capability(id="same", description="First."),
                Capability(id="same", description="Second."),
            ]
        )
