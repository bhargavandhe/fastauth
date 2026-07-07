from __future__ import annotations

import pytest
from pydantic import SecretStr

from fastauth.database import custom
from fastauth.exceptions import FeatureNotEnabledError
from fastauth.options import FastAuthOptions
from fastauth.plugins.email_password import EmailPasswordOptions
from fastauth.providers import email_otp, email_password
from fastauth.providers import test_utils as make_test_utils_plugin
from fastauth.runtime.auth import FastAuth
from fastauth.runtime.capabilities import Capability, CapabilityRegistry
from fastauth.storage.memory import InMemoryAdapter


def build_auth(*, username_sign_in: bool = True) -> FastAuth:
    return FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("a" * 64),
            database=custom(InMemoryAdapter()),
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

    assert "core.sessions" in ids
    assert "core.refresh-tokens" in ids
    assert "email-password" in ids
    assert "username-sign-in" in ids
    assert "email-otp" in ids
    assert "test-utils" in ids
    assert auth.capabilities.has("email-password")
    assert auth.capabilities.require("email-password").plugin_id == "fastauth-email-password"


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
