from __future__ import annotations

import pytest
from pydantic import SecretStr

from fastauth.database import custom
from fastauth.options import FastAuthOptions
from fastauth.plugins.api_key import ApiKeyPlugin
from fastauth.plugins.email_otp import EmailOtpPlugin
from fastauth.plugins.openapi import OpenApiPlugin
from fastauth.plugins.test_utils import TestUtilsPlugin
from fastauth.runtime.auth import FastAuth
from fastauth.storage.memory import InMemoryAdapter


@pytest.mark.parametrize(
    "plugin",
    [
        ApiKeyPlugin(),
        EmailOtpPlugin(),
        OpenApiPlugin(),
        TestUtilsPlugin(),
    ],
)
def test_first_party_plugin_bind_calls_base_context_hook(plugin: object) -> None:
    auth = FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("a" * 64),
            database=custom(InMemoryAdapter()),
        ),
        plugins=[plugin],  # type: ignore[list-item]
    )

    assert plugin.require_context() is auth.context  # type: ignore[attr-defined]
