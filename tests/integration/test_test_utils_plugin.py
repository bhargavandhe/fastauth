"""Integration tests for the TestUtilsPlugin (Task 23)."""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from fastauth.plugins.test_utils import TestHelpers, TestUtilsConfig, TestUtilsPlugin
from fastauth.runtime.auth import FastAuth


def get_helpers(auth: FastAuth) -> TestHelpers:
    plugin = auth.context.plugins.by_id["fastauth-test-utils"]
    assert isinstance(plugin, TestUtilsPlugin)
    assert plugin.helpers is not None
    return plugin.helpers


@pytest.fixture
def auth(auth_factory: Callable[..., FastAuth]) -> FastAuth:
    return auth_factory(plugins=[TestUtilsPlugin(TestUtilsConfig(capture_otp=True))])


async def test_factory_and_login(client: httpx.AsyncClient, auth: FastAuth) -> None:
    helpers = get_helpers(auth)
    user = helpers.create_user(email="alice@example.com")
    saved = await helpers.save_user(user)
    login = await helpers.login(saved.id)
    assert login.token
    response = await client.get(
        "/auth/get-session",
        headers={"authorization": f"Bearer {login.token}"},
    )
    assert response.status_code == 200
    assert response.json()["user"]["id"] == saved.id


async def test_otp_capture(client: httpx.AsyncClient, auth: FastAuth) -> None:
    helpers = get_helpers(auth)
    user = helpers.create_user(email="bob@example.com", email_verified=False)
    await helpers.save_user(user)
    sent = await client.post(
        "/auth/send-verification-email",
        json={"email": "bob@example.com"},
    )
    assert sent.status_code == 200
    plain = helpers.get_otp("bob@example.com")
    assert plain is not None
    verify = await client.post(
        "/auth/verify-email",
        json={"email": "bob@example.com", "token": plain},
    )
    assert verify.status_code == 200
