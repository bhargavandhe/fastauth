"""Integration tests for ``EmailOtpPlugin``."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from authkit.flows.email_otp import EmailOtpConfig
from authkit.plugins.email_otp import EmailOtpPlugin
from authkit.plugins.test_utils import TestHelpers, TestUtilsConfig, TestUtilsPlugin
from authkit.runtime.auth import AuthKit
from authkit.storage.memory import InMemoryAdapter as MemoryAdapter


def get_helpers(auth: AuthKit) -> TestHelpers:
    plugin = auth.context.plugins.by_id["authkit-test-utils"]
    assert isinstance(plugin, TestUtilsPlugin)
    assert plugin.helpers is not None
    return plugin.helpers


@pytest.fixture
def auth(auth_factory: Callable[..., AuthKit]) -> AuthKit:
    return auth_factory(
        plugins=[
            EmailOtpPlugin(EmailOtpConfig(change_email_enabled=True)),
            TestUtilsPlugin(TestUtilsConfig(capture_otp=True)),
        ],
    )


@pytest.fixture
def disable_signup_auth(auth_factory: Callable[..., AuthKit]) -> AuthKit:
    return auth_factory(
        plugins=[
            EmailOtpPlugin(EmailOtpConfig(disable_sign_up=True)),
            TestUtilsPlugin(TestUtilsConfig(capture_otp=True)),
        ],
    )


# --- Send / check ----------------------------------------------------------


async def test_send_otp_for_sign_in(client: httpx.AsyncClient, auth: AuthKit) -> None:
    response = await client.post(
        "/auth/email-otp/send-verification-otp",
        json={"email": "fresh@example.com", "type": "sign-in"},
    )
    assert response.status_code == 200
    assert response.json() == {"success": True}
    plain = get_helpers(auth).get_otp("fresh@example.com")
    assert plain is not None
    assert len(plain) == 6
    assert plain.isdigit()


async def test_send_otp_anti_enumeration_for_email_verification(
    client: httpx.AsyncClient,
    auth: AuthKit,
) -> None:
    """Send-OTP for email-verification of an unknown email returns success
    without sending anything (no helpers.get_otp will find it).
    """
    response = await client.post(
        "/auth/email-otp/send-verification-otp",
        json={"email": "unknown@example.com", "type": "email-verification"},
    )
    assert response.status_code == 200
    assert get_helpers(auth).get_otp("unknown@example.com") is None


async def test_check_otp_does_not_consume(
    client: httpx.AsyncClient,
    auth: AuthKit,
) -> None:
    helpers = get_helpers(auth)
    await client.post(
        "/auth/email-otp/send-verification-otp",
        json={"email": "alice@example.com", "type": "sign-in"},
    )
    otp = helpers.get_otp("alice@example.com")
    assert otp is not None
    # Pre-check passes.
    check = await client.post(
        "/auth/email-otp/check-verification-otp",
        json={"email": "alice@example.com", "type": "sign-in", "otp": otp},
    )
    assert check.status_code == 200
    # Same OTP can still complete sign-in afterwards.
    sign_in = await client.post(
        "/auth/sign-in/email-otp",
        json={"email": "alice@example.com", "otp": otp},
    )
    assert sign_in.status_code == 200, sign_in.text


# --- Sign-in --------------------------------------------------------------


async def test_sign_in_auto_registers_new_user(
    client: httpx.AsyncClient,
    auth: AuthKit,
) -> None:
    helpers = get_helpers(auth)
    await client.post(
        "/auth/email-otp/send-verification-otp",
        json={"email": "newbie@example.com", "type": "sign-in"},
    )
    otp = helpers.get_otp("newbie@example.com")
    assert otp is not None
    response = await client.post(
        "/auth/sign-in/email-otp",
        json={"email": "newbie@example.com", "otp": otp, "name": "Newbie"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["user"]["email"] == "newbie@example.com"
    assert body["user"]["name"] == "Newbie"
    assert body["user"]["email_verified"] is True
    assert "authkit.session_token" in response.headers.get("set-cookie", "")


async def test_sign_in_existing_user(
    client: httpx.AsyncClient,
    auth: AuthKit,
) -> None:
    helpers = get_helpers(auth)
    user = helpers.create_user(email="returning@example.com", email_verified=True)
    await helpers.save_user(user)
    await client.post(
        "/auth/email-otp/send-verification-otp",
        json={"email": "returning@example.com", "type": "sign-in"},
    )
    otp = helpers.get_otp("returning@example.com")
    assert otp is not None
    response = await client.post(
        "/auth/sign-in/email-otp",
        json={"email": "returning@example.com", "otp": otp},
    )
    assert response.status_code == 200
    assert response.json()["user"]["id"] == user.id


async def test_sign_in_disable_sign_up_rejects_unknown_user(
    auth_factory: Callable[..., AuthKit],
) -> None:
    auth = auth_factory(
        plugins=[
            EmailOtpPlugin(EmailOtpConfig(disable_sign_up=True)),
            TestUtilsPlugin(TestUtilsConfig(capture_otp=True)),
        ],
    )
    helpers = get_helpers(auth)
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(auth.router)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        # Send returns success but no email is sent (anti-enumeration).
        await client.post(
            "/auth/email-otp/send-verification-otp",
            json={"email": "stranger@example.com", "type": "sign-in"},
        )
        assert helpers.get_otp("stranger@example.com") is None
        # Sign-in attempt with any OTP fails.
        response = await client.post(
            "/auth/sign-in/email-otp",
            json={"email": "stranger@example.com", "otp": "123456"},
        )
        assert response.status_code == 401
        assert response.json()["code"] == "INVALID_CREDENTIALS"


async def test_sign_in_wrong_otp_rejected(
    client: httpx.AsyncClient,
    auth: AuthKit,
) -> None:
    await client.post(
        "/auth/email-otp/send-verification-otp",
        json={"email": "alice@example.com", "type": "sign-in"},
    )
    response = await client.post(
        "/auth/sign-in/email-otp",
        json={"email": "alice@example.com", "otp": "000000"},
    )
    assert response.status_code == 400
    assert response.json()["code"] == "TOKEN_INVALID"


async def test_otp_invalidated_after_allowed_attempts(
    client: httpx.AsyncClient,
    auth: AuthKit,
) -> None:
    helpers = get_helpers(auth)
    await client.post(
        "/auth/email-otp/send-verification-otp",
        json={"email": "alice@example.com", "type": "sign-in"},
    )
    correct_otp = helpers.get_otp("alice@example.com")
    assert correct_otp is not None
    # 3 failed attempts (default allowed_attempts=3) burns the OTP.
    for _ in range(3):
        bad = await client.post(
            "/auth/sign-in/email-otp",
            json={"email": "alice@example.com", "otp": "999999"},
        )
        assert bad.status_code == 400
    # The previously-correct OTP is now invalid because the row is gone.
    final = await client.post(
        "/auth/sign-in/email-otp",
        json={"email": "alice@example.com", "otp": correct_otp},
    )
    assert final.status_code == 400


async def test_otp_replay_protection(
    client: httpx.AsyncClient,
    auth: AuthKit,
) -> None:
    """A successfully-consumed OTP cannot be reused."""
    helpers = get_helpers(auth)
    await client.post(
        "/auth/email-otp/send-verification-otp",
        json={"email": "alice@example.com", "type": "sign-in"},
    )
    otp = helpers.get_otp("alice@example.com")
    assert otp is not None
    first = await client.post(
        "/auth/sign-in/email-otp",
        json={"email": "alice@example.com", "otp": otp},
    )
    assert first.status_code == 200
    second = await client.post(
        "/auth/sign-in/email-otp",
        json={"email": "alice@example.com", "otp": otp},
    )
    assert second.status_code == 400


async def test_resend_rotates_otp(client: httpx.AsyncClient, auth: AuthKit) -> None:
    """Sending a second OTP invalidates the first (rotate strategy)."""
    helpers = get_helpers(auth)
    await client.post(
        "/auth/email-otp/send-verification-otp",
        json={"email": "alice@example.com", "type": "sign-in"},
    )
    first_otp = helpers.get_otp("alice@example.com")
    assert first_otp is not None
    helpers.clear_otps()
    await client.post(
        "/auth/email-otp/send-verification-otp",
        json={"email": "alice@example.com", "type": "sign-in"},
    )
    second_otp = helpers.get_otp("alice@example.com")
    assert second_otp is not None
    assert first_otp != second_otp
    # First OTP is now invalid.
    bad = await client.post(
        "/auth/sign-in/email-otp",
        json={"email": "alice@example.com", "otp": first_otp},
    )
    assert bad.status_code == 400
    # Second OTP works.
    good = await client.post(
        "/auth/sign-in/email-otp",
        json={"email": "alice@example.com", "otp": second_otp},
    )
    assert good.status_code == 200


async def test_expired_otp_rejected(
    client: httpx.AsyncClient,
    auth: AuthKit,
    adapter: MemoryAdapter,
) -> None:
    helpers = get_helpers(auth)
    await client.post(
        "/auth/email-otp/send-verification-otp",
        json={"email": "alice@example.com", "type": "sign-in"},
    )
    otp = helpers.get_otp("alice@example.com")
    assert otp is not None
    # Manually back-date expires_at on the row.
    row = next(iter(adapter.verifications.values()))
    row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    response = await client.post(
        "/auth/sign-in/email-otp",
        json={"email": "alice@example.com", "otp": otp},
    )
    assert response.status_code == 400
    assert response.json()["code"] == "TOKEN_EXPIRED"


# --- Verify-email + password-reset ---------------------------------------


async def test_verify_email_with_otp(
    client: httpx.AsyncClient,
    auth: AuthKit,
) -> None:
    helpers = get_helpers(auth)
    user = helpers.create_user(email="bob@example.com", email_verified=False)
    await helpers.save_user(user)
    await client.post(
        "/auth/email-otp/send-verification-otp",
        json={"email": "bob@example.com", "type": "email-verification"},
    )
    otp = helpers.get_otp("bob@example.com")
    assert otp is not None
    response = await client.post(
        "/auth/email-otp/verify-email",
        json={"email": "bob@example.com", "otp": otp},
    )
    assert response.status_code == 200
    assert response.json() == {"success": True}
    # User's email is now verified.
    refreshed = await auth.context.adapter.get_user_by_id(user.id)
    assert refreshed is not None
    assert refreshed.email_verified is True


async def test_password_reset_round_trip(
    client: httpx.AsyncClient,
    auth: AuthKit,
) -> None:
    helpers = get_helpers(auth)
    user = helpers.create_user(email="reset@example.com", email_verified=True)
    await helpers.save_user(user)
    # Set an initial password via the credential provider so reset has
    # something to overwrite.
    from authkit.domain.enums import ProviderId
    from authkit.domain.models import Account

    await auth.context.adapter.create_account(
        Account(
            user_id=user.id,
            provider_id=ProviderId.CREDENTIAL,
            account_id=user.id,
            password=auth.context.password_hasher.hash("oldpassword1"),
        ),
    )
    # Request reset OTP.
    await client.post(
        "/auth/email-otp/request-password-reset",
        json={"email": "reset@example.com"},
    )
    otp = helpers.get_otp("reset@example.com")
    assert otp is not None
    # Consume.
    response = await client.post(
        "/auth/email-otp/reset-password",
        json={
            "email": "reset@example.com",
            "otp": otp,
            "password": "brand-new-pw-1",
        },
    )
    assert response.status_code == 200
    # New password works on the regular sign-in.
    sign_in = await client.post(
        "/auth/sign-in/email",
        json={"email": "reset@example.com", "password": "brand-new-pw-1"},
    )
    assert sign_in.status_code == 200


async def test_password_reset_anti_enumeration(
    client: httpx.AsyncClient,
    auth: AuthKit,
) -> None:
    """Reset-OTP for an unknown email returns success without sending."""
    helpers = get_helpers(auth)
    response = await client.post(
        "/auth/email-otp/request-password-reset",
        json={"email": "ghost@example.com"},
    )
    assert response.status_code == 200
    assert helpers.get_otp("ghost@example.com") is None


# --- Change-email --------------------------------------------------------


async def test_change_email_round_trip(
    client: httpx.AsyncClient,
    auth: AuthKit,
) -> None:
    helpers = get_helpers(auth)
    user = helpers.create_user(email="old@example.com", email_verified=True)
    saved = await helpers.save_user(user)
    login = await helpers.login(saved.id)
    headers = {"authorization": f"Bearer {login.token}"}
    request = await client.post(
        "/auth/email-otp/request-email-change",
        json={"new_email": "new@example.com"},
        headers=headers,
    )
    assert request.status_code == 200
    otp = helpers.get_otp("new@example.com")
    assert otp is not None
    confirm = await client.post(
        "/auth/email-otp/change-email",
        json={"new_email": "new@example.com", "otp": otp},
        headers=headers,
    )
    assert confirm.status_code == 200
    refreshed = await auth.context.adapter.get_user_by_id(saved.id)
    assert refreshed is not None
    assert refreshed.email == "new@example.com"


async def test_change_email_endpoints_404_when_disabled(
    auth_factory: Callable[..., AuthKit],
) -> None:
    """Without ``change_email_enabled``, the two endpoints are not registered."""
    auth = auth_factory(
        plugins=[EmailOtpPlugin(EmailOtpConfig())],  # default change_email_enabled=False
    )
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(auth.router)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        # No JSON body needed — the route doesn't exist.
        response = await client.post(
            "/auth/email-otp/request-email-change",
            json={"new_email": "x@example.com"},
        )
        assert response.status_code == 404
        response = await client.post(
            "/auth/email-otp/change-email",
            json={"new_email": "x@example.com", "otp": "000000"},
        )
        assert response.status_code == 404


async def test_change_email_requires_authentication(
    client: httpx.AsyncClient,
    auth: AuthKit,
) -> None:
    response = await client.post(
        "/auth/email-otp/request-email-change",
        json={"new_email": "x@example.com"},
    )
    assert response.status_code == 401
    assert response.json()["code"] == "INVALID_CREDENTIALS"
