"""A required email-verification gate applies before any signup credential issue."""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from pydantic import SecretStr

from fastauth import FastAuth, email_password
from fastauth.api.commands import (
    BearerCredentialDelivery,
    CookieCredentialDelivery,
    SignUpEmailCommand,
)
from fastauth.api.responses import AuthenticationResponse, EmailVerificationRequiredResponse
from fastauth.database import custom
from fastauth.domain.enums import ProviderId, SessionStrategyKind
from fastauth.domain.events import SessionCreated, UserSignedUp
from fastauth.domain.models import EmailMessage
from fastauth.messaging.email import ConsoleEmailSender
from fastauth.options import (
    AppOptions,
    CsrfOptions,
    DynamicBaseUrlOptions,
    EmailVerificationOptions,
    FastAuthOptions,
    PasswordOptions,
    RateLimitOptions,
    RefreshTokenOptions,
    SessionOptions,
)
from fastauth.plugins.jwt import JwtPlugin
from fastauth.storage.memory import InMemoryAdapter


def build_auth(
    adapter: InMemoryAdapter,
    sender: ConsoleEmailSender,
    *,
    required: bool = True,
    strategy: SessionStrategyKind = SessionStrategyKind.DATABASE,
    app: AppOptions | None = None,
) -> FastAuth:
    return FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("v" * 64),
            database=custom(adapter=adapter),
            app=app or AppOptions(),
            csrf=CsrfOptions(enabled=False),
            rate_limit=RateLimitOptions(enabled=False),
            password=PasswordOptions(argon2_time_cost=1, argon2_memory_cost_kib=8192),
            refresh_token=RefreshTokenOptions(enabled=True),
            session=SessionOptions(strategy=strategy),
            email_verification=EmailVerificationOptions(require_verified_for_sign_in=required),
        ),
        plugins=[email_password(), JwtPlugin()],
        email_sender=sender,
    )


@pytest.mark.parametrize("delivery", ["cookie", "bearer"])
@pytest.mark.parametrize("strategy", list(SessionStrategyKind))
async def test_http_signup_requires_verification_before_issuing_any_credentials(
    delivery: str,
    strategy: SessionStrategyKind,
) -> None:
    adapter, sender = InMemoryAdapter(), ConsoleEmailSender()
    auth = build_auth(adapter, sender, strategy=strategy)
    sessions: list[SessionCreated] = []
    signups: list[UserSignedUp] = []

    async def record_session(event: SessionCreated) -> None:
        sessions.append(event)

    async def record_signup(event: UserSignedUp) -> None:
        signups.append(event)

    auth.events.subscribe(SessionCreated, record_session)
    auth.events.subscribe(UserSignedUp, record_signup)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=auth.as_asgi()), base_url="https://example.com"
    ) as client:
        response = await client.post(
            "/auth/sign-up/email",
            json={
                "email": "verify@example.com",
                "password": "correct-password-123",
                "delivery": {"kind": delivery},
            },
        )
        assert response.status_code == 200
        body = response.json()
        assert "session" not in body
        assert "credentials" not in body
        assert set(body) == {"user", "verificationRequired"}
        assert body["verificationRequired"] is True
        assert not body["user"]["emailVerified"]
        assert "set-cookie" not in response.headers
        assert not adapter.sessions
        assert not adapter.refresh_tokens
        assert not adapter.jwks_keys
        assert not sessions
        assert len(signups) == 1
        assert len(sender.outbox) == 1
        user = await adapter.get_user_by_email("verify@example.com")
        assert user is not None
        account = await adapter.get_account_for_user(user.id, ProviderId.CREDENTIAL)
        assert account is not None and account.password is not None
        assert len(adapter.verifications) == 1
        assert (await client.get("/auth/get-session")).status_code == 204

        blocked = await client.post(
            "/auth/sign-in/email",
            json={"email": user.email, "password": "correct-password-123"},
        )
        assert blocked.status_code == 403
        assert blocked.json()["code"] == "EMAIL_NOT_VERIFIED"

        verification_url = next(
            urlparse(line.strip())
            for line in sender.outbox[0].text.splitlines()
            if line.strip().startswith("http")
        )
        token = parse_qs(verification_url.query)["token"][0]
        verified = await client.post(
            "/auth/verify-email",
            json={"email": user.email, "token": token, "delivery": {"kind": delivery}},
        )
        assert verified.status_code == 200
        assert verified.json()["user"]["emailVerified"] is True
        assert verified.json()["session"]["userId"] == user.id
        if delivery == "bearer":
            credentials = verified.json()["credentials"]
            assert credentials["token"]
            assert credentials["refreshToken"]
        else:
            assert "set-cookie" in verified.headers


@pytest.mark.parametrize("path", ["command", "sdk"])
@pytest.mark.parametrize("delivery", [CookieCredentialDelivery(), BearerCredentialDelivery()])
async def test_sdk_signup_returns_typed_verification_result_without_credentials(
    path: str,
    delivery: CookieCredentialDelivery | BearerCredentialDelivery,
) -> None:
    adapter, sender = InMemoryAdapter(), ConsoleEmailSender()
    auth = build_auth(adapter, sender)
    command = SignUpEmailCommand(
        email="sdk@example.com", password=SecretStr("correct-password-123"), delivery=delivery
    )
    result = (
        await auth.api.sign_up.email(command)
        if path == "command"
        else await auth.sign_up.email(command.email, command.password, delivery=delivery)
    )
    assert isinstance(result, EmailVerificationRequiredResponse)
    assert result.verification_required is True
    assert set(result.model_dump()) == {"user", "verificationRequired"}
    assert not adapter.sessions
    assert not adapter.refresh_tokens
    assert len(sender.outbox) == 1


@pytest.mark.parametrize("delivery", [CookieCredentialDelivery(), BearerCredentialDelivery()])
async def test_optional_verification_preserves_authenticated_signup(
    delivery: CookieCredentialDelivery | BearerCredentialDelivery,
) -> None:
    adapter, sender = InMemoryAdapter(), ConsoleEmailSender()
    auth = build_auth(adapter, sender, required=False)
    command = SignUpEmailCommand(
        email="normal@example.com", password=SecretStr("correct-password-123")
    )
    result = await auth.sign_up.email(
        command.email,
        command.password,
        delivery=delivery,
    )
    assert isinstance(result, AuthenticationResponse)
    assert result.session.user_id == result.user.id
    assert len(adapter.sessions) == 1
    assert not sender.outbox
    if isinstance(delivery, BearerCredentialDelivery):
        assert result.credentials is not None and result.credentials.refresh_token is not None
    else:
        assert result.credentials is None


async def test_signup_verification_link_uses_validated_dynamic_request_origin() -> None:
    adapter, sender = InMemoryAdapter(), ConsoleEmailSender()
    auth = build_auth(
        adapter,
        sender,
        app=AppOptions(
            base_url=DynamicBaseUrlOptions(allowed_hosts=("tenant.example.com",), protocol="https")
        ),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=auth.as_asgi()), base_url="https://tenant.example.com"
    ) as client:
        result = await client.post(
            "/auth/sign-up/email",
            json={"email": "tenant@example.com", "password": "correct-password-123"},
        )
    assert result.status_code == 200
    assert len(sender.outbox) == 1
    assert "https://tenant.example.com/auth/verify-email?" in sender.outbox[0].text


async def test_failed_signup_email_keeps_identity_without_credentials_and_resend_recovers() -> None:
    class FailingEmailSender(ConsoleEmailSender):
        fail = True

        async def send(self, message: EmailMessage) -> None:
            if self.fail:
                raise RuntimeError("email delivery failed")
            await super().send(message)

    adapter, sender = InMemoryAdapter(), FailingEmailSender()
    auth = build_auth(adapter, sender)
    command = SignUpEmailCommand(
        email="recover@example.com",
        password=SecretStr("correct-password-123"),
        delivery=BearerCredentialDelivery(),
    )
    with pytest.raises(RuntimeError, match="email delivery failed"):
        await auth.api.sign_up.email(command)
    user = await adapter.get_user_by_email(command.email)
    assert user is not None
    account = await adapter.get_account_for_user(user.id, ProviderId.CREDENTIAL)
    assert account is not None and account.password is not None
    assert not adapter.sessions
    assert not adapter.refresh_tokens
    assert not sender.outbox

    sender.fail = False
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=auth.as_asgi()), base_url="https://example.com"
    ) as client:
        resent = await client.post("/auth/send-verification-email", json={"email": command.email})
        assert resent.status_code == 200
        assert len(sender.outbox) == 1
        verification_url = next(
            urlparse(line.strip())
            for line in sender.outbox[0].text.splitlines()
            if line.strip().startswith("http")
        )
        verified = await client.post(
            "/auth/verify-email",
            json={"email": command.email, "token": parse_qs(verification_url.query)["token"][0]},
        )
        assert verified.status_code == 200
        assert verified.json()["user"]["id"] == user.id
        assert verified.json()["user"]["emailVerified"] is True
