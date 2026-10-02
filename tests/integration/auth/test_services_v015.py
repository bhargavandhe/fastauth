"""Public typed services work without HTTP Request objects."""

from collections.abc import Callable

import pytest
from pydantic import SecretStr

from fastauth import FastAuth, audit_logs, email_otp, jwt
from fastauth.api.commands import BearerCredentialDelivery, RequestContext
from fastauth.domain.enums import HookPhase
from fastauth.domain.events import OtpGenerated
from fastauth.exceptions import FeatureNotEnabledError, InvalidCredentialsError, TokenInvalidError
from fastauth.flows.email_otp import (
    ChangeEmailOtpRequest,
    CheckOtpRequest,
    EmailOtpPurpose,
    RequestEmailChangeOtpRequest,
    RequestPasswordResetOtpRequest,
    ResetPasswordOtpRequest,
    SendOtpRequest,
    SignInOtpRequest,
    VerifyEmailOtpRequest,
)
from fastauth.flows.verification import SendVerificationEmailRequest, VerifyEmailRequest
from fastauth.plugins.email_otp_options import EmailChangeOtpOptions, EmailOtpOptions
from fastauth.runtime.hooks import HookContext


@pytest.mark.asyncio
async def test_complete_typed_service_flows(auth_factory: Callable[..., FastAuth]) -> None:
    auth = auth_factory(
        plugins=[
            email_otp(EmailOtpOptions(email_change=EmailChangeOtpOptions(enabled=True))),
            jwt(),
            audit_logs(),
        ]
    )
    updates: list[HookPhase] = []

    async def updated(hook: HookContext) -> None:
        updates.append(hook.phase)

    auth.hook(HookPhase.BEFORE_UPDATE, target="user")(updated)
    auth.hook(HookPhase.AFTER_UPDATE, target="user")(updated)
    captured: list[OtpGenerated] = []

    async def remember(event: OtpGenerated) -> None:
        captured.append(event)

    auth.on(OtpGenerated)(remember)
    user = await auth.api.create_user(email="sdk@example.com", password="Password123!")
    assert (await auth.verification.send(SendVerificationEmailRequest(email=user.email))).success
    verified = await auth.verification.confirm(
        VerifyEmailRequest(
            email=user.email,
            token=SecretStr(captured[-1].plain),
            delivery=BearerCredentialDelivery(),
        )
    )
    assert verified.user.email_verified
    assert verified.credentials is not None
    await auth.otp.send(
        SendOtpRequest(email=user.email, purpose=EmailOtpPurpose.SIGN_IN),
        context=RequestContext(ip_address="127.0.0.1"),
    )
    code = SecretStr(captured[-1].plain)
    assert (
        await auth.otp.check(
            CheckOtpRequest(email=user.email, purpose=EmailOtpPurpose.SIGN_IN, otp=code)
        )
    ).success
    signed = await auth.otp.sign_in(
        SignInOtpRequest(email=user.email, otp=code, delivery=BearerCredentialDelivery())
    )
    assert signed.credentials is not None
    token = SecretStr(signed.credentials.token.root)
    with pytest.raises(TokenInvalidError):
        await auth.otp.sign_in(SignInOtpRequest(email=user.email, otp=code))
    await auth.otp.send(
        SendOtpRequest(email=user.email, purpose=EmailOtpPurpose.EMAIL_VERIFICATION)
    )
    assert (
        await auth.otp.verify_email(
            VerifyEmailOtpRequest(email=user.email, otp=SecretStr(captured[-1].plain))
        )
    ).success
    await auth.otp.request_email_change(
        token, RequestEmailChangeOtpRequest(new_email="changed@example.com")
    )
    assert (
        await auth.otp.change_email(
            token,
            ChangeEmailOtpRequest(
                new_email="changed@example.com", otp=SecretStr(captured[-1].plain)
            ),
        )
    ).success
    assert updates == [HookPhase.BEFORE_UPDATE, HookPhase.AFTER_UPDATE] * 3
    issued = await auth.jwt.issue(token)
    assert issued.token.count(".") == 2
    assert (await auth.jwt.jwks()).keys
    events = await auth.audit.list(token)
    assert events.total > 0
    assert all(event.user_id == user.id.root for event in events.events)
    await auth.otp.request_password_reset(
        RequestPasswordResetOtpRequest(email="changed@example.com")
    )
    assert (
        await auth.otp.reset_password(
            ResetPasswordOtpRequest(
                email="changed@example.com",
                otp=SecretStr(captured[-1].plain),
                password=SecretStr("UpdatedPassword123!"),
            )
        )
    ).success
    with pytest.raises(InvalidCredentialsError):
        await auth.jwt.issue(token)
    assert (
        await auth.sign_in.email("changed@example.com", SecretStr("UpdatedPassword123!"))
    ).user.id == user.id


@pytest.mark.asyncio
async def test_services_fail_closed_without_plugins(auth: FastAuth) -> None:
    with pytest.raises(FeatureNotEnabledError):
        await auth.otp.send(
            SendOtpRequest(email="missing@example.com", purpose=EmailOtpPurpose.SIGN_IN)
        )
    with pytest.raises(FeatureNotEnabledError):
        await auth.jwt.jwks()
    with pytest.raises(FeatureNotEnabledError):
        await auth.audit.list(SecretStr("invalid"))


@pytest.mark.asyncio
async def test_audit_admin_and_plugin_namespace_contract(
    auth_factory: Callable[..., FastAuth],
) -> None:
    from pydantic import ValidationError

    from fastauth.exceptions import CsrfError
    from fastauth.runtime.services import AuditLogsApi, AuditQuery, EmailOtpApi, JwtApi

    auth = auth_factory(plugins=[email_otp(), jwt(), audit_logs()])
    assert isinstance(auth.plugins.get(EmailOtpApi), EmailOtpApi)
    assert isinstance(auth.plugins.get(JwtApi), JwtApi)
    assert isinstance(auth.plugins.get(AuditLogsApi), AuditLogsApi)
    signed = await auth.sign_up.email(
        "audit@example.com", SecretStr("Password123!"), delivery=BearerCredentialDelivery()
    )
    assert signed.credentials is not None
    with pytest.raises(CsrfError, match="admin access"):
        await auth.audit.list_all(SecretStr(signed.credentials.token.root))
    with pytest.raises(ValidationError):
        AuditQuery(limit=101)
    with pytest.raises(FeatureNotEnabledError):
        await auth.otp.request_email_change(
            SecretStr(signed.credentials.token.root),
            RequestEmailChangeOtpRequest(new_email="new@example.com"),
        )


@pytest.mark.asyncio
async def test_verification_respects_bearer_delivery_policy(auth: FastAuth) -> None:
    from fastauth import email_password
    from fastauth.exceptions import InvalidRequestError
    from fastauth.plugins.email_password import EmailPasswordOptions

    restricted = FastAuth(
        auth.options, plugins=[email_password(EmailPasswordOptions(allow_bearer_tokens=False))]
    )
    captured: list[OtpGenerated] = []

    async def remember(event: OtpGenerated) -> None:
        captured.append(event)

    restricted.on(OtpGenerated)(remember)
    user = await restricted.api.create_user(email="restricted@example.com", password="Password123!")
    await restricted.verification.send(SendVerificationEmailRequest(email=user.email))
    token = SecretStr(captured[-1].plain)
    with pytest.raises(InvalidRequestError, match="bearer token delivery is disabled"):
        await restricted.verification.confirm(
            VerifyEmailRequest(email=user.email, token=token, delivery=BearerCredentialDelivery())
        )
    assert (
        await restricted.verification.confirm(VerifyEmailRequest(email=user.email, token=token))
    ).user.email_verified
