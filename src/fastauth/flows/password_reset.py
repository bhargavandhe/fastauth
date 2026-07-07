"""Password reset flow: forgot-password sends a token, reset-password applies it."""

from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import urlencode

from pydantic import ConfigDict, EmailStr, SecretStr, field_validator

from fastauth.domain.enums import EmailMessageKind, ProviderId, VerificationPurpose
from fastauth.domain.events import (
    OtpGenerated,
    PasswordChanged,
    PasswordResetCompleted,
    PasswordResetRequested,
    SessionsRevokedAll,
)
from fastauth.domain.models import EmailMessage, Verification, WireModel
from fastauth.domain.value_objects import normalize_email
from fastauth.exceptions import TokenExpiredError, TokenInvalidError
from fastauth.flows.callbacks import resolve_callback_url
from fastauth.flows.credentials import EmptyResponse, validate_password_policy
from fastauth.plugins.email_password import email_password_options
from fastauth.runtime.context import AuthContext

__all__ = [
    "ForgotPasswordRequest",
    "ResetPasswordRequest",
    "forgot_password",
    "reset_password",
]


class ForgotPasswordRequest(WireModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr
    redirect_url: str | None = None

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email_value(cls, value: object) -> object:
        return normalize_email(value)


class ResetPasswordRequest(WireModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr
    token: SecretStr
    new_password: SecretStr

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email_value(cls, value: object) -> object:
        return normalize_email(value)


async def forgot_password(
    context: AuthContext,
    request: ForgotPasswordRequest,
    *,
    ip: str | None,
    user_agent: str | None,
) -> EmptyResponse:
    """Issue a reset token and email it; always returns success (anti-enumeration)."""
    user = await context.adapter.get_user_by_email(request.email)
    if user is None:
        # Anti-enumeration: do not reveal account existence.
        await context.event_bus.publish(
            PasswordResetRequested(
                identifier=request.email,
                ip_address=ip,
                user_agent=user_agent,
            ),
        )
        return EmptyResponse(success=True)

    pair = context.token_service.generate_pair()
    options = email_password_options(context)
    expires_in = (
        options.password_reset_expires_in
        if options is not None
        else context.config.password_reset.expires_in
    )
    ttl_minutes = max(1, int(expires_in.total_seconds() // 60))
    await context.adapter.create_verification(
        Verification(
            identifier=user.email,
            value_hash=pair.hashed,
            purpose=VerificationPurpose.PASSWORD_RESET,
            expires_at=datetime.now(UTC) + expires_in,
        ),
    )
    await context.event_bus.publish(
        OtpGenerated(
            identifier=user.email,
            purpose=VerificationPurpose.PASSWORD_RESET.value,
            plain=pair.plain,
        ),
    )

    params = {"token": pair.plain, "email": user.email}
    if request.redirect_url is not None:
        params["redirect_url"] = request.redirect_url
    reset_base_url = resolve_callback_url(
        app_base_url=context.config.app.base_url,
        callback_path=context.config.password_reset.callback_path,
        override=context.config.password_reset.callback_url_override,
    )
    reset_url = reset_base_url + "?" + urlencode(params)
    html, text = context.template_renderer.render(
        "reset",
        {
            "reset_url": reset_url,
            "name": user.name,
            "expires_in_minutes": ttl_minutes,
        },
    )
    message = EmailMessage(
        kind=EmailMessageKind.PASSWORD_RESET,
        to=user.email,
        subject=context.config.email.password_reset_subject,
        html=html,
        text=text,
    )
    await context.email_sender.send(message)
    await context.event_bus.publish(
        PasswordResetRequested(
            identifier=user.email,
            ip_address=ip,
            user_agent=user_agent,
        ),
    )
    return EmptyResponse(success=True)


async def reset_password(
    context: AuthContext,
    request: ResetPasswordRequest,
    *,
    ip: str | None,
    user_agent: str | None,
) -> EmptyResponse:
    """Verify the reset token, change the password, and revoke every active session."""
    token_hash = context.token_service.hash_only(request.token.get_secret_value())
    verification = await context.adapter.get_verification(
        request.email,
        VerificationPurpose.PASSWORD_RESET,
        token_hash,
    )
    if verification is None:
        raise TokenInvalidError(message="invalid reset token")
    if verification.expires_at <= datetime.now(UTC):
        await context.adapter.delete_verification(verification.id)
        raise TokenExpiredError(message="reset token expired")

    user = await context.adapter.get_user_by_email(request.email)
    if user is None:
        raise TokenInvalidError(message="invalid reset token")

    account = await context.adapter.get_account_for_user(user.id, ProviderId.CREDENTIAL)
    if account is None:
        raise TokenInvalidError(message="credential account not found")
    account.password = context.password_hasher.hash(
        validate_password_policy(context, request.new_password),
    )
    await context.adapter.update_account(account)

    revoked = await context.session_strategy.revoke_all(user.id)
    await context.refresh_token_service.revoke_for_user(user.id)
    await context.adapter.delete_verifications_for_identifier(
        request.email,
        VerificationPurpose.PASSWORD_RESET,
    )
    await context.lockout_tracker.reset(user.email)
    if user.username is not None:
        await context.lockout_tracker.reset(user.username)

    await context.event_bus.publish(
        PasswordChanged(
            user_id=user.id,
            ip_address=ip,
            user_agent=user_agent,
        ),
    )
    await context.event_bus.publish(
        PasswordResetCompleted(
            user_id=user.id,
            ip_address=ip,
            user_agent=user_agent,
        ),
    )
    if revoked:
        await context.event_bus.publish(
            SessionsRevokedAll(
                user_id=user.id,
                ip_address=ip,
                user_agent=user_agent,
            ),
        )
    return EmptyResponse(success=True)
