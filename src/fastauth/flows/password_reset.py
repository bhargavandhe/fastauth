"""Password reset flow: forgot-password sends a token, reset-password applies it."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from urllib.parse import quote

from pydantic import ConfigDict, EmailStr, SecretStr

from fastauth.domain.enums import EmailMessageKind, ProviderId, VerificationPurpose
from fastauth.domain.events import (
    OtpGenerated,
    PasswordChanged,
    PasswordResetCompleted,
    PasswordResetRequested,
    SessionsRevokedAll,
)
from fastauth.domain.models import EmailMessage, Verification, WireModel
from fastauth.exceptions import TokenExpiredError, TokenInvalidError
from fastauth.flows.credentials import EmptyResponse, validate_password_policy
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


class ResetPasswordRequest(WireModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr
    token: SecretStr
    new_password: SecretStr


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
        return EmptyResponse(success=True)

    pair = context.token_service.generate_pair()
    ttl_minutes = context.config.password_reset.token_ttl_minutes
    await context.adapter.create_verification(
        Verification(
            identifier=user.email,
            value_hash=pair.hashed,
            purpose=VerificationPurpose.PASSWORD_RESET,
            expires_at=datetime.now(UTC) + timedelta(minutes=ttl_minutes),
        ),
    )
    await context.event_bus.publish(
        OtpGenerated(
            identifier=user.email,
            purpose=VerificationPurpose.PASSWORD_RESET.value,
            plain=pair.plain,
        ),
    )

    reset_url = (
        str(context.config.password_reset.base_reset_url)
        + f"?token={quote(pair.plain)}&email={quote(user.email)}"
    )
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
    await context.adapter.delete_verifications_for_identifier(
        request.email,
        VerificationPurpose.PASSWORD_RESET,
    )

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
