"""Email verification flow: send a token to a user's email, then verify it."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from urllib.parse import quote

from pydantic import ConfigDict, EmailStr, SecretStr

from fastauth.api.responses import authentication_response
from fastauth.domain.enums import EmailMessageKind, VerificationPurpose
from fastauth.domain.events import EmailVerificationSent, OtpGenerated, UserEmailVerified
from fastauth.domain.models import EmailMessage, Verification, WireModel
from fastauth.exceptions import TokenExpiredError, TokenInvalidError
from fastauth.flows.credentials import EmptyResponse, SessionResponse
from fastauth.runtime.context import AuthContext
from fastauth.security.sessions import SessionContext

__all__ = [
    "SendVerificationEmailRequest",
    "VerifyEmailRequest",
    "send_verification_email",
    "verify_email",
]


class SendVerificationEmailRequest(WireModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr
    redirect_url: str | None = None


class VerifyEmailRequest(WireModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr
    token: SecretStr


async def send_verification_email(
    context: AuthContext,
    request: SendVerificationEmailRequest,
    *,
    ip: str | None,
    user_agent: str | None,
) -> EmptyResponse:
    """Send a verification email; always returns success (anti-enumeration)."""
    user = await context.adapter.get_user_by_email(request.email)
    if user is None or user.email_verified:
        # Anti-enumeration: do not reveal account existence or verification state.
        return EmptyResponse(success=True)

    pair = context.token_service.generate_pair()
    ttl_minutes = context.config.email_verification.token_ttl_minutes
    await context.adapter.create_verification(
        Verification(
            identifier=user.email,
            value_hash=pair.hashed,
            purpose=VerificationPurpose.EMAIL_VERIFICATION,
            expires_at=datetime.now(UTC) + timedelta(minutes=ttl_minutes),
        ),
    )
    await context.event_bus.publish(
        OtpGenerated(
            identifier=user.email,
            purpose=VerificationPurpose.EMAIL_VERIFICATION.value,
            plain=pair.plain,
        ),
    )

    verify_url = (
        str(context.config.email_verification.base_verify_url)
        + f"?token={quote(pair.plain)}&email={quote(user.email)}"
    )
    html, text = context.template_renderer.render(
        "verification",
        {
            "verify_url": verify_url,
            "name": user.name,
            "expires_in_minutes": ttl_minutes,
        },
    )
    message = EmailMessage(
        kind=EmailMessageKind.VERIFICATION,
        to=user.email,
        subject=context.config.email.verification_subject,
        html=html,
        text=text,
    )
    await context.email_sender.send(message)
    await context.event_bus.publish(
        EmailVerificationSent(
            identifier=user.email,
            ip_address=ip,
            user_agent=user_agent,
        ),
    )
    return EmptyResponse(success=True)


async def verify_email(
    context: AuthContext,
    request: VerifyEmailRequest,
    *,
    ip: str | None,
    user_agent: str | None,
) -> tuple[SessionResponse, SessionContext]:
    """Verify a token, mark the user's email verified, and issue a fresh session."""
    token_hash = context.token_service.hash_only(request.token.get_secret_value())
    verification = await context.adapter.get_verification(
        request.email,
        VerificationPurpose.EMAIL_VERIFICATION,
        token_hash,
    )
    if verification is None:
        raise TokenInvalidError(message="invalid verification token")
    if verification.expires_at <= datetime.now(UTC):
        await context.adapter.delete_verification(verification.id)
        raise TokenExpiredError(message="verification token expired")

    user = await context.adapter.get_user_by_email(request.email)
    if user is None:
        # Identical error code to the not-found path above.
        raise TokenInvalidError(message="invalid verification token")

    user.email_verified = True
    user = await context.adapter.update_user(user)
    await context.adapter.delete_verifications_for_identifier(
        request.email,
        VerificationPurpose.EMAIL_VERIFICATION,
    )

    session_context = await context.session_strategy.create(
        user,
        ip=ip,
        user_agent=user_agent,
    )
    await context.event_bus.publish(
        UserEmailVerified(
            user_id=user.id,
            identifier=user.email,
            ip_address=ip,
            user_agent=user_agent,
        ),
    )
    return (authentication_response(user=user, session=session_context.session), session_context)
