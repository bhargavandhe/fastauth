"""Authenticated change-email flow with reverification.

Two-step:

1. ``POST /auth/change-email/request`` — authenticated. The caller provides
   their password and the proposed new email. We verify the password, check
   that the new email is not already taken, set ``user.pending_email_change``
   to the new address, and send a verification token to the NEW address. The
   user keeps seeing their OLD email in ``auth.get_current_user`` until the
   change is confirmed.

2. ``POST /auth/change-email/confirm`` — token-based. The caller submits the
   token they received in the email. We validate the token + identifier
   (= new email), apply ``user.email = new_email``, clear
   ``pending_email_change``, and emit ``UserEmailChanged``. The user's
   sessions remain valid; only the email address changes.

If a race causes the new email to be taken between request and confirm,
confirm returns ``DUPLICATE`` (409). The pending change is cleared so the
user can try a different address.
"""

from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import quote

from pydantic import ConfigDict, EmailStr, SecretStr, field_validator

from fastauth.domain.enums import EmailMessageKind, ProviderId, VerificationPurpose
from fastauth.domain.events import UserEmailChanged, UserEmailChangeRequested
from fastauth.domain.models import EmailMessage, User, Verification, WireModel
from fastauth.domain.value_objects import normalize_email
from fastauth.exceptions import (
    DuplicateError,
    InvalidCredentialsError,
    NotFoundError,
    TokenExpiredError,
    TokenInvalidError,
)
from fastauth.flows.callbacks import resolve_callback_url
from fastauth.flows.credentials import EmptyResponse
from fastauth.runtime.context import AuthContext

__all__ = [
    "ConfirmEmailChangeRequest",
    "RequestEmailChangeRequest",
    "confirm_email_change",
    "request_email_change",
]


class RequestEmailChangeRequest(WireModel):
    """Authenticated request to begin the email-change flow."""

    model_config = ConfigDict(extra="forbid")
    new_email: EmailStr
    password: SecretStr

    @field_validator("new_email", mode="before")
    @classmethod
    def normalize_new_email_value(cls, value: object) -> object:
        return normalize_email(value)


class ConfirmEmailChangeRequest(WireModel):
    """Token-based request to finalise the email change."""

    model_config = ConfigDict(extra="forbid")
    new_email: EmailStr
    token: SecretStr

    @field_validator("new_email", mode="before")
    @classmethod
    def normalize_new_email_value(cls, value: object) -> object:
        return normalize_email(value)


async def request_email_change(
    context: AuthContext,
    user: User,
    request: RequestEmailChangeRequest,
    *,
    ip: str | None,
    user_agent: str | None,
) -> EmptyResponse:
    if request.new_email.lower() == user.email.lower():
        # Already on this address. Anti-enumeration: succeed silently.
        return EmptyResponse(success=True)

    # Validate that the credential exists and the password matches.
    account = await context.adapter.get_account_for_user(user.id, ProviderId.CREDENTIAL)
    if account is None or account.password is None:
        raise NotFoundError(resource="credential_account")
    if not context.password_hasher.verify(request.password.get_secret_value(), account.password):
        raise InvalidCredentialsError()

    # Check that no other user is using the address. Race is possible; we
    # re-check on confirm.
    existing = await context.adapter.get_user_by_email(request.new_email)
    if existing is not None and existing.id != user.id:
        raise DuplicateError(resource="user", field="email")

    # Store the pending change on the user record so the application can
    # display "verification pending: new@example.com" if desired.
    user.pending_email_change = request.new_email
    await context.adapter.update_user(user)

    # Create the verification record keyed by the NEW email so the confirm
    # endpoint can look it up.
    expires_in = context.config.email_change.expires_in
    ttl_minutes = max(1, int(expires_in.total_seconds() // 60))
    pair = context.token_service.generate_pair()
    await context.adapter.create_verification(
        Verification(
            identifier=request.new_email,
            value_hash=pair.hashed,
            purpose=VerificationPurpose.EMAIL_CHANGE,
            expires_at=datetime.now(UTC) + expires_in,
        ),
    )

    # Build the confirm URL and send the email to the NEW address.
    confirm_base_url = resolve_callback_url(
        app_base_url=context.config.app.base_url,
        callback_path=context.config.email_change.callback_path,
        override=context.config.email_change.callback_url_override,
    )
    confirm_url = (
        confirm_base_url + f"?token={quote(pair.plain)}&new_email={quote(request.new_email)}"
    )
    # We reuse the verification template — it shows a verify URL + recipient
    # name and is structurally identical to "click to confirm this email".
    html, text = context.template_renderer.render(
        "verification",
        {
            "verify_url": confirm_url,
            "name": user.name,
            "expires_in_minutes": ttl_minutes,
        },
    )
    await context.email_sender.send(
        EmailMessage(
            kind=EmailMessageKind.VERIFICATION,
            to=request.new_email,
            subject=context.config.email_change.subject,
            html=html,
            text=text,
        ),
    )

    await context.event_bus.publish(
        UserEmailChangeRequested(
            user_id=user.id,
            identifier=user.email,
            new_email=request.new_email,
            ip_address=ip,
            user_agent=user_agent,
        ),
    )
    return EmptyResponse(success=True)


async def confirm_email_change(
    context: AuthContext,
    request: ConfirmEmailChangeRequest,
    *,
    ip: str | None,
    user_agent: str | None,
) -> EmptyResponse:
    token_hash = context.token_service.hash_only(request.token.get_secret_value())
    verification = await context.adapter.get_verification(
        request.new_email,
        VerificationPurpose.EMAIL_CHANGE,
        token_hash,
    )
    if verification is None:
        raise TokenInvalidError(message="invalid email-change token")
    if verification.expires_at <= datetime.now(UTC):
        await context.adapter.delete_verification(verification.id)
        raise TokenExpiredError(message="email-change token expired")

    # Find the user whose pending change matches. We don't trust the request
    # to identify the user; we look up by pending_email_change instead.
    candidates = await context.adapter.find_user_by_pending_email_change(request.new_email)
    if candidates is None:
        raise TokenInvalidError(message="no pending email change matches this token")

    # Race re-check: another user may have grabbed the address in the meantime.
    other = await context.adapter.get_user_by_email(request.new_email)
    if other is not None and other.id != candidates.id:
        candidates.pending_email_change = None
        await context.adapter.update_user(candidates)
        await context.adapter.delete_verifications_for_identifier(
            request.new_email,
            VerificationPurpose.EMAIL_CHANGE,
        )
        raise DuplicateError(resource="user", field="email")

    previous_email = candidates.email
    candidates.email = request.new_email
    candidates.pending_email_change = None
    # The user has proved possession of the new address; mark it verified.
    candidates.email_verified = True
    await context.adapter.update_user(candidates)
    await context.adapter.delete_verifications_for_identifier(
        request.new_email,
        VerificationPurpose.EMAIL_CHANGE,
    )
    await context.lockout_tracker.reset(request.new_email)

    await context.event_bus.publish(
        UserEmailChanged(
            user_id=candidates.id,
            identifier=request.new_email,
            previous_email=previous_email,
            ip_address=ip,
            user_agent=user_agent,
        ),
    )
    return EmptyResponse(success=True)
