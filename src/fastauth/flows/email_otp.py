"""Email-OTP flows: send / check / sign-in / verify-email / password-reset / change-email.

The :class:`EmailOtpPlugin` thinly wraps these functions in HTTP route
handlers. Keeping the business logic here (rather than inside the plugin
file) mirrors the split between :mod:`fastauth.flows.credentials` and the
route handlers in :mod:`fastauth.web.fastapi`.

**Storage model.** Each issued OTP is persisted as a :class:`Verification`
row, keyed by ``(identifier, purpose, value_hash)`` where ``purpose`` is
one of the four ``EMAIL_OTP_*`` discriminator values and ``value_hash``
is the SHA-256 of the plaintext OTP. The plaintext is never persisted —
it lives only in the email body delivered to the user.

**Resend strategy.** This module implements only the "rotate" strategy:
issuing a fresh OTP discards every prior un-consumed OTP for the same
``(identifier, purpose)`` pair. The "reuse" strategy from better-auth
requires plaintext-recoverable storage and is not supported with hashed
storage.

**Lockout coupling.** Failed OTP attempts feed the same
:class:`AccountLockoutTracker` as failed password attempts. Five
failures across multiple OTPs in the lockout window will lock the
account just like five password failures would.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from pydantic import BaseModel, EmailStr, Field

from fastauth.config import FastAuthConfig
from fastauth.domain.enums import (
    EmailMessageKind,
    HookPhase,
    ProviderId,
    VerificationPurpose,
)
from fastauth.domain.events import (
    AccountLinked,
    EmailVerificationSent,
    OtpGenerated,
    OtpRequested,
    OtpVerified,
    OtpVerifyFailed,
    PasswordChanged,
    PasswordResetCompleted,
    PasswordResetRequested,
    SessionCreated,
    SessionsRevokedAll,
    UserEmailChanged,
    UserEmailChangeRequested,
    UserEmailVerified,
    UserSignedIn,
    UserSignedUp,
)
from fastauth.domain.models import Account, EmailMessage, User, Verification, WireModel
from fastauth.exceptions import (
    InvalidCredentialsError,
    NotFoundError,
    TokenExpiredError,
    TokenInvalidError,
)
from fastauth.flows.credentials import (
    EmptyResponse,
    SessionResponse,
    maybe_issue_refresh_token,
)
from fastauth.runtime.context import AuthContext
from fastauth.security.otp import OtpService
from fastauth.security.sessions import SessionContext

__all__ = [
    "ChangeEmailOtpRequest",
    "CheckOtpRequest",
    "EmailOtpConfig",
    "RequestEmailChangeOtpRequest",
    "RequestPasswordResetOtpRequest",
    "ResetPasswordOtpRequest",
    "SendOtpKind",
    "SendOtpRequest",
    "SignInOtpRequest",
    "VerifyEmailOtpRequest",
    "change_email_with_otp",
    "check_otp",
    "purpose_for_kind",
    "request_email_change_otp",
    "request_password_reset_otp",
    "reset_password_with_otp",
    "send_otp",
    "sign_in_with_otp",
    "verify_email_with_otp",
]


# --- Config (owned by the plugin, threaded through to flows) -----------------


class EmailOtpConfig(BaseModel):
    """Tunables for the email-OTP plugin.

    Defaults match better-auth: 6 digits, 5-minute expiry, 3 attempts per
    OTP. Auto-sign-up on first sign-in is enabled (set
    ``disable_sign_up=True`` for closed-membership applications).
    """

    length: int = 6
    expires_in_seconds: int = 300
    allowed_attempts: int = 3
    disable_sign_up: bool = False
    change_email_enabled: bool = False
    change_email_verify_current: bool = False


# --- Request payloads --------------------------------------------------------


# better-auth uses the strings "sign-in" / "email-verification" /
# "forget-password" as the discriminator. We keep those wire values
# verbatim for compatibility, then map them onto our internal
# ``VerificationPurpose`` enum at the boundary.
SendOtpKind = str  # one of: "sign-in" | "email-verification" | "password-reset"


def purpose_for_kind(kind: str) -> VerificationPurpose:
    """Map the wire-level OTP kind onto the internal ``VerificationPurpose``."""
    mapping = {
        "sign-in": VerificationPurpose.EMAIL_OTP_SIGN_IN,
        "email-verification": VerificationPurpose.EMAIL_OTP_VERIFICATION,
        "password-reset": VerificationPurpose.EMAIL_OTP_PASSWORD_RESET,
        # Accept better-auth's legacy spelling as a synonym.
        "forget-password": VerificationPurpose.EMAIL_OTP_PASSWORD_RESET,
    }
    if kind not in mapping:
        raise TokenInvalidError(message=f"unknown otp kind: {kind!r}")
    return mapping[kind]


class SendOtpRequest(WireModel):
    email: EmailStr
    type: str = Field(description="One of: sign-in | email-verification | password-reset")


class CheckOtpRequest(WireModel):
    email: EmailStr
    type: str
    otp: str


class SignInOtpRequest(WireModel):
    email: EmailStr
    otp: str
    name: str | None = None
    include_token: bool = False


class VerifyEmailOtpRequest(WireModel):
    email: EmailStr
    otp: str


class RequestPasswordResetOtpRequest(WireModel):
    email: EmailStr


class ResetPasswordOtpRequest(WireModel):
    email: EmailStr
    otp: str
    password: str = Field(min_length=8)


class RequestEmailChangeOtpRequest(WireModel):
    new_email: EmailStr
    otp_for_current: str | None = None


class ChangeEmailOtpRequest(WireModel):
    new_email: EmailStr
    otp: str


# --- Internal helpers --------------------------------------------------------


TEMPLATES_BY_PURPOSE: dict[VerificationPurpose, str] = {
    VerificationPurpose.EMAIL_OTP_SIGN_IN: "otp_sign_in",
    VerificationPurpose.EMAIL_OTP_VERIFICATION: "otp_verification",
    VerificationPurpose.EMAIL_OTP_PASSWORD_RESET: "otp_password_reset",
    VerificationPurpose.EMAIL_OTP_EMAIL_CHANGE: "otp_email_change",
}


SUBJECTS_BY_PURPOSE: dict[VerificationPurpose, str] = {
    VerificationPurpose.EMAIL_OTP_SIGN_IN: "Your sign-in code",
    VerificationPurpose.EMAIL_OTP_VERIFICATION: "Verify your email",
    VerificationPurpose.EMAIL_OTP_PASSWORD_RESET: "Reset your password",
    VerificationPurpose.EMAIL_OTP_EMAIL_CHANGE: "Confirm your email change",
}


KIND_BY_PURPOSE: dict[VerificationPurpose, EmailMessageKind] = {
    VerificationPurpose.EMAIL_OTP_SIGN_IN: EmailMessageKind.VERIFICATION,
    VerificationPurpose.EMAIL_OTP_VERIFICATION: EmailMessageKind.VERIFICATION,
    VerificationPurpose.EMAIL_OTP_PASSWORD_RESET: EmailMessageKind.PASSWORD_RESET,
    VerificationPurpose.EMAIL_OTP_EMAIL_CHANGE: EmailMessageKind.VERIFICATION,
}


async def issue_otp(
    context: AuthContext,
    *,
    config: EmailOtpConfig,
    otp_service: OtpService,
    identifier: str,
    purpose: VerificationPurpose,
    user_name: str | None,
    extra_template_vars: dict[str, str] | None = None,
) -> str:
    """Mint a new OTP, persist its hash, send the email, return the plaintext.

    Implements the "rotate" resend strategy: any pre-existing un-consumed
    OTPs for the same ``(identifier, purpose)`` pair are deleted first
    so only the newest code is valid.
    """
    await context.adapter.delete_verifications_for_identifier(identifier, purpose)
    pair = otp_service.generate_pair()
    expires_at = datetime.now(UTC) + timedelta(seconds=config.expires_in_seconds)
    await context.adapter.create_verification(
        Verification(
            identifier=identifier,
            value_hash=pair.hashed,
            purpose=purpose,
            expires_at=expires_at,
        ),
    )

    template_name = TEMPLATES_BY_PURPOSE[purpose]
    template_vars: dict[str, str] = {
        "otp": pair.plain,
        "name": user_name or "",
        "expires_in_minutes": str(max(1, config.expires_in_seconds // 60)),
    }
    if extra_template_vars:
        template_vars.update(extra_template_vars)
    html, text = context.template_renderer.render(template_name, template_vars)

    await context.email_sender.send(
        EmailMessage(
            kind=KIND_BY_PURPOSE[purpose],
            to=identifier,
            subject=SUBJECTS_BY_PURPOSE[purpose],
            html=html,
            text=text,
        ),
    )

    # Two events: OtpGenerated carries the plaintext (consumed by
    # TestUtilsPlugin); OtpRequested is the audit-safe twin without
    # plaintext, so AuditLogsPlugin can persist it without leaking codes.
    await context.event_bus.publish(
        OtpGenerated(identifier=identifier, purpose=purpose.value, plain=pair.plain),
    )
    await context.event_bus.publish(
        OtpRequested(identifier=identifier, purpose=purpose.value),
    )
    return pair.plain


async def consume_otp(
    context: AuthContext,
    *,
    config: EmailOtpConfig,
    otp_service: OtpService,
    identifier: str,
    purpose: VerificationPurpose,
    plain_otp: str,
    feed_lockout: bool,
) -> Verification:
    """Verify ``plain_otp``, increment the attempt counter on miss, return the row.

    On success the row is **deleted** before this function returns
    (one-time-use). The caller can rely on the returned row's fields but
    must not attempt further reads against the same id.

    On miss the row's ``attempt_count`` is bumped. When it equals or
    exceeds ``config.allowed_attempts`` the row is deleted and a fresh
    OTP is required.

    When ``feed_lockout=True`` (the default for sign-in / verify-email /
    reset / change-email) every miss is also fed to
    ``AccountLockoutTracker`` so password-style velocity protection
    applies. ``check_otp`` (the optional pre-check endpoint) sets this
    to ``False`` so a UX double-check doesn't trigger lockout.
    """
    row = await context.adapter.get_active_verification(identifier, purpose)
    if row is None:
        if feed_lockout:
            await context.lockout_tracker.record_failure(identifier)
        await context.event_bus.publish(
            OtpVerifyFailed(identifier=identifier, purpose=purpose.value, attempt_count=0),
        )
        raise TokenInvalidError(message="no active otp for this email")

    if row.expires_at <= datetime.now(UTC):
        await context.adapter.delete_verification(row.id)
        if feed_lockout:
            await context.lockout_tracker.record_failure(identifier)
        await context.event_bus.publish(
            OtpVerifyFailed(
                identifier=identifier,
                purpose=purpose.value,
                attempt_count=row.attempt_count,
            ),
        )
        raise TokenExpiredError(message="otp expired")

    if not otp_service.verify_match(plain_otp, row.value_hash):
        row.attempt_count += 1
        if row.attempt_count >= config.allowed_attempts:
            # Burned. Delete; user must request a fresh one.
            await context.adapter.delete_verification(row.id)
        else:
            await context.adapter.update_verification(row)
        if feed_lockout:
            await context.lockout_tracker.record_failure(identifier)
        await context.event_bus.publish(
            OtpVerifyFailed(
                identifier=identifier,
                purpose=purpose.value,
                attempt_count=row.attempt_count,
            ),
        )
        raise TokenInvalidError(message="incorrect otp")

    # Success — delete the row (one-time-use) and reset lockout for this
    # identifier so a successful sign-in clears any partial-failure state.
    await context.adapter.delete_verification(row.id)
    if feed_lockout:
        await context.lockout_tracker.reset(identifier)
    return row


# --- Top-level flows ---------------------------------------------------------


async def send_otp(
    context: AuthContext,
    request: SendOtpRequest,
    *,
    config: EmailOtpConfig,
    otp_service: OtpService,
    ip: str | None,
    user_agent: str | None,
) -> EmptyResponse:
    """Issue an OTP for the given (email, kind) pair. Always returns success.

    For ``sign-in`` we send the OTP regardless of whether the user
    exists, because auto-sign-up is enabled by default and a non-existent
    user is a legitimate first-time-signup recipient. When
    ``disable_sign_up=True`` AND the user doesn't exist we still return
    success but skip the email — anti-enumeration.
    """
    purpose = purpose_for_kind(request.type)
    user = await context.adapter.get_user_by_email(request.email)

    if purpose is VerificationPurpose.EMAIL_OTP_SIGN_IN:
        if user is None and config.disable_sign_up:
            # Anti-enumeration: silently succeed without sending.
            return EmptyResponse(success=True)
    elif user is None:
        # email-verification / password-reset target an existing user.
        # Anti-enumeration: silently succeed.
        return EmptyResponse(success=True)

    await issue_otp(
        context,
        config=config,
        otp_service=otp_service,
        identifier=request.email,
        purpose=purpose,
        user_name=user.name if user else None,
    )
    if purpose is VerificationPurpose.EMAIL_OTP_VERIFICATION:
        await context.event_bus.publish(
            EmailVerificationSent(
                identifier=request.email,
                ip_address=ip,
                user_agent=user_agent,
            ),
        )
    return EmptyResponse(success=True)


async def check_otp(
    context: AuthContext,
    request: CheckOtpRequest,
    *,
    config: EmailOtpConfig,
    otp_service: OtpService,
) -> EmptyResponse:
    """Verify an OTP **without consuming it**. Used as a UX pre-check.

    The lockout tracker is NOT fed here (a UX-double-check shouldn't
    contribute to a lockout). Attempt counts ARE bumped — better-auth
    behaves the same way; otherwise an attacker could brute-force this
    endpoint with no per-OTP cap.

    On success: returns ``{"success": true}`` and the row is left
    untouched so the actual sign-in / verify-email / reset endpoint can
    consume it next.
    """
    purpose = purpose_for_kind(request.type)
    row = await context.adapter.get_active_verification(request.email, purpose)
    if row is None:
        raise TokenInvalidError(message="no active otp for this email")
    if row.expires_at <= datetime.now(UTC):
        await context.adapter.delete_verification(row.id)
        raise TokenExpiredError(message="otp expired")
    if not otp_service.verify_match(request.otp, row.value_hash):
        row.attempt_count += 1
        if row.attempt_count >= config.allowed_attempts:
            await context.adapter.delete_verification(row.id)
        else:
            await context.adapter.update_verification(row)
        raise TokenInvalidError(message="incorrect otp")
    return EmptyResponse(success=True)


async def sign_in_with_otp(
    context: AuthContext,
    request: SignInOtpRequest,
    *,
    config: EmailOtpConfig,
    otp_service: OtpService,
    ip: str | None,
    user_agent: str | None,
) -> tuple[SessionResponse, SessionContext]:
    """Consume an OTP and return a fresh session. Auto-registers new users.

    When the email doesn't match an existing user AND
    ``config.disable_sign_up=False`` (the default), a new user is
    created with no password and an ``Account`` row tied to
    ``ProviderId.EMAIL_OTP``. Email is marked verified because OTP
    delivery proves ownership.

    When ``disable_sign_up=True`` and the user doesn't exist, this raises
    ``InvalidCredentialsError`` — consistent with better-auth.
    """
    await context.lockout_tracker.check_locked(request.email)
    user = await context.adapter.get_user_by_email(request.email)
    is_new_user = user is None
    if user is None and config.disable_sign_up:
        # Even though there's no user, still record the failure so an
        # attacker iterating emails sees uniform timing.
        await context.lockout_tracker.record_failure(request.email)
        raise InvalidCredentialsError()
    await consume_otp(
        context,
        config=config,
        otp_service=otp_service,
        identifier=request.email,
        purpose=VerificationPurpose.EMAIL_OTP_SIGN_IN,
        plain_otp=request.otp,
        feed_lockout=True,
    )

    if user is None:
        # Auto-register. Email is verified because we just proved
        # the user controls it.
        new_user = User(
            email=request.email,
            name=request.name,
            email_verified=True,
        )
        new_user = await context.hooks.run(
            HookPhase.BEFORE_CREATE,
            "user",
            new_user,
            actor_user_id=None,
        )
        new_user = await context.adapter.create_user(new_user)
        await context.hooks.run(
            HookPhase.AFTER_CREATE,
            "user",
            new_user,
            actor_user_id=new_user.id,
        )
        await context.adapter.create_account(
            Account(
                user_id=new_user.id,
                provider_id=ProviderId.EMAIL_OTP,
                account_id=new_user.id,
                password=None,  # OTP-only account; password may be added later
            ),
        )
        await context.event_bus.publish(
            UserSignedUp(
                user_id=new_user.id,
                identifier=new_user.email,
                ip_address=ip,
                user_agent=user_agent,
            ),
        )
        await context.event_bus.publish(
            AccountLinked(
                user_id=new_user.id,
                provider_id=ProviderId.EMAIL_OTP.value,
                ip_address=ip,
                user_agent=user_agent,
            ),
        )
        user = new_user
    elif not user.email_verified:
        # Existing user signing in via OTP for the first time. The OTP
        # delivery proves email ownership — flip the flag.
        user.email_verified = True
        user = await context.adapter.update_user(user)

    session_context = await context.session_strategy.create(user, ip=ip, user_agent=user_agent)

    if not is_new_user:
        await context.event_bus.publish(
            UserSignedIn(
                user_id=user.id,
                identifier=user.email,
                ip_address=ip,
                user_agent=user_agent,
            ),
        )
    await context.event_bus.publish(
        SessionCreated(
            user_id=user.id,
            session_id=session_context.session.id,
            ip_address=ip,
            user_agent=user_agent,
        ),
    )
    await context.event_bus.publish(
        OtpVerified(
            identifier=request.email,
            purpose=VerificationPurpose.EMAIL_OTP_SIGN_IN.value,
            user_id=user.id,
        ),
    )

    refresh_plain = await maybe_issue_refresh_token(
        context,
        user_id=user.id,
        include_token=request.include_token,
        ip=ip,
        user_agent=user_agent,
    )
    return (
        SessionResponse(
            user=user,
            session=session_context.session,
            token=session_context.token if request.include_token else None,
            refresh_token=refresh_plain,
        ),
        session_context,
    )


async def verify_email_with_otp(
    context: AuthContext,
    request: VerifyEmailOtpRequest,
    *,
    config: EmailOtpConfig,
    otp_service: OtpService,
    ip: str | None,
    user_agent: str | None,
) -> EmptyResponse:
    """Consume an OTP and mark the user's email as verified.

    Anti-enumeration on the missing-user case: returns success without
    consuming any state. This is consistent with the token-based
    ``/auth/verify-email`` flow.
    """
    user = await context.adapter.get_user_by_email(request.email)
    if user is None:
        raise TokenInvalidError(message="invalid otp")
    await consume_otp(
        context,
        config=config,
        otp_service=otp_service,
        identifier=request.email,
        purpose=VerificationPurpose.EMAIL_OTP_VERIFICATION,
        plain_otp=request.otp,
        feed_lockout=True,
    )
    if not user.email_verified:
        user.email_verified = True
        await context.adapter.update_user(user)
    await context.event_bus.publish(
        UserEmailVerified(
            user_id=user.id,
            identifier=user.email,
            ip_address=ip,
            user_agent=user_agent,
        ),
    )
    await context.event_bus.publish(
        OtpVerified(
            identifier=request.email,
            purpose=VerificationPurpose.EMAIL_OTP_VERIFICATION.value,
            user_id=user.id,
        ),
    )
    return EmptyResponse(success=True)


async def request_password_reset_otp(
    context: AuthContext,
    request: RequestPasswordResetOtpRequest,
    *,
    config: EmailOtpConfig,
    otp_service: OtpService,
    ip: str | None,
    user_agent: str | None,
) -> EmptyResponse:
    user = await context.adapter.get_user_by_email(request.email)
    if user is None:
        # Anti-enumeration.
        return EmptyResponse(success=True)
    await issue_otp(
        context,
        config=config,
        otp_service=otp_service,
        identifier=request.email,
        purpose=VerificationPurpose.EMAIL_OTP_PASSWORD_RESET,
        user_name=user.name,
    )
    await context.event_bus.publish(
        PasswordResetRequested(
            identifier=user.email,
            ip_address=ip,
            user_agent=user_agent,
        ),
    )
    return EmptyResponse(success=True)


async def reset_password_with_otp(
    context: AuthContext,
    request: ResetPasswordOtpRequest,
    *,
    config: EmailOtpConfig,
    otp_service: OtpService,
    ip: str | None,
    user_agent: str | None,
) -> EmptyResponse:
    user = await context.adapter.get_user_by_email(request.email)
    if user is None:
        raise TokenInvalidError(message="invalid otp")
    await consume_otp(
        context,
        config=config,
        otp_service=otp_service,
        identifier=request.email,
        purpose=VerificationPurpose.EMAIL_OTP_PASSWORD_RESET,
        plain_otp=request.otp,
        feed_lockout=True,
    )
    new_hash = context.password_hasher.hash(request.password)
    account = await context.adapter.get_account_for_user(user.id, ProviderId.CREDENTIAL)
    if account is None:
        # User signed up via OTP and never set a password. Create the
        # credential account row now.
        await context.adapter.create_account(
            Account(
                user_id=user.id,
                provider_id=ProviderId.CREDENTIAL,
                account_id=user.id,
                password=new_hash,
            ),
        )
    else:
        account.password = new_hash
        await context.adapter.update_account(account)
    revoked = await context.session_strategy.revoke_all(user.id)
    await context.event_bus.publish(
        PasswordChanged(user_id=user.id, ip_address=ip, user_agent=user_agent),
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
            SessionsRevokedAll(user_id=user.id),
        )
    await context.event_bus.publish(
        OtpVerified(
            identifier=request.email,
            purpose=VerificationPurpose.EMAIL_OTP_PASSWORD_RESET.value,
            user_id=user.id,
        ),
    )
    return EmptyResponse(success=True)


async def request_email_change_otp(
    context: AuthContext,
    user: User,
    request: RequestEmailChangeOtpRequest,
    *,
    auth_config: FastAuthConfig,
    config: EmailOtpConfig,
    otp_service: OtpService,
    ip: str | None,
    user_agent: str | None,
) -> EmptyResponse:
    """Send an OTP to the user's *new* email address.

    When ``config.change_email_verify_current=True`` the caller must
    first send themselves an OTP via the regular send-otp flow (with
    ``type=email-verification``) and pass that OTP as
    ``otp_for_current``. We verify it here before sending the new-email
    OTP. This double-confirm protects against an attacker who has
    transient access to a logged-in session.

    Duplicate-email + same-as-current-email checks match the
    token-based change-email flow (:mod:`fastauth.flows.change_email`).
    """
    if not config.change_email_enabled:
        raise NotFoundError(resource="change_email_otp_endpoint")
    if request.new_email == user.email:
        raise TokenInvalidError(message="new email matches current email")
    existing = await context.adapter.get_user_by_email(request.new_email)
    if existing is not None and existing.id != user.id:
        raise TokenInvalidError(message="new email already in use")

    if config.change_email_verify_current:
        if request.otp_for_current is None:
            raise InvalidCredentialsError()
        # Consume the verification OTP sent to the *current* email.
        await consume_otp(
            context,
            config=config,
            otp_service=otp_service,
            identifier=user.email,
            purpose=VerificationPurpose.EMAIL_OTP_VERIFICATION,
            plain_otp=request.otp_for_current,
            feed_lockout=True,
        )

    user.pending_email_change = request.new_email
    await context.adapter.update_user(user)
    await issue_otp(
        context,
        config=config,
        otp_service=otp_service,
        identifier=request.new_email,
        purpose=VerificationPurpose.EMAIL_OTP_EMAIL_CHANGE,
        user_name=user.name,
        extra_template_vars={"new_email": request.new_email},
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


async def change_email_with_otp(
    context: AuthContext,
    user: User,
    request: ChangeEmailOtpRequest,
    *,
    config: EmailOtpConfig,
    otp_service: OtpService,
    ip: str | None,
    user_agent: str | None,
) -> EmptyResponse:
    if not config.change_email_enabled:
        raise NotFoundError(resource="change_email_otp_endpoint")
    if user.pending_email_change != request.new_email:
        raise TokenInvalidError(message="no pending change for this email")
    await consume_otp(
        context,
        config=config,
        otp_service=otp_service,
        identifier=request.new_email,
        purpose=VerificationPurpose.EMAIL_OTP_EMAIL_CHANGE,
        plain_otp=request.otp,
        feed_lockout=True,
    )

    old_email = user.email
    user.email = request.new_email
    user.email_verified = True
    user.pending_email_change = None
    await context.adapter.update_user(user)
    await context.event_bus.publish(
        UserEmailChanged(
            user_id=user.id,
            identifier=request.new_email,
            previous_email=old_email,
            ip_address=ip,
            user_agent=user_agent,
        ),
    )
    await context.event_bus.publish(
        OtpVerified(
            identifier=request.new_email,
            purpose=VerificationPurpose.EMAIL_OTP_EMAIL_CHANGE.value,
            user_id=user.id,
        ),
    )
    return EmptyResponse(success=True)
