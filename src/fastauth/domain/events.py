"""Typed event bus and the AuthEvent hierarchy."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from fastauth.domain.enums import AuditEventType
from fastauth.domain.models import new_id

__all__ = [
    "AccountLinked",
    "AccountLockedOut",
    "AccountUnlinked",
    "ApiKeyCreated",
    "ApiKeyRevoked",
    "ApiKeyVerifyFailed",
    "AuthEvent",
    "EmailVerificationSent",
    "OtpGenerated",
    "OtpRequested",
    "OtpVerified",
    "OtpVerifyFailed",
    "PasswordChanged",
    "PasswordResetCompleted",
    "PasswordResetRequested",
    "RateLimitExceeded",
    "SessionCreated",
    "SessionRevoked",
    "SessionsRevokedAll",
    "UserDeleteRequested",
    "UserDeleted",
    "UserEmailChangeRequested",
    "UserEmailChanged",
    "UserEmailVerified",
    "UserSignedIn",
    "UserSignedOut",
    "UserSignedUp",
    "UserUpdated",
]


class AuthEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_id: str = Field(default_factory=new_id)
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    audit_event_type: AuditEventType
    ip_address: str | None = None
    user_agent: str | None = None
    extra: dict[str, JsonValue] = Field(default_factory=dict)


class UserSignedUp(AuthEvent):
    audit_event_type: AuditEventType = AuditEventType.USER_SIGNED_UP
    user_id: str
    identifier: str


class UserSignedIn(AuthEvent):
    audit_event_type: AuditEventType = AuditEventType.USER_SIGNED_IN
    user_id: str
    identifier: str


class UserSignedOut(AuthEvent):
    audit_event_type: AuditEventType = AuditEventType.USER_SIGNED_OUT
    user_id: str


class UserEmailVerified(AuthEvent):
    audit_event_type: AuditEventType = AuditEventType.USER_EMAIL_VERIFIED
    user_id: str
    identifier: str


class UserUpdated(AuthEvent):
    audit_event_type: AuditEventType = AuditEventType.USER_UPDATED
    user_id: str
    changed_fields: list[str]


class UserEmailChangeRequested(AuthEvent):
    audit_event_type: AuditEventType = AuditEventType.USER_EMAIL_CHANGE_REQUESTED
    user_id: str
    identifier: str  # OLD email at request time
    new_email: str


class UserEmailChanged(AuthEvent):
    audit_event_type: AuditEventType = AuditEventType.USER_EMAIL_CHANGED
    user_id: str
    identifier: str  # NEW email after change
    previous_email: str


class UserDeleted(AuthEvent):
    audit_event_type: AuditEventType = AuditEventType.USER_DELETED
    user_id: str


class UserDeleteRequested(AuthEvent):
    audit_event_type: AuditEventType = AuditEventType.USER_DELETE_REQUESTED
    user_id: str
    identifier: str


class SessionCreated(AuthEvent):
    audit_event_type: AuditEventType = AuditEventType.SESSION_CREATED
    user_id: str
    session_id: str


class SessionRevoked(AuthEvent):
    audit_event_type: AuditEventType = AuditEventType.SESSION_REVOKED
    user_id: str
    session_id: str


class SessionsRevokedAll(AuthEvent):
    audit_event_type: AuditEventType = AuditEventType.SESSIONS_REVOKED_ALL
    user_id: str


class AccountLinked(AuthEvent):
    audit_event_type: AuditEventType = AuditEventType.ACCOUNT_LINKED
    user_id: str
    provider_id: str


class AccountUnlinked(AuthEvent):
    audit_event_type: AuditEventType = AuditEventType.ACCOUNT_UNLINKED
    user_id: str
    provider_id: str


class PasswordChanged(AuthEvent):
    audit_event_type: AuditEventType = AuditEventType.PASSWORD_CHANGED
    user_id: str


class PasswordResetRequested(AuthEvent):
    audit_event_type: AuditEventType = AuditEventType.PASSWORD_RESET_REQUESTED
    identifier: str


class PasswordResetCompleted(AuthEvent):
    audit_event_type: AuditEventType = AuditEventType.PASSWORD_RESET_COMPLETED
    user_id: str


class EmailVerificationSent(AuthEvent):
    audit_event_type: AuditEventType = AuditEventType.EMAIL_VERIFICATION_SENT
    identifier: str


class OtpGenerated(AuthEvent):
    audit_event_type: AuditEventType = AuditEventType.EMAIL_VERIFICATION_SENT
    identifier: str
    purpose: str
    plain: str


class OtpRequested(AuthEvent):
    """Audit-safe event emitted whenever an OTP is issued. Carries no plaintext."""

    audit_event_type: AuditEventType = AuditEventType.OTP_REQUESTED
    identifier: str
    purpose: str


class OtpVerified(AuthEvent):
    """Audit-safe event emitted on a successful OTP verification."""

    audit_event_type: AuditEventType = AuditEventType.OTP_VERIFIED
    identifier: str
    purpose: str
    user_id: str | None = None


class OtpVerifyFailed(AuthEvent):
    """Audit-safe event emitted on a failed OTP verification."""

    audit_event_type: AuditEventType = AuditEventType.OTP_VERIFY_FAILED
    identifier: str
    purpose: str
    attempt_count: int


class ApiKeyCreated(AuthEvent):
    audit_event_type: AuditEventType = AuditEventType.API_KEY_CREATED
    user_id: str
    api_key_id: str


class ApiKeyRevoked(AuthEvent):
    audit_event_type: AuditEventType = AuditEventType.API_KEY_REVOKED
    user_id: str
    api_key_id: str


class ApiKeyVerifyFailed(AuthEvent):
    audit_event_type: AuditEventType = AuditEventType.API_KEY_VERIFIED_FAILED
    identifier: str | None = None


class RateLimitExceeded(AuthEvent):
    audit_event_type: AuditEventType = AuditEventType.SECURITY_VELOCITY_EXCEEDED
    identifier: str
    path: str


class AccountLockedOut(AuthEvent):
    audit_event_type: AuditEventType = AuditEventType.ACCOUNT_LOCKED
    identifier: str
    retry_after_seconds: int
