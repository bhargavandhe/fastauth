"""Project-wide string enumerations. Every closed set of strings lives here."""

from __future__ import annotations

from enum import StrEnum

__all__ = [
    "AuditEventType",
    "DatabaseBackendKind",
    "EmailMessageKind",
    "HookPhase",
    "JwtAlgorithm",
    "ProviderId",
    "RateLimitStorageKind",
    "SessionStrategyKind",
    "TokenType",
    "VerificationPurpose",
    "WireFormat",
]


class ProviderId(StrEnum):
    CREDENTIAL = "credential"
    EMAIL_OTP = "email-otp"


class VerificationPurpose(StrEnum):
    EMAIL_VERIFICATION = "email-verification"
    PASSWORD_RESET = "password-reset"  # noqa: S105
    EMAIL_CHANGE = "email-change"
    ACCOUNT_DELETION = "account-deletion"
    EMAIL_OTP_SIGN_IN = "email-otp-sign-in"
    EMAIL_OTP_VERIFICATION = "email-otp-verification"
    EMAIL_OTP_PASSWORD_RESET = "email-otp-password-reset"  # noqa: S105
    EMAIL_OTP_EMAIL_CHANGE = "email-otp-email-change"


class AuditEventType(StrEnum):
    USER_SIGNED_UP = "user_signed_up"
    USER_SIGNED_IN = "user_signed_in"
    USER_SIGNED_OUT = "user_signed_out"
    USER_EMAIL_VERIFIED = "user_email_verified"
    USER_UPDATED = "user_updated"
    USER_EMAIL_CHANGE_REQUESTED = "user_email_change_requested"
    USER_EMAIL_CHANGED = "user_email_changed"
    USER_DELETE_REQUESTED = "user_delete_requested"
    USER_DELETED = "user_deleted"
    SESSION_CREATED = "session_created"
    SESSION_REVOKED = "session_revoked"
    SESSIONS_REVOKED_ALL = "sessions_revoked_all"
    ACCOUNT_LINKED = "account_linked"
    ACCOUNT_UNLINKED = "account_unlinked"
    PASSWORD_CHANGED = "password_changed"  # noqa: S105
    PASSWORD_RESET_REQUESTED = "password_reset_requested"  # noqa: S105
    PASSWORD_RESET_COMPLETED = "password_reset_completed"  # noqa: S105
    EMAIL_VERIFICATION_SENT = "email_verification_sent"
    API_KEY_CREATED = "api_key_created"
    API_KEY_REVOKED = "api_key_revoked"
    API_KEY_VERIFIED_FAILED = "api_key_verified_failed"
    SECURITY_VELOCITY_EXCEEDED = "security_velocity_exceeded"
    ACCOUNT_LOCKED = "account_locked"
    OTP_REQUESTED = "otp_requested"
    OTP_VERIFIED = "otp_verified"
    OTP_VERIFY_FAILED = "otp_verify_failed"


class SessionStrategyKind(StrEnum):
    DATABASE = "database"
    JWT = "jwt"


class DatabaseBackendKind(StrEnum):
    MEMORY = "memory"
    MONGO = "mongo"
    POSTGRES = "postgres"


class WireFormat(StrEnum):
    """JSON casing convention applied to public request / response bodies.

    ``SNAKE`` (default) emits Pythonic ``snake_case`` field names — the
    historical and back-compat behaviour. ``CAMEL`` emits ``camelCase``
    (e.g. ``email_verified`` → ``emailVerified``, ``refresh_token`` →
    ``refreshToken``).

    Both casings are always **accepted** on input regardless of this
    setting — toggling only affects output.
    """

    SNAKE = "snake"
    CAMEL = "camel"


class TokenType(StrEnum):
    SESSION = "session"
    VERIFICATION = "verification"
    API_KEY = "api-key"


class HookPhase(StrEnum):
    BEFORE_CREATE = "before_create"
    AFTER_CREATE = "after_create"
    BEFORE_UPDATE = "before_update"
    AFTER_UPDATE = "after_update"
    BEFORE_DELETE = "before_delete"
    AFTER_DELETE = "after_delete"


class RateLimitStorageKind(StrEnum):
    MEMORY = "memory"
    DATABASE = "database"


class EmailMessageKind(StrEnum):
    VERIFICATION = "verification"
    PASSWORD_RESET = "password-reset"  # noqa: S105
    ACCOUNT_DELETION = "account-deletion"


class JwtAlgorithm(StrEnum):
    EDDSA = "EdDSA"
    ES256 = "ES256"
    RS256 = "RS256"
    PS256 = "PS256"
    ES512 = "ES512"
