"""Public exception hierarchy for fastauth."""

from __future__ import annotations

from http import HTTPStatus

__all__ = [
    "EXCEPTION_HTTP_STATUS",
    "AccountLockedError",
    "AdapterError",
    "AdapterFeatureUnsupportedError",
    "AuthenticationError",
    "ConfigError",
    "CsrfError",
    "DuplicateError",
    "EmailNotVerifiedError",
    "FastAuthError",
    "HookAbortError",
    "InvalidCredentialsError",
    "JwksDecryptionError",
    "NotFoundError",
    "PasswordAlreadySetError",
    "RateLimitError",
    "RefreshTokenReuseError",
    "SessionExpiredError",
    "TokenExpiredError",
    "TokenInvalidError",
    "VerificationError",
]


class FastAuthError(Exception):
    """Base class for every error raised by fastauth."""

    default_code: str = "FASTAUTH_ERROR"

    def __init__(self, *, code: str | None = None, message: str = "") -> None:
        self.code = code or self.default_code
        self.message = message or self.code
        super().__init__(self.message)


class ConfigError(FastAuthError):
    default_code = "CONFIG_ERROR"


class AdapterError(FastAuthError):
    default_code = "ADAPTER_ERROR"


class AdapterFeatureUnsupportedError(AdapterError):
    default_code = "ADAPTER_FEATURE_UNSUPPORTED"

    def __init__(self, *, feature: str) -> None:
        super().__init__(message=f"adapter does not support {feature}")


class NotFoundError(AdapterError):
    default_code = "NOT_FOUND"

    def __init__(self, *, resource: str, code: str | None = None) -> None:
        super().__init__(code=code, message=f"{resource} not found")


class DuplicateError(AdapterError):
    default_code = "DUPLICATE"

    def __init__(self, *, resource: str, field: str, code: str | None = None) -> None:
        super().__init__(code=code, message=f"{resource} with duplicate {field}")


class PasswordAlreadySetError(FastAuthError):
    default_code = "PASSWORD_ALREADY_SET"

    def __init__(self) -> None:
        super().__init__(message="password is already set")


class AuthenticationError(FastAuthError):
    default_code = "AUTHENTICATION_ERROR"


class InvalidCredentialsError(AuthenticationError):
    default_code = "INVALID_CREDENTIALS"

    def __init__(self) -> None:
        super().__init__(message="invalid email or password")


class EmailNotVerifiedError(AuthenticationError):
    default_code = "EMAIL_NOT_VERIFIED"

    def __init__(self) -> None:
        super().__init__(message="email is not verified")


class SessionExpiredError(AuthenticationError):
    default_code = "SESSION_EXPIRED"


class RateLimitError(FastAuthError):
    default_code = "RATE_LIMITED"

    def __init__(self, *, retry_after_seconds: int) -> None:
        super().__init__(message=f"rate limited, retry in {retry_after_seconds}s")
        self.retry_after_seconds = retry_after_seconds


class VerificationError(FastAuthError):
    default_code = "VERIFICATION_ERROR"


class TokenInvalidError(VerificationError):
    default_code = "TOKEN_INVALID"


class TokenExpiredError(VerificationError):
    default_code = "TOKEN_EXPIRED"


class HookAbortError(FastAuthError):
    default_code = "HOOK_ABORT"


class CsrfError(FastAuthError):
    default_code = "CSRF_FORBIDDEN"


class AccountLockedError(AuthenticationError):
    """Raised when an identifier has too many recent failed sign-in attempts.

    Carries ``retry_after_seconds`` so the FastAPI exception handler can
    populate the ``Retry-After`` header (RFC 9110 §10.2.3). Maps to HTTP 423
    Locked (RFC 4918 §11.3) rather than 429 because the lockout is account
    state, not rate state — the same caller will be locked from every IP.
    """

    default_code = "ACCOUNT_LOCKED"

    def __init__(self, *, retry_after_seconds: int) -> None:
        super().__init__(
            message=f"account locked, retry in {retry_after_seconds}s",
        )
        self.retry_after_seconds = retry_after_seconds


class JwksDecryptionError(FastAuthError):
    """Raised when a stored JWKS private key cannot be decrypted.

    Almost always means ``FastAuthConfig.secret_key`` was changed without an
    accompanying ``secret_key_rotation`` entry holding the previous value. The
    KEK derived from the current secret no longer matches the AES-GCM tag on
    the stored ciphertext. ``JwksRegistry.ensure_key`` proactively detects
    this at startup and rotates the affected key to keep the server serviceable;
    this exception escapes to the request layer only when the proactive path was
    skipped (e.g. by a custom signer wired post-startup).
    """

    default_code = "JWKS_DECRYPTION_FAILED"


class RefreshTokenReuseError(AuthenticationError):
    """Raised when a previously-consumed refresh token is presented again.

    A strong signal of token theft: the legitimate client already rotated
    this token and got a new one; whoever is presenting this stale token
    isn't the legitimate client. The handler revokes every refresh token
    in the same family and the user must sign in again.
    """

    default_code = "REFRESH_TOKEN_REUSE"


EXCEPTION_HTTP_STATUS: dict[type[FastAuthError], int] = {
    ConfigError: HTTPStatus.INTERNAL_SERVER_ERROR,
    AdapterError: HTTPStatus.INTERNAL_SERVER_ERROR,
    NotFoundError: HTTPStatus.NOT_FOUND,
    DuplicateError: HTTPStatus.CONFLICT,
    PasswordAlreadySetError: HTTPStatus.CONFLICT,
    InvalidCredentialsError: HTTPStatus.UNAUTHORIZED,
    EmailNotVerifiedError: HTTPStatus.FORBIDDEN,
    SessionExpiredError: HTTPStatus.UNAUTHORIZED,
    RateLimitError: HTTPStatus.TOO_MANY_REQUESTS,
    TokenInvalidError: HTTPStatus.BAD_REQUEST,
    TokenExpiredError: HTTPStatus.BAD_REQUEST,
    HookAbortError: HTTPStatus.BAD_REQUEST,
    CsrfError: HTTPStatus.FORBIDDEN,
    AccountLockedError: HTTPStatus.LOCKED,
    JwksDecryptionError: HTTPStatus.INTERNAL_SERVER_ERROR,
    RefreshTokenReuseError: HTTPStatus.UNAUTHORIZED,
}
