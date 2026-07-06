# tests/unit/test_exceptions.py
from __future__ import annotations

from fastauth import exceptions


def test_base_carries_code_and_message() -> None:
    error = exceptions.FastAuthError(code="x", message="bad")
    assert error.code == "x"
    assert error.message == "bad"
    assert "bad" in str(error)


def test_invalid_credentials_inherits_authentication() -> None:
    error = exceptions.InvalidCredentialsError()
    assert isinstance(error, exceptions.AuthenticationError)
    assert isinstance(error, exceptions.FastAuthError)
    assert error.code == "INVALID_CREDENTIALS"


def test_not_found_default_code() -> None:
    error = exceptions.NotFoundError(resource="user")
    assert error.code == "NOT_FOUND"
    assert "user" in error.message


def test_rate_limit_carries_retry_after() -> None:
    error = exceptions.RateLimitError(retry_after_seconds=42)
    assert error.code == "RATE_LIMITED"
    assert error.retry_after_seconds == 42


def test_http_status_map_complete() -> None:
    for cls in (
        exceptions.InvalidCredentialsError,
        exceptions.EmailNotVerifiedError,
        exceptions.SessionExpiredError,
        exceptions.RateLimitError,
        exceptions.TokenInvalidError,
        exceptions.TokenExpiredError,
        exceptions.NotFoundError,
        exceptions.DuplicateError,
        exceptions.CsrfError,
        exceptions.HookAbortError,
        exceptions.ConfigError,
        exceptions.AdapterError,
    ):
        assert cls in exceptions.EXCEPTION_HTTP_STATUS, f"{cls.__name__} missing from status map"
