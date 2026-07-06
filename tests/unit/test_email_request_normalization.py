"""Request-model email normalization coverage for auth flows."""

from __future__ import annotations

from pydantic import SecretStr

from fastauth.flows.change_email import ConfirmEmailChangeRequest, RequestEmailChangeRequest
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
from fastauth.flows.password_reset import ForgotPasswordRequest, ResetPasswordRequest
from fastauth.flows.verification import SendVerificationEmailRequest, VerifyEmailRequest


def test_password_reset_requests_normalize_email_local_part() -> None:
    assert ForgotPasswordRequest(email="Alice@Example.COM").email == "alice@example.com"
    assert (
        ResetPasswordRequest(
            email="Alice@Example.COM",
            token=SecretStr("token"),
            new_password=SecretStr("new-secret-12345"),
        ).email
        == "alice@example.com"
    )


def test_email_verification_requests_normalize_email_local_part() -> None:
    assert SendVerificationEmailRequest(email="Alice@Example.COM").email == "alice@example.com"
    assert (
        VerifyEmailRequest(email="Alice@Example.COM", token=SecretStr("token")).email
        == "alice@example.com"
    )


def test_email_otp_requests_normalize_email_local_part() -> None:
    assert (
        SendOtpRequest(email="Alice@Example.COM", purpose=EmailOtpPurpose.SIGN_IN).email
        == "alice@example.com"
    )
    assert (
        CheckOtpRequest(
            email="Alice@Example.COM",
            purpose=EmailOtpPurpose.SIGN_IN,
            otp=SecretStr("123456"),
        ).email
        == "alice@example.com"
    )
    assert (
        SignInOtpRequest(email="Alice@Example.COM", otp=SecretStr("123456")).email
        == "alice@example.com"
    )
    assert (
        VerifyEmailOtpRequest(email="Alice@Example.COM", otp=SecretStr("123456")).email
        == "alice@example.com"
    )
    assert RequestPasswordResetOtpRequest(email="Alice@Example.COM").email == "alice@example.com"
    assert (
        ResetPasswordOtpRequest(
            email="Alice@Example.COM",
            otp=SecretStr("123456"),
            password=SecretStr("new-secret-12345"),
        ).email
        == "alice@example.com"
    )
    assert RequestEmailChangeOtpRequest(new_email="Alice@Example.COM").new_email == (
        "alice@example.com"
    )
    assert (
        ChangeEmailOtpRequest(new_email="Alice@Example.COM", otp=SecretStr("123456")).new_email
        == "alice@example.com"
    )


def test_change_email_requests_normalize_new_email_local_part() -> None:
    assert (
        RequestEmailChangeRequest(
            new_email="Alice2@Example.COM",
            password=SecretStr("correct-horse-staple"),
        ).new_email
        == "alice2@example.com"
    )
    assert (
        ConfirmEmailChangeRequest(
            new_email="Alice2@Example.COM",
            token=SecretStr("token"),
        ).new_email
        == "alice2@example.com"
    )
