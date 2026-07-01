"""Options for the email-OTP plugin."""

from __future__ import annotations

from datetime import timedelta

from pydantic import BaseModel, ConfigDict, Field

__all__ = ["EmailChangeOtpOptions", "EmailOtpOptions"]


class EmailChangeOtpOptions(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
        revalidate_instances="always",
    )

    enabled: bool = False
    verify_current_email: bool = False


class EmailOtpOptions(BaseModel):
    """Tunables for the email-OTP plugin.

    Defaults match better-auth: 6 digits, 5-minute expiry, 3 attempts per
    OTP. Auto-sign-up on first sign-in is enabled by default.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
        revalidate_instances="always",
    )

    code_length: int = Field(default=6, ge=4, le=10)
    expires_in: timedelta = Field(
        default=timedelta(minutes=5),
        gt=timedelta(0),
        le=timedelta(hours=1),
    )
    max_attempts: int = Field(default=3, ge=1, le=20)
    allow_sign_up: bool = True
    email_change: EmailChangeOtpOptions = Field(default_factory=EmailChangeOtpOptions)
