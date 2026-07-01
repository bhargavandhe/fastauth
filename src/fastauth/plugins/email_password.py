"""Email/password first-party auth provider plugin."""

from __future__ import annotations

from datetime import timedelta
from typing import Annotated, ClassVar, Self

from pydantic import Field, TypeAdapter, model_validator

from fastauth.plugins.base import Plugin, PluginOptions

__all__ = ["EmailPasswordOptions", "EmailPasswordPlugin", "PasswordPolicy"]


class PasswordPolicy(PluginOptions):
    """Password validation and hashing policy for email/password auth."""

    min_length: int = Field(default=8, ge=8, le=1024)
    max_length: int = Field(default=128, ge=8, le=4096)
    argon2_time_cost: int = Field(default=3, ge=1, le=64)
    argon2_memory_cost_kib: int = Field(default=64 * 1024, ge=8 * 1024, le=2 * 1024 * 1024)
    argon2_parallelism: int = Field(default=4, ge=1, le=64)

    @model_validator(mode="after")
    def validate_password_bounds(self) -> Self:
        if self.max_length < self.min_length:
            raise ValueError("max_length cannot be less than min_length")
        return self

    def build_adapter(self) -> TypeAdapter[str]:
        password_value = Annotated[
            str,
            Field(min_length=self.min_length, max_length=self.max_length),
        ]
        return TypeAdapter(password_value)


class EmailPasswordOptions(PluginOptions):
    """Static options for the email/password provider."""

    allow_username_sign_in: bool = True
    allow_bearer_tokens: bool = True
    require_email_verification: bool = False
    password: PasswordPolicy = Field(default_factory=PasswordPolicy)
    email_verification_expires_in: timedelta = Field(default=timedelta(minutes=15), gt=timedelta(0))
    password_reset_expires_in: timedelta = Field(default=timedelta(minutes=30), gt=timedelta(0))
    email_change_expires_in: timedelta = Field(default=timedelta(minutes=15), gt=timedelta(0))
    delete_account_expires_in: timedelta = Field(default=timedelta(minutes=15), gt=timedelta(0))


class EmailPasswordPlugin(Plugin):
    """Enable built-in email/password routes."""

    id: ClassVar[str] = "fastauth-email-password"

    def __init__(self, options: EmailPasswordOptions | None = None) -> None:
        self.options = options or EmailPasswordOptions()
