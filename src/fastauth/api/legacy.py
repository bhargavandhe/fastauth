"""Deprecated server API command models kept for temporary compatibility."""

from __future__ import annotations

import warnings

from pydantic import EmailStr, Field, SecretStr, field_validator, model_validator

from fastauth.api.commands import CommandModel, RequestContext
from fastauth.domain.models import User
from fastauth.domain.value_objects import UserMetadata, normalize_email

__all__ = [
    "ChangePasswordCommand",
    "ConfirmUserDeletionCommand",
    "DeleteUserCommand",
    "ListSessionsCommand",
    "RequestEmailChangeCommand",
    "RequestUserDeletionCommand",
    "RevokeOtherSessionsCommand",
    "RevokeSessionCommand",
    "SetPasswordCommand",
    "UpdateUserCommand",
    "VerifyPasswordCommand",
]


class LegacyPrincipalCommand(CommandModel):
    user: User

    @model_validator(mode="after")
    def warn_legacy_user_command(self) -> LegacyPrincipalCommand:
        warnings.warn(
            (
                "fastauth.api.legacy user= command models are deprecated; "
                "use fastauth.api.commands UserPrincipal or SessionPrincipal"
            ),
            DeprecationWarning,
            stacklevel=3,
        )
        return self


class ListSessionsCommand(LegacyPrincipalCommand):
    current_session_id: str | None = None


class RevokeSessionCommand(LegacyPrincipalCommand):
    session_id: str


class RevokeOtherSessionsCommand(LegacyPrincipalCommand):
    current_session_id: str | None = None


class ChangePasswordCommand(LegacyPrincipalCommand):
    current_session_id: str | None = None
    current_password: SecretStr
    new_password: SecretStr
    revoke_other_sessions: bool = True
    context: RequestContext = Field(default_factory=RequestContext)


class UpdateUserCommand(LegacyPrincipalCommand):
    name: str | None = None
    image: str | None = None
    metadata: UserMetadata | None = None
    context: RequestContext = Field(default_factory=RequestContext)


class SetPasswordCommand(LegacyPrincipalCommand):
    current_session_id: str | None = None
    new_password: SecretStr
    revoke_other_sessions: bool = True
    context: RequestContext = Field(default_factory=RequestContext)


class VerifyPasswordCommand(LegacyPrincipalCommand):
    password: SecretStr
    context: RequestContext = Field(default_factory=RequestContext)


class DeleteUserCommand(LegacyPrincipalCommand):
    password: SecretStr
    context: RequestContext = Field(default_factory=RequestContext)


class RequestUserDeletionCommand(LegacyPrincipalCommand):
    context: RequestContext = Field(default_factory=RequestContext)


class ConfirmUserDeletionCommand(LegacyPrincipalCommand):
    token: SecretStr
    context: RequestContext = Field(default_factory=RequestContext)


class RequestEmailChangeCommand(LegacyPrincipalCommand):
    new_email: EmailStr
    password: SecretStr
    context: RequestContext = Field(default_factory=RequestContext)

    @field_validator("new_email", mode="before")
    @classmethod
    def normalize_new_email_value(cls, value: object) -> object:
        return normalize_email(value)
