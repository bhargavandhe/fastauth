"""Application command/value models shared by HTTP and server-side APIs."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, SecretStr, field_validator
from pydantic.alias_generators import to_camel

from fastauth.domain.models import User
from fastauth.domain.value_objects import UserMetadata, normalize_email

__all__ = [
    "BearerCredentialDelivery",
    "ChangePasswordCommand",
    "ConfirmEmailChangeCommand",
    "ConfirmUserDeletionCommand",
    "CookieCredentialDelivery",
    "CredentialDelivery",
    "DeleteUserCommand",
    "GetSessionCommand",
    "ListSessionsCommand",
    "RefreshSessionCommand",
    "RequestContext",
    "RequestEmailChangeCommand",
    "RequestPasswordResetCommand",
    "RequestUserDeletionCommand",
    "ResetPasswordCommand",
    "RevokeOtherSessionsCommand",
    "RevokeSessionCommand",
    "SetPasswordCommand",
    "SignInEmailCommand",
    "SignInUsernameCommand",
    "SignOutCommand",
    "SignUpEmailCommand",
    "UpdateUserCommand",
    "VerifyPasswordCommand",
]


class CommandModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        alias_generator=to_camel,
        serialize_by_alias=True,
    )


class CookieCredentialDelivery(CommandModel):
    kind: Literal["cookie"] = "cookie"


class BearerCredentialDelivery(CommandModel):
    kind: Literal["bearer"] = "bearer"
    include_refresh_token: bool = True


CredentialDelivery = Annotated[
    CookieCredentialDelivery | BearerCredentialDelivery,
    Field(discriminator="kind"),
]


class RequestContext(CommandModel):
    ip_address: str | None = None
    user_agent: str | None = None


class SignInEmailCommand(CommandModel):
    email: EmailStr
    password: SecretStr
    context: RequestContext = Field(default_factory=RequestContext)
    delivery: CredentialDelivery = Field(default_factory=CookieCredentialDelivery)

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email_value(cls, value: object) -> object:
        return normalize_email(value)


class SignUpEmailCommand(CommandModel):
    email: EmailStr
    password: SecretStr
    name: str | None = None
    username: str | None = None
    context: RequestContext = Field(default_factory=RequestContext)
    delivery: CredentialDelivery = Field(default_factory=CookieCredentialDelivery)

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email_value(cls, value: object) -> object:
        return normalize_email(value)


class SignInUsernameCommand(CommandModel):
    username: str
    password: SecretStr
    context: RequestContext = Field(default_factory=RequestContext)
    delivery: CredentialDelivery = Field(default_factory=CookieCredentialDelivery)


class SignOutCommand(CommandModel):
    token: SecretStr | None = None


class GetSessionCommand(CommandModel):
    token: SecretStr | None = None


class RefreshSessionCommand(CommandModel):
    refresh_token: SecretStr
    context: RequestContext = Field(default_factory=RequestContext)
    delivery: CredentialDelivery = Field(default_factory=BearerCredentialDelivery)


class ListSessionsCommand(CommandModel):
    user: User
    current_session_id: str | None = None


class RevokeSessionCommand(CommandModel):
    user: User
    session_id: str


class RevokeOtherSessionsCommand(CommandModel):
    user: User
    current_session_id: str | None = None


class ChangePasswordCommand(CommandModel):
    user: User
    current_session_id: str
    current_password: SecretStr
    new_password: SecretStr
    revoke_other_sessions: bool = True
    context: RequestContext = Field(default_factory=RequestContext)


class RequestPasswordResetCommand(CommandModel):
    email: EmailStr
    redirect_url: str | None = None
    context: RequestContext = Field(default_factory=RequestContext)

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email_value(cls, value: object) -> object:
        return normalize_email(value)


class ResetPasswordCommand(CommandModel):
    email: EmailStr
    token: SecretStr
    new_password: SecretStr
    context: RequestContext = Field(default_factory=RequestContext)

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email_value(cls, value: object) -> object:
        return normalize_email(value)


class UpdateUserCommand(CommandModel):
    user: User
    name: str | None = None
    image: str | None = None
    metadata: UserMetadata | None = None
    context: RequestContext = Field(default_factory=RequestContext)


class SetPasswordCommand(CommandModel):
    user: User
    current_session_id: str
    new_password: SecretStr
    revoke_other_sessions: bool = True
    context: RequestContext = Field(default_factory=RequestContext)


class VerifyPasswordCommand(CommandModel):
    user: User
    password: SecretStr
    context: RequestContext = Field(default_factory=RequestContext)


class DeleteUserCommand(CommandModel):
    user: User
    password: SecretStr
    context: RequestContext = Field(default_factory=RequestContext)


class RequestUserDeletionCommand(CommandModel):
    user: User
    context: RequestContext = Field(default_factory=RequestContext)


class ConfirmUserDeletionCommand(CommandModel):
    user: User
    token: SecretStr
    context: RequestContext = Field(default_factory=RequestContext)


class RequestEmailChangeCommand(CommandModel):
    user: User
    new_email: EmailStr
    password: SecretStr
    context: RequestContext = Field(default_factory=RequestContext)

    @field_validator("new_email", mode="before")
    @classmethod
    def normalize_new_email_value(cls, value: object) -> object:
        return normalize_email(value)


class ConfirmEmailChangeCommand(CommandModel):
    new_email: EmailStr
    token: SecretStr
    context: RequestContext = Field(default_factory=RequestContext)

    @field_validator("new_email", mode="before")
    @classmethod
    def normalize_new_email_value(cls, value: object) -> object:
        return normalize_email(value)
