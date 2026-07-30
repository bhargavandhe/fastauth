"""Application command/value models shared by HTTP and server-side APIs."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    SecretStr,
    field_validator,
)
from pydantic.alias_generators import to_camel

from fastauth.domain.value_objects import SessionId, UserId, UserMetadata, Username, normalize_email

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
    "SessionPrincipal",
    "SetPasswordCommand",
    "SignInEmailCommand",
    "SignInUsernameCommand",
    "SignOutCommand",
    "SignUpEmailCommand",
    "UpdateUserCommand",
    "UserPrincipal",
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


class UserPrincipal(CommandModel):
    user_id: UserId


class SessionPrincipal(UserPrincipal):
    session_id: SessionId


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
    username: Username | None = None
    context: RequestContext = Field(default_factory=RequestContext)
    delivery: CredentialDelivery = Field(default_factory=CookieCredentialDelivery)

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email_value(cls, value: object) -> object:
        return normalize_email(value)


class SignInUsernameCommand(CommandModel):
    username: Username
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
    principal: UserPrincipal


class RevokeSessionCommand(CommandModel):
    principal: UserPrincipal
    session_id: SessionId


class RevokeOtherSessionsCommand(CommandModel):
    principal: SessionPrincipal


class ChangePasswordCommand(CommandModel):
    principal: SessionPrincipal
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
    principal: UserPrincipal
    name: str | None = None
    image: str | None = None
    metadata: UserMetadata | None = None
    username: Username | None = None
    context: RequestContext = Field(default_factory=RequestContext)


class SetPasswordCommand(CommandModel):
    principal: SessionPrincipal
    new_password: SecretStr
    revoke_other_sessions: bool = True
    context: RequestContext = Field(default_factory=RequestContext)


class VerifyPasswordCommand(CommandModel):
    principal: UserPrincipal
    password: SecretStr
    context: RequestContext = Field(default_factory=RequestContext)


class DeleteUserCommand(CommandModel):
    principal: UserPrincipal
    password: SecretStr
    context: RequestContext = Field(default_factory=RequestContext)


class RequestUserDeletionCommand(CommandModel):
    principal: UserPrincipal
    context: RequestContext = Field(default_factory=RequestContext)


class ConfirmUserDeletionCommand(CommandModel):
    principal: UserPrincipal
    token: SecretStr
    context: RequestContext = Field(default_factory=RequestContext)


class RequestEmailChangeCommand(CommandModel):
    principal: UserPrincipal
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
