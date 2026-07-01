"""Application command/value models shared by HTTP and server-side APIs."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, SecretStr, field_validator
from pydantic.alias_generators import to_camel

from fastauth.domain.value_objects import normalize_email

__all__ = [
    "BearerCredentialDelivery",
    "CookieCredentialDelivery",
    "CredentialDelivery",
    "RequestContext",
    "SignInEmailCommand",
    "SignUpEmailCommand",
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
