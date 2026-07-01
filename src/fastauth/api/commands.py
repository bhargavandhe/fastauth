"""Application command/value models shared by HTTP and server-side APIs."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel

__all__ = [
    "BearerCredentialDelivery",
    "CookieCredentialDelivery",
    "CredentialDelivery",
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
