"""Safe public response DTOs.

These models deliberately do not inherit from persistence/domain entities.
Only fields intended for HTTP clients are represented here.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, JsonValue
from pydantic.alias_generators import to_camel

from fastauth.domain.models import ApiKey, Session, User

__all__ = [
    "ApiKeyView",
    "AuthenticationResponse",
    "CredentialsView",
    "ResponseModel",
    "SessionView",
    "UserView",
    "api_key_view",
    "authentication_response",
    "session_view",
    "user_view",
]


class ResponseModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        alias_generator=to_camel,
        serialize_by_alias=True,
    )


class UserView(ResponseModel):
    id: str
    email: EmailStr
    username: str | None = None
    name: str | None = None
    image: str | None = None
    email_verified: bool
    metadata: dict[str, JsonValue] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime


class SessionView(ResponseModel):
    id: str
    user_id: str
    expires_at: datetime
    ip_address: str | None = None
    user_agent: str | None = None
    created_at: datetime
    updated_at: datetime


class CredentialsView(ResponseModel):
    token: str
    refresh_token: str | None = None


class AuthenticationResponse(ResponseModel):
    user: UserView
    session: SessionView
    credentials: CredentialsView | None = None


class ApiKeyView(ResponseModel):
    id: str
    user_id: str
    name: str
    key_prefix: str
    enabled: bool
    expires_at: datetime | None = None
    remaining: int | None = None
    permissions: dict[str, list[str]] = Field(default_factory=dict)
    metadata: dict[str, JsonValue] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime


def user_view(user: User) -> UserView:
    return UserView(
        id=user.id,
        email=user.email,
        username=user.username,
        name=user.name,
        image=user.image,
        email_verified=user.email_verified,
        metadata=user.metadata,
        created_at=user.created_at,
        updated_at=user.updated_at,
    )


def session_view(session: Session) -> SessionView:
    return SessionView(
        id=session.id,
        user_id=session.user_id,
        expires_at=session.expires_at,
        ip_address=session.ip_address,
        user_agent=session.user_agent,
        created_at=session.created_at,
        updated_at=session.updated_at,
    )


def api_key_view(api_key: ApiKey) -> ApiKeyView:
    return ApiKeyView(
        id=api_key.id,
        user_id=api_key.user_id,
        name=api_key.name,
        key_prefix=api_key.key_prefix,
        enabled=api_key.enabled,
        expires_at=api_key.expires_at,
        remaining=api_key.remaining,
        permissions=api_key.permissions,
        metadata=api_key.metadata,
        created_at=api_key.created_at,
        updated_at=api_key.updated_at,
    )


def authentication_response(
    *,
    user: User,
    session: Session,
    token: str | None = None,
    refresh_token: str | None = None,
) -> AuthenticationResponse:
    credentials = (
        CredentialsView(token=token, refresh_token=refresh_token)
        if token is not None
        else None
    )
    return AuthenticationResponse(
        user=user_view(user),
        session=session_view(session),
        credentials=credentials,
    )
