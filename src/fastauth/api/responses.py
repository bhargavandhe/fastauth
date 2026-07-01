"""Safe public response DTOs.

These models deliberately do not inherit from persistence/domain entities.
Only fields intended for HTTP clients are represented here.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field
from pydantic.alias_generators import to_camel

from fastauth.domain.models import ApiKey, Session, User
from fastauth.domain.value_objects import (
    ApiKeyId,
    ApiKeyMetadata,
    ApiKeyPrefix,
    PermissionSet,
    RawToken,
    SessionId,
    UserId,
    UserMetadata,
)

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
    id: UserId
    email: EmailStr
    username: str | None = None
    name: str | None = None
    image: str | None = None
    email_verified: bool
    metadata: UserMetadata = Field(default_factory=lambda: UserMetadata({}))
    created_at: datetime
    updated_at: datetime


class SessionView(ResponseModel):
    id: SessionId
    user_id: UserId
    expires_at: datetime
    ip_address: str | None = None
    user_agent: str | None = None
    created_at: datetime
    updated_at: datetime


class CredentialsView(ResponseModel):
    token: RawToken
    refresh_token: RawToken | None = None


class AuthenticationResponse(ResponseModel):
    user: UserView
    session: SessionView
    credentials: CredentialsView | None = None


class ApiKeyView(ResponseModel):
    id: ApiKeyId
    user_id: UserId
    name: str
    key_prefix: ApiKeyPrefix
    enabled: bool
    expires_at: datetime | None = None
    remaining: int | None = None
    permissions: PermissionSet = Field(default_factory=lambda: PermissionSet({}))
    metadata: ApiKeyMetadata = Field(default_factory=lambda: ApiKeyMetadata({}))
    created_at: datetime
    updated_at: datetime


def user_view(user: User) -> UserView:
    return UserView(
        id=UserId(user.id),
        email=user.email,
        username=user.username,
        name=user.name,
        image=user.image,
        email_verified=user.email_verified,
        metadata=UserMetadata.model_validate(user.metadata),
        created_at=user.created_at,
        updated_at=user.updated_at,
    )


def session_view(session: Session) -> SessionView:
    return SessionView(
        id=SessionId(session.id),
        user_id=UserId(session.user_id),
        expires_at=session.expires_at,
        ip_address=session.ip_address,
        user_agent=session.user_agent,
        created_at=session.created_at,
        updated_at=session.updated_at,
    )


def api_key_view(api_key: ApiKey) -> ApiKeyView:
    return ApiKeyView(
        id=ApiKeyId(api_key.id),
        user_id=UserId(api_key.user_id),
        name=api_key.name,
        key_prefix=ApiKeyPrefix(api_key.key_prefix),
        enabled=api_key.enabled,
        expires_at=api_key.expires_at,
        remaining=api_key.remaining,
        permissions=PermissionSet.model_validate(api_key.permissions),
        metadata=ApiKeyMetadata.model_validate(api_key.metadata),
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
        CredentialsView(
            token=RawToken(token),
            refresh_token=RawToken(refresh_token) if refresh_token is not None else None,
        )
        if token is not None
        else None
    )
    return AuthenticationResponse(
        user=user_view(user),
        session=session_view(session),
        credentials=credentials,
    )
