"""Beanie ``Document`` subclasses + Doc→domain conversion helpers.

Each Doc subclass overrides the parent Pydantic model's ``id: str`` (and
Mongo-owned relation ids where applicable) with ``PydanticObjectId``,
aliased to ``_id`` for the primary key. Beanie/Motor then store these as
real BSON ObjectIds. The ``to_*`` converters at the bottom of this module
rebuild plain string-typed domain models on the way out.

Why ``model_dump()`` + manual id-string conversion instead of
``mode="json"``? ``mode="json"`` recursively converts ``bytes`` fields to
strings via an attempted UTF-8 decode, which corrupts the encrypted JWKS
private-key blob stored on :class:`JwksKey.private_key_encrypted`. The
explicit field-by-field approach below preserves raw bytes and only
re-stringifies the ``PydanticObjectId`` fields we care about.
"""

from __future__ import annotations

from typing import Any, ClassVar

import pymongo
from beanie import (  # pyright: ignore[reportUnknownVariableType]
    Document,
    PydanticObjectId,
    init_beanie,  # pyright: ignore[reportUnknownVariableType]
)
from motor.motor_asyncio import AsyncIOMotorDatabase
from pydantic import Field
from pymongo import IndexModel

from fastauth.domain.models import (
    Account,
    ApiKey,
    AuditLog,
    JwksKey,
    RateLimit,
    RefreshToken,
    Session,
    User,
    Verification,
)

__all__ = [
    "DOCUMENT_MODELS",
    "AccountDoc",
    "ApiKeyDoc",
    "AuditLogDoc",
    "JwksKeyDoc",
    "RateLimitDoc",
    "RefreshTokenDoc",
    "SessionDoc",
    "UserDoc",
    "VerificationDoc",
    "init_beanie_documents",
    "to_account",
    "to_api_key",
    "to_audit_log",
    "to_jwks_key",
    "to_rate_limit",
    "to_refresh_token",
    "to_session",
    "to_user",
    "to_verification",
]


# --- Document classes ---


class UserDoc(User, Document):  # pyright: ignore[reportIncompatibleVariableOverride]
    id: PydanticObjectId | None = Field(default=None, alias="_id")  # pyright: ignore[reportIncompatibleVariableOverride]

    class Settings:
        name = "users"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel("email", unique=True, name="users_email_unique"),
            IndexModel("username", unique=True, sparse=True, name="users_username_unique"),
        ]


class SessionDoc(Session, Document):  # pyright: ignore[reportIncompatibleVariableOverride]
    id: PydanticObjectId | None = Field(default=None, alias="_id")  # pyright: ignore[reportIncompatibleVariableOverride]
    user_id: PydanticObjectId  # pyright: ignore[reportIncompatibleVariableOverride]

    class Settings:
        name = "sessions"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel("token_hash", unique=True, name="sessions_token_hash_unique"),
            IndexModel("user_id", name="sessions_user_id"),
            IndexModel("expires_at", expireAfterSeconds=0, name="sessions_ttl"),
        ]


class RefreshTokenDoc(RefreshToken, Document):  # pyright: ignore[reportIncompatibleVariableOverride]
    id: PydanticObjectId | None = Field(default=None, alias="_id")  # pyright: ignore[reportIncompatibleVariableOverride]
    user_id: PydanticObjectId  # pyright: ignore[reportIncompatibleVariableOverride]
    family_id: PydanticObjectId  # pyright: ignore[reportIncompatibleVariableOverride]
    replaced_by: PydanticObjectId | None = None  # pyright: ignore[reportIncompatibleVariableOverride]

    class Settings:
        name = "refresh_tokens"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel("token_hash", unique=True, name="refresh_tokens_token_hash_unique"),
            IndexModel("user_id", name="refresh_tokens_user_id"),
            IndexModel("family_id", name="refresh_tokens_family_id"),
            IndexModel("expires_at", expireAfterSeconds=0, name="refresh_tokens_ttl"),
        ]


class AccountDoc(Account, Document):  # pyright: ignore[reportIncompatibleVariableOverride]
    id: PydanticObjectId | None = Field(default=None, alias="_id")  # pyright: ignore[reportIncompatibleVariableOverride]
    user_id: PydanticObjectId  # pyright: ignore[reportIncompatibleVariableOverride]

    class Settings:
        name = "accounts"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel(
                [("user_id", pymongo.ASCENDING), ("provider_id", pymongo.ASCENDING)],
                unique=True,
                name="accounts_user_provider_unique",
            ),
        ]


class VerificationDoc(Verification, Document):  # pyright: ignore[reportIncompatibleVariableOverride]
    id: PydanticObjectId | None = Field(default=None, alias="_id")  # pyright: ignore[reportIncompatibleVariableOverride]

    class Settings:
        name = "verifications"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel(
                [
                    ("identifier", pymongo.ASCENDING),
                    ("purpose", pymongo.ASCENDING),
                    ("value_hash", pymongo.ASCENDING),
                ],
                unique=True,
                name="verifications_lookup_unique",
            ),
            IndexModel("expires_at", expireAfterSeconds=0, name="verifications_ttl"),
        ]


class ApiKeyDoc(ApiKey, Document):  # pyright: ignore[reportIncompatibleVariableOverride]
    id: PydanticObjectId | None = Field(default=None, alias="_id")  # pyright: ignore[reportIncompatibleVariableOverride]
    user_id: PydanticObjectId  # pyright: ignore[reportIncompatibleVariableOverride]

    class Settings:
        name = "api_keys"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel("key_hash", unique=True, name="api_keys_hash_unique"),
            IndexModel("user_id", name="api_keys_user_id"),
            IndexModel("expires_at", name="api_keys_expires_at"),
        ]


class JwksKeyDoc(JwksKey, Document):  # pyright: ignore[reportIncompatibleVariableOverride]
    id: PydanticObjectId | None = Field(default=None, alias="_id")  # pyright: ignore[reportIncompatibleVariableOverride]
    kid: PydanticObjectId  # pyright: ignore[reportIncompatibleVariableOverride]

    class Settings:
        name = "jwks_keys"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel("kid", unique=True, name="jwks_kid_unique"),
        ]


class AuditLogDoc(AuditLog, Document):  # pyright: ignore[reportIncompatibleVariableOverride]
    id: PydanticObjectId | None = Field(default=None, alias="_id")  # pyright: ignore[reportIncompatibleVariableOverride]
    user_id: PydanticObjectId | None = None  # pyright: ignore[reportIncompatibleVariableOverride]

    class Settings:
        name = "audit_logs"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel(
                [("user_id", pymongo.ASCENDING), ("event_type", pymongo.ASCENDING)],
                name="audit_user_event",
            ),
            IndexModel("created_at", name="audit_created_at"),
        ]


class RateLimitDoc(RateLimit, Document):  # pyright: ignore[reportIncompatibleVariableOverride]
    id: PydanticObjectId | None = Field(default=None, alias="_id")  # pyright: ignore[reportIncompatibleVariableOverride]

    class Settings:
        name = "rate_limits"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel("key", unique=True, name="rate_limits_key_unique"),
        ]


DOCUMENT_MODELS: list[type[Document]] = [
    UserDoc,
    SessionDoc,
    RefreshTokenDoc,
    AccountDoc,
    VerificationDoc,
    ApiKeyDoc,
    JwksKeyDoc,
    AuditLogDoc,
    RateLimitDoc,
]


async def init_beanie_documents(database: AsyncIOMotorDatabase[Any]) -> None:
    await init_beanie(database=database, document_models=DOCUMENT_MODELS)


# --- Doc → domain conversion ---


def to_user(doc: UserDoc) -> User:
    data = doc.model_dump()
    if doc.id is not None:
        data["id"] = str(doc.id)
    return User.model_validate(data)


def to_session(doc: SessionDoc) -> Session:
    data = doc.model_dump()
    if doc.id is not None:
        data["id"] = str(doc.id)
    data["user_id"] = str(doc.user_id)
    return Session.model_validate(data)


def to_refresh_token(doc: RefreshTokenDoc) -> RefreshToken:
    data = doc.model_dump()
    if doc.id is not None:
        data["id"] = str(doc.id)
    data["user_id"] = str(doc.user_id)
    data["family_id"] = str(doc.family_id)
    if doc.replaced_by is not None:
        data["replaced_by"] = str(doc.replaced_by)
    return RefreshToken.model_validate(data)


def to_account(doc: AccountDoc) -> Account:
    data = doc.model_dump()
    if doc.id is not None:
        data["id"] = str(doc.id)
    data["user_id"] = str(doc.user_id)
    return Account.model_validate(data)


def to_verification(doc: VerificationDoc) -> Verification:
    data = doc.model_dump()
    if doc.id is not None:
        data["id"] = str(doc.id)
    return Verification.model_validate(data)


def to_api_key(doc: ApiKeyDoc) -> ApiKey:
    data = doc.model_dump()
    if doc.id is not None:
        data["id"] = str(doc.id)
    data["user_id"] = str(doc.user_id)
    return ApiKey.model_validate(data)


def to_jwks_key(doc: JwksKeyDoc) -> JwksKey:
    data = doc.model_dump()
    if doc.id is not None:
        data["id"] = str(doc.id)
    data["kid"] = str(doc.kid)
    return JwksKey.model_validate(data)


def to_audit_log(doc: AuditLogDoc) -> AuditLog:
    data = doc.model_dump()
    if doc.id is not None:
        data["id"] = str(doc.id)
    if doc.user_id is not None:
        data["user_id"] = str(doc.user_id)
    return AuditLog.model_validate(data)


def to_rate_limit(doc: RateLimitDoc) -> RateLimit:
    data = doc.model_dump()
    if doc.id is not None:
        data["id"] = str(doc.id)
    return RateLimit.model_validate(data)
