"""Beanie ``Document`` classes + explicit domain conversion helpers.

Each Doc class declares its persisted fields directly instead of inheriting
from the storage-agnostic Pydantic domain models. Mongo-owned primary and
relation ids use ``PydanticObjectId`` so Beanie/PyMongo store them as real
BSON ObjectIds. The ``from_*``/``to_*`` converters at the bottom of this
module translate between these documents and plain string-typed domain models.

Why ``model_dump()`` + manual id-string conversion instead of
``mode="json"``? ``mode="json"`` recursively converts ``bytes`` fields to
strings via an attempted UTF-8 decode, which corrupts the encrypted JWKS
private-key blob stored on :class:`JwksKey.private_key_encrypted`. The
explicit field-by-field approach below preserves raw bytes and only
re-stringifies the ``PydanticObjectId`` fields we care about.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, ClassVar

import pymongo
from beanie import (  # pyright: ignore[reportUnknownVariableType]
    Document,
    PydanticObjectId,
    init_beanie,  # pyright: ignore[reportUnknownVariableType]
)
from pydantic import Field
from pymongo import IndexModel
from pymongo.asynchronous.database import AsyncDatabase

from fastauth.domain.enums import AuditEventType, ProviderId, VerificationPurpose
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
    utc_now,
)
from fastauth.storage.beanie.helpers import (
    require_object_id,
    to_pydantic_object_id_or_none,
)

__all__ = [
    "DOCUMENT_MODELS",
    "AccountDoc",
    "ApiKeyDoc",
    "AuditLogDoc",
    "BeanieDocumentModels",
    "JwksKeyDoc",
    "RateLimitDoc",
    "RefreshTokenDoc",
    "SessionDoc",
    "UserDoc",
    "VerificationDoc",
    "build_beanie_document_models",
    "from_account",
    "from_api_key",
    "from_audit_log",
    "from_jwks_key",
    "from_rate_limit",
    "from_refresh_token",
    "from_session",
    "from_user",
    "from_verification",
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


class UserDoc(Document):
    id: PydanticObjectId | None = Field(default=None, alias="_id")
    email: str
    username: str | None = None
    name: str | None = None
    image: str | None = None
    email_verified: bool = False
    pending_email_change: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    class Settings:
        name = "users"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel("email", unique=True, name="users_email_unique"),
            IndexModel("username", unique=True, sparse=True, name="users_username_unique"),
        ]


class SessionDoc(Document):
    id: PydanticObjectId | None = Field(default=None, alias="_id")
    user_id: PydanticObjectId
    token_hash: str
    expires_at: datetime
    ip_address: str | None = None
    user_agent: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    class Settings:
        name = "sessions"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel("token_hash", unique=True, name="sessions_token_hash_unique"),
            IndexModel("user_id", name="sessions_user_id"),
            IndexModel("expires_at", expireAfterSeconds=0, name="sessions_ttl"),
        ]


class RefreshTokenDoc(Document):
    id: PydanticObjectId | None = Field(default=None, alias="_id")
    user_id: PydanticObjectId
    token_hash: str
    family_id: PydanticObjectId
    expires_at: datetime
    consumed_at: datetime | None = None
    replaced_by: PydanticObjectId | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    class Settings:
        name = "refresh_tokens"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel("token_hash", unique=True, name="refresh_tokens_token_hash_unique"),
            IndexModel("user_id", name="refresh_tokens_user_id"),
            IndexModel("family_id", name="refresh_tokens_family_id"),
            IndexModel("expires_at", expireAfterSeconds=0, name="refresh_tokens_ttl"),
        ]


class AccountDoc(Document):
    id: PydanticObjectId | None = Field(default=None, alias="_id")
    user_id: PydanticObjectId
    provider_id: ProviderId
    account_id: str
    password: str | None = None
    access_token: str | None = None
    refresh_token: str | None = None
    access_token_expires_at: datetime | None = None
    refresh_token_expires_at: datetime | None = None
    scope: str | None = None
    id_token: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    class Settings:
        name = "accounts"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel(
                [("user_id", pymongo.ASCENDING), ("provider_id", pymongo.ASCENDING)],
                unique=True,
                name="accounts_user_provider_unique",
            ),
        ]


class VerificationDoc(Document):
    id: PydanticObjectId | None = Field(default=None, alias="_id")
    identifier: str
    value_hash: str
    purpose: VerificationPurpose
    expires_at: datetime
    attempt_count: int = 0
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

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


class ApiKeyDoc(Document):
    id: PydanticObjectId | None = Field(default=None, alias="_id")
    user_id: PydanticObjectId
    name: str
    key_hash: str
    key_prefix: str
    enabled: bool = True
    expires_at: datetime | None = None
    remaining: int | None = None
    refill_amount: int | None = None
    refill_interval_ms: int | None = None
    rate_limit_enabled: bool = False
    rate_limit_max: int | None = None
    rate_limit_window_ms: int | None = None
    last_refill_at: datetime | None = None
    last_request_at: datetime | None = None
    request_count: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)
    permissions: dict[str, list[str]] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    class Settings:
        name = "api_keys"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel("key_hash", unique=True, name="api_keys_hash_unique"),
            IndexModel("user_id", name="api_keys_user_id"),
            IndexModel("expires_at", name="api_keys_expires_at"),
        ]


class JwksKeyDoc(Document):
    id: PydanticObjectId | None = Field(default=None, alias="_id")
    kid: str
    alg: str
    public_key: str
    private_key_encrypted: bytes
    created_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime | None = None
    rotated_at: datetime | None = None

    class Settings:
        name = "jwks_keys"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel("kid", unique=True, name="jwks_kid_unique"),
        ]


class AuditLogDoc(Document):
    id: PydanticObjectId | None = Field(default=None, alias="_id")
    event_type: AuditEventType
    identifier: str | None = None
    user_id: PydanticObjectId | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    event_data: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)

    class Settings:
        name = "audit_logs"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel(
                [("user_id", pymongo.ASCENDING), ("event_type", pymongo.ASCENDING)],
                name="audit_user_event",
            ),
            IndexModel("created_at", name="audit_created_at"),
        ]


class RateLimitDoc(Document):
    id: PydanticObjectId | None = Field(default=None, alias="_id")
    key: str
    count: int  # pyright: ignore[reportIncompatibleMethodOverride]
    last_request_ms: int

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


@dataclass(frozen=True, slots=True)
class BeanieDocumentModels:
    user: type[Document]
    session: type[Document]
    refresh_token: type[Document]
    account: type[Document]
    verification: type[Document]
    api_key: type[Document]
    jwks_key: type[Document]
    audit_log: type[Document]
    rate_limit: type[Document]

    @property
    def all(self) -> list[type[Document]]:
        return [
            self.user,
            self.session,
            self.refresh_token,
            self.account,
            self.verification,
            self.api_key,
            self.jwks_key,
            self.audit_log,
            self.rate_limit,
        ]


DEFAULT_DOCUMENT_MODELS = BeanieDocumentModels(
    user=UserDoc,
    session=SessionDoc,
    refresh_token=RefreshTokenDoc,
    account=AccountDoc,
    verification=VerificationDoc,
    api_key=ApiKeyDoc,
    jwks_key=JwksKeyDoc,
    audit_log=AuditLogDoc,
    rate_limit=RateLimitDoc,
)


def build_collection_name(base_name: str, collection_prefix: str, collection_suffix: str) -> str:
    name = f"{collection_prefix}{base_name}{collection_suffix}"
    if not name or "\x00" in name or "$" in name or name.startswith("system."):
        raise ValueError(f"Invalid MongoDB collection name: {name!r}")
    return name


def build_beanie_document_models(
    *,
    collection_prefix: str = "",
    collection_suffix: str = "",
) -> BeanieDocumentModels:
    """Configure and return the public Beanie document classes.

    Beanie initializes class objects in place. Keeping these as the exported
    ``UserDoc``/``SessionDoc``/... classes lets consumers use Beanie's
    documented query style after custom collection naming is enabled.
    """

    collection_names = {
        "users": build_collection_name("users", collection_prefix, collection_suffix),
        "sessions": build_collection_name("sessions", collection_prefix, collection_suffix),
        "refresh_tokens": build_collection_name(
            "refresh_tokens",
            collection_prefix,
            collection_suffix,
        ),
        "accounts": build_collection_name("accounts", collection_prefix, collection_suffix),
        "verifications": build_collection_name(
            "verifications",
            collection_prefix,
            collection_suffix,
        ),
        "api_keys": build_collection_name("api_keys", collection_prefix, collection_suffix),
        "jwks_keys": build_collection_name("jwks_keys", collection_prefix, collection_suffix),
        "audit_logs": build_collection_name("audit_logs", collection_prefix, collection_suffix),
        "rate_limits": build_collection_name("rate_limits", collection_prefix, collection_suffix),
    }

    UserDoc.Settings.name = collection_names["users"]
    SessionDoc.Settings.name = collection_names["sessions"]
    RefreshTokenDoc.Settings.name = collection_names["refresh_tokens"]
    AccountDoc.Settings.name = collection_names["accounts"]
    VerificationDoc.Settings.name = collection_names["verifications"]
    ApiKeyDoc.Settings.name = collection_names["api_keys"]
    JwksKeyDoc.Settings.name = collection_names["jwks_keys"]
    AuditLogDoc.Settings.name = collection_names["audit_logs"]
    RateLimitDoc.Settings.name = collection_names["rate_limits"]

    return DEFAULT_DOCUMENT_MODELS


async def init_beanie_documents(
    database: AsyncDatabase[Any],
    *,
    collection_prefix: str = "",
    collection_suffix: str = "",
) -> None:
    document_models = build_beanie_document_models(
        collection_prefix=collection_prefix,
        collection_suffix=collection_suffix,
    )
    await init_beanie(database=database, document_models=document_models.all)


# --- Domain ↔ Doc conversion ---


def document_id(value: str | None) -> PydanticObjectId | None:
    if value is None:
        return None
    oid = to_pydantic_object_id_or_none(value)
    if oid is None:
        raise ValueError("expected a Mongo ObjectId hex string")
    return oid


def from_user(user: User, *, include_id: bool = True) -> UserDoc:
    data = user.model_dump(exclude={"id"})
    if include_id:
        data["id"] = document_id(user.id)
    return UserDoc.model_construct(**data)


def from_session(session: Session, *, include_id: bool = True) -> SessionDoc:
    data = session.model_dump(exclude={"id", "user_id"})
    if include_id:
        data["id"] = document_id(session.id)
    data["user_id"] = require_object_id(session.user_id)
    return SessionDoc.model_construct(**data)


def from_refresh_token(
    token: RefreshToken,
    *,
    include_id: bool = True,
) -> RefreshTokenDoc:
    data = token.model_dump(exclude={"id", "user_id", "family_id", "replaced_by"})
    if include_id:
        data["id"] = document_id(token.id)
    data["user_id"] = require_object_id(token.user_id)
    data["family_id"] = require_object_id(token.family_id)
    if token.replaced_by is not None:
        data["replaced_by"] = require_object_id(token.replaced_by)
    return RefreshTokenDoc.model_construct(**data)


def from_account(account: Account, *, include_id: bool = True) -> AccountDoc:
    data = account.model_dump(exclude={"id", "user_id"})
    if include_id:
        data["id"] = document_id(account.id)
    data["user_id"] = require_object_id(account.user_id)
    return AccountDoc.model_construct(**data)


def from_verification(
    verification: Verification,
    *,
    include_id: bool = True,
) -> VerificationDoc:
    data = verification.model_dump(exclude={"id"})
    if include_id:
        data["id"] = document_id(verification.id)
    return VerificationDoc.model_construct(**data)


def from_api_key(api_key: ApiKey, *, include_id: bool = True) -> ApiKeyDoc:
    data = api_key.model_dump(exclude={"id", "user_id"})
    if include_id:
        data["id"] = document_id(api_key.id)
    data["user_id"] = require_object_id(api_key.user_id)
    return ApiKeyDoc.model_construct(**data)


def from_jwks_key(key: JwksKey, *, include_id: bool = True) -> JwksKeyDoc:
    data = key.model_dump(exclude={"id"})
    if include_id:
        data["id"] = document_id(key.id)
    return JwksKeyDoc.model_construct(**data)


def from_audit_log(row: AuditLog, *, include_id: bool = True) -> AuditLogDoc:
    data = row.model_dump(exclude={"id", "user_id"})
    if include_id:
        data["id"] = document_id(row.id)
    if row.user_id is not None:
        data["user_id"] = require_object_id(row.user_id)
    return AuditLogDoc.model_construct(**data)


def from_rate_limit(rate_limit: RateLimit, *, include_id: bool = True) -> RateLimitDoc:
    data = rate_limit.model_dump(exclude={"id"})
    if include_id:
        data["id"] = document_id(rate_limit.id)
    return RateLimitDoc.model_construct(**data)


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
