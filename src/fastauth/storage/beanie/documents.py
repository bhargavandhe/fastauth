"""Beanie ``Document`` subclasses + Doc→domain conversion helpers.

Each Doc subclass overrides the parent Pydantic model's ``id: str`` (and
Mongo-owned relation ids where applicable) with ``PydanticObjectId``,
aliased to ``_id`` for the primary key. Beanie/PyMongo then store these as
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

from dataclasses import dataclass
from functools import lru_cache
from hashlib import blake2s
from typing import Any, ClassVar, cast

import pymongo
from beanie import (  # pyright: ignore[reportUnknownVariableType]
    Document,
    PydanticObjectId,
    init_beanie,  # pyright: ignore[reportUnknownVariableType]
)
from pydantic import Field
from pymongo import IndexModel
from pymongo.asynchronous.database import AsyncDatabase

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
    "BeanieDocumentModels",
    "JwksKeyDoc",
    "RateLimitDoc",
    "RefreshTokenDoc",
    "SessionDoc",
    "UserDoc",
    "VerificationDoc",
    "build_beanie_document_models",
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


def build_document_settings(name: str, indexes: list[IndexModel]) -> type:
    return type(
        "Settings",
        (),
        {
            "__annotations__": {"indexes": ClassVar[list[IndexModel]]},
            "name": name,
            "indexes": indexes,
        },
    )


def build_document_class(
    *,
    class_name: str,
    domain_model: type[Any],
    collection_name: str,
    indexes: list[IndexModel],
    annotations: dict[str, Any],
) -> type[Document]:
    namespace: dict[str, Any] = {
        "__module__": __name__,
        "__annotations__": {
            **annotations,
            "Settings": ClassVar[type],
        },
        "id": Field(default=None, alias="_id"),
        "Settings": build_document_settings(collection_name, indexes),
    }
    if "replaced_by" in annotations:
        namespace["replaced_by"] = None
    if "user_id" in annotations and annotations["user_id"] == PydanticObjectId | None:
        namespace["user_id"] = None
    return cast(type[Document], type(class_name, (domain_model, Document), namespace))


@lru_cache(maxsize=128)
def build_beanie_document_models(
    *,
    collection_prefix: str = "",
    collection_suffix: str = "",
) -> BeanieDocumentModels:
    if collection_prefix == "" and collection_suffix == "":
        return DEFAULT_DOCUMENT_MODELS

    digest = blake2s(f"{collection_prefix}\0{collection_suffix}".encode()).hexdigest()[:10]

    return BeanieDocumentModels(
        user=build_document_class(
            class_name=f"UserDoc_{digest}",
            domain_model=User,
            collection_name=build_collection_name("users", collection_prefix, collection_suffix),
            indexes=UserDoc.Settings.indexes,
            annotations={"id": PydanticObjectId | None},
        ),
        session=build_document_class(
            class_name=f"SessionDoc_{digest}",
            domain_model=Session,
            collection_name=build_collection_name(
                "sessions",
                collection_prefix,
                collection_suffix,
            ),
            indexes=SessionDoc.Settings.indexes,
            annotations={
                "id": PydanticObjectId | None,
                "user_id": PydanticObjectId,
            },
        ),
        refresh_token=build_document_class(
            class_name=f"RefreshTokenDoc_{digest}",
            domain_model=RefreshToken,
            collection_name=build_collection_name(
                "refresh_tokens",
                collection_prefix,
                collection_suffix,
            ),
            indexes=RefreshTokenDoc.Settings.indexes,
            annotations={
                "id": PydanticObjectId | None,
                "user_id": PydanticObjectId,
                "family_id": PydanticObjectId,
                "replaced_by": PydanticObjectId | None,
            },
        ),
        account=build_document_class(
            class_name=f"AccountDoc_{digest}",
            domain_model=Account,
            collection_name=build_collection_name(
                "accounts",
                collection_prefix,
                collection_suffix,
            ),
            indexes=AccountDoc.Settings.indexes,
            annotations={
                "id": PydanticObjectId | None,
                "user_id": PydanticObjectId,
            },
        ),
        verification=build_document_class(
            class_name=f"VerificationDoc_{digest}",
            domain_model=Verification,
            collection_name=build_collection_name(
                "verifications",
                collection_prefix,
                collection_suffix,
            ),
            indexes=VerificationDoc.Settings.indexes,
            annotations={"id": PydanticObjectId | None},
        ),
        api_key=build_document_class(
            class_name=f"ApiKeyDoc_{digest}",
            domain_model=ApiKey,
            collection_name=build_collection_name("api_keys", collection_prefix, collection_suffix),
            indexes=ApiKeyDoc.Settings.indexes,
            annotations={
                "id": PydanticObjectId | None,
                "user_id": PydanticObjectId,
            },
        ),
        jwks_key=build_document_class(
            class_name=f"JwksKeyDoc_{digest}",
            domain_model=JwksKey,
            collection_name=build_collection_name(
                "jwks_keys",
                collection_prefix,
                collection_suffix,
            ),
            indexes=JwksKeyDoc.Settings.indexes,
            annotations={"id": PydanticObjectId | None},
        ),
        audit_log=build_document_class(
            class_name=f"AuditLogDoc_{digest}",
            domain_model=AuditLog,
            collection_name=build_collection_name(
                "audit_logs",
                collection_prefix,
                collection_suffix,
            ),
            indexes=AuditLogDoc.Settings.indexes,
            annotations={
                "id": PydanticObjectId | None,
                "user_id": PydanticObjectId | None,
            },
        ),
        rate_limit=build_document_class(
            class_name=f"RateLimitDoc_{digest}",
            domain_model=RateLimit,
            collection_name=build_collection_name(
                "rate_limits",
                collection_prefix,
                collection_suffix,
            ),
            indexes=RateLimitDoc.Settings.indexes,
            annotations={"id": PydanticObjectId | None},
        ),
    )


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
