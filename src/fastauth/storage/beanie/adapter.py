"""The MongoDB/Beanie implementation of :class:`DatabaseAdapter`.

**Native MongoDB identity convention.** Every primary key (``_id``), every
foreign-key field (``*_id``), and every Mongo-owned relation id used for
rotation is a real ``bson.ObjectId`` in BSON. The Pydantic domain
layer (:mod:`fastauth.domain.models`) keeps these as ``str`` for storage
agnosticism and stable wire format — this adapter does the string⇄ObjectId
conversion at its boundary. See CONTRIBUTING.md rule #5.

Mongo-owned ids stored as ObjectId in BSON:

* ``Session.user_id``        → ``users._id``
* ``RefreshToken.user_id``   → ``users._id``
* ``RefreshToken.family_id`` → ``refresh_tokens._id`` family chain root
* ``RefreshToken.replaced_by`` → ``refresh_tokens._id`` successor id
* ``Account.user_id``        → ``users._id``
* ``ApiKey.user_id``         → ``users._id``
* ``AuditLog.user_id``       → ``users._id`` (nullable)

Non-FK identifier-shaped fields stay as strings because they are not Mongo
references: ``Account.account_id`` (provider-side identifier),
``Verification.identifier`` (email/username), the various ``*_hash`` columns
(content-derived hashes), ``JwksKey.kid`` (JOSE key id), ``RateLimit.key``
(composite IP+path bucket).
"""

from __future__ import annotations

from collections.abc import AsyncGenerator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from beanie import PydanticObjectId
from fastapi import FastAPI
from pymongo import ReturnDocument
from pymongo.asynchronous.database import AsyncDatabase
from pymongo.errors import DuplicateKeyError

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
)
from fastauth.exceptions import DuplicateError, NotFoundError
from fastauth.storage.beanie.documents import (
    AccountDoc,
    ApiKeyDoc,
    AuditLogDoc,
    BeanieDocumentModels,
    JwksKeyDoc,
    RateLimitDoc,
    RefreshTokenDoc,
    SessionDoc,
    UserDoc,
    VerificationDoc,
    from_account,
    from_api_key,
    from_audit_log,
    from_jwks_key,
    from_rate_limit,
    from_session,
    from_user,
    from_verification,
    init_beanie_documents,
    to_account,
    to_api_key,
    to_audit_log,
    to_jwks_key,
    to_rate_limit,
    to_refresh_token,
    to_session,
    to_user,
    to_verification,
)
from fastauth.storage.beanie.helpers import (
    apply_model_updates,
    normalise_datetimes,
    require_object_id,
    to_object_id_or_none,
    to_pydantic_object_id_or_none,
    truncate_to_millis,
)

__all__ = ["BeanieAdapter"]

if TYPE_CHECKING:
    from fastauth.runtime.auth import FastAuth


class BeanieAdapter:
    """DatabaseAdapter backed by MongoDB via Beanie ODM.

    All PK/FK conversions happen at this boundary; the caller's
    :mod:`fastauth.domain.models` instances stay storage-agnostic strings.
    """

    def __init__(
        self,
        database: AsyncDatabase[Any],
        *,
        collection_prefix: str = "",
        collection_suffix: str = "",
    ) -> None:
        self.database = database
        self.collection_prefix = collection_prefix
        self.collection_suffix = collection_suffix
        self.documents = BeanieDocumentModels(
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
        self.user_doc: Any = self.documents.user
        self.session_doc: Any = self.documents.session
        self.refresh_token_doc: Any = self.documents.refresh_token
        self.account_doc: Any = self.documents.account
        self.verification_doc: Any = self.documents.verification
        self.api_key_doc: Any = self.documents.api_key
        self.jwks_key_doc: Any = self.documents.jwks_key
        self.audit_log_doc: Any = self.documents.audit_log
        self.rate_limit_doc: Any = self.documents.rate_limit

    def lifespan(self, auth: FastAuth) -> Callable[[FastAPI], AbstractAsyncContextManager[None]]:
        """Return a FastAPI lifespan that initialises Beanie, then fastauth.

        This is a lower-level escape hatch for manually constructed adapters:

        ``app = FastAPI(lifespan=adapter.lifespan(auth))``

        Application code should normally prefer ``FastAuthOptions`` with
        ``database=mongo(database)`` and then use ``auth.lifespan``.

        It keeps Beanie-specific bootstrap in the Beanie adapter package while
        preserving ``FastAuth`` as storage-agnostic runtime code.
        """

        @asynccontextmanager
        async def app_lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
            await init_beanie_documents(
                self.database,
                collection_prefix=self.collection_prefix,
                collection_suffix=self.collection_suffix,
            )
            async with auth.lifespan(app):
                yield

        return app_lifespan

    # ----- User -----
    async def create_user(self, user: User) -> User:
        normalise_datetimes(user)
        # Drop the domain-side ``id`` (UUID-hex from ``new_id()``) so Beanie generates
        # a fresh ObjectId. The new id is written back into the input model below.
        doc = from_user(user, include_id=False)
        try:
            await doc.insert()
        except DuplicateKeyError as exc:
            raise DuplicateError(resource="user", field="email") from exc
        if doc.id is not None:
            user.id = str(doc.id)
        return user

    async def get_user_by_id(self, user_id: str) -> User | None:
        oid = to_object_id_or_none(user_id)
        if oid is None:
            return None
        doc = await self.user_doc.find_one(self.user_doc.id == oid)
        return to_user(doc) if doc else None

    async def get_user_by_email(self, email: str) -> User | None:
        doc = await self.user_doc.find_one({"email": email})
        return to_user(doc) if doc else None

    async def get_user_by_username(self, username: str) -> User | None:
        doc = await self.user_doc.find_one({"username": username})
        return to_user(doc) if doc else None

    async def find_user_by_pending_email_change(self, new_email: str) -> User | None:
        doc = await self.user_doc.find_one({"pending_email_change": new_email})
        return to_user(doc) if doc else None

    async def update_user(self, user: User) -> User:
        oid = to_object_id_or_none(user.id)
        if oid is None:
            raise NotFoundError(resource="user")
        doc = await self.user_doc.find_one(self.user_doc.id == oid)
        if doc is None:
            raise NotFoundError(resource="user")
        user.updated_at = datetime.now(UTC)
        normalise_datetimes(user)
        apply_model_updates(doc, user)
        await doc.replace()
        return user

    async def delete_user(self, user_id: str) -> None:
        oid = to_object_id_or_none(user_id)
        if oid is None:
            return
        doc = await self.user_doc.find_one(self.user_doc.id == oid)
        if doc is None:
            return
        identifiers = {doc.email}
        if doc.pending_email_change is not None:
            identifiers.add(str(doc.pending_email_change))
        await self.session_doc.find({"user_id": oid}).delete()
        await self.refresh_token_doc.find({"user_id": oid}).delete()
        await self.account_doc.find({"user_id": oid}).delete()
        await self.api_key_doc.find({"user_id": oid}).delete()
        if identifiers:
            await self.verification_doc.find({"identifier": {"$in": list(identifiers)}}).delete()
        await doc.delete()

    # ----- Session -----
    async def create_session(self, session: Session) -> Session:
        normalise_datetimes(session)
        # ``user_id`` must be a valid ObjectId hex (set from a prior ``create_user``
        # call). The document mapper raises with a clear error if not.
        doc = from_session(session, include_id=False)
        await doc.insert()
        if doc.id is not None:
            session.id = str(doc.id)
        return session

    async def get_session_by_token_hash(self, token_hash: str) -> Session | None:
        doc = await self.session_doc.find_one({"token_hash": token_hash})
        return to_session(doc) if doc else None

    async def list_sessions_for_user(self, user_id: str) -> list[Session]:
        oid = to_object_id_or_none(user_id)
        if oid is None:
            return []
        docs = await self.session_doc.find({"user_id": oid}).to_list()
        return [to_session(doc) for doc in docs]

    async def update_session(self, session: Session) -> Session:
        oid = to_object_id_or_none(session.id)
        if oid is None:
            raise NotFoundError(resource="session")
        doc = await self.session_doc.find_one(self.session_doc.id == oid)
        if doc is None:
            raise NotFoundError(resource="session")
        session.updated_at = datetime.now(UTC)
        normalise_datetimes(session)
        apply_model_updates(doc, session)
        await doc.replace()
        return session

    async def delete_session(self, session_id: str) -> None:
        oid = to_object_id_or_none(session_id)
        if oid is None:
            return
        doc = await self.session_doc.find_one(self.session_doc.id == oid)
        if doc:
            await doc.delete()

    async def delete_sessions_for_user(
        self,
        user_id: str,
        *,
        except_session_id: str | None = None,
    ) -> int:
        oid = to_object_id_or_none(user_id)
        if oid is None:
            return 0
        query: dict[str, object] = {"user_id": oid}
        if except_session_id is not None:
            except_oid = to_object_id_or_none(except_session_id)
            if except_oid is not None:
                query["_id"] = {"$ne": except_oid}
        result = await self.session_doc.find(query).delete()
        return int(result.deleted_count) if result and result.deleted_count else 0

    # ----- RefreshToken -----
    async def create_refresh_token(self, token: RefreshToken) -> RefreshToken:
        normalise_datetimes(token)
        data = token.model_dump(exclude={"id"})
        doc_id = to_pydantic_object_id_or_none(token.id) or PydanticObjectId()
        family_id = to_object_id_or_none(token.family_id)
        if family_id is None:
            if token.family_id != token.id:
                raise ValueError("refresh token family_id must reference a token id")
            family_id = doc_id
        data["user_id"] = require_object_id(token.user_id)
        data["family_id"] = family_id
        if token.replaced_by is not None:
            data["replaced_by"] = require_object_id(token.replaced_by)
        doc = self.refresh_token_doc(**data)
        doc.id = doc_id
        await doc.insert()
        token.id = str(doc.id)
        token.family_id = str(doc.family_id)
        if doc.replaced_by is not None:
            token.replaced_by = str(doc.replaced_by)
        return token

    async def get_refresh_token_by_hash(self, token_hash: str) -> RefreshToken | None:
        doc = await self.refresh_token_doc.find_one({"token_hash": token_hash})
        return to_refresh_token(doc) if doc else None

    async def update_refresh_token(self, token: RefreshToken) -> RefreshToken:
        oid = to_object_id_or_none(token.id)
        if oid is None:
            raise NotFoundError(resource="refresh_token")
        doc = await self.refresh_token_doc.find_one(self.refresh_token_doc.id == oid)
        if doc is None:
            raise NotFoundError(resource="refresh_token")
        token.updated_at = datetime.now(UTC)
        normalise_datetimes(token)
        apply_model_updates(doc, token)
        await doc.replace()
        return token

    async def rotate_refresh_token(
        self,
        *,
        current_token_id: str,
        new_token: RefreshToken,
        consumed_at: datetime,
    ) -> RefreshToken | None:
        oid = to_object_id_or_none(current_token_id)
        if oid is None:
            return None
        normalise_datetimes(new_token)
        data = new_token.model_dump(exclude={"id"})
        data["user_id"] = require_object_id(new_token.user_id)
        data["family_id"] = require_object_id(new_token.family_id)
        new_oid = PydanticObjectId()
        new_token.id = str(new_oid)
        doc = self.refresh_token_doc(**data)
        doc.id = new_oid
        await doc.insert()
        result = await self.database[self.refresh_token_doc.Settings.name].update_one(
            {"_id": oid, "consumed_at": None},
            {
                "$set": {
                    "consumed_at": truncate_to_millis(consumed_at),
                    "replaced_by": new_oid,
                    "updated_at": truncate_to_millis(datetime.now(UTC)),
                },
            },
        )
        if result.modified_count == 1:
            return new_token
        await doc.delete()
        return None

    async def delete_refresh_token(self, token_id: str) -> None:
        oid = to_object_id_or_none(token_id)
        if oid is None:
            return
        await self.refresh_token_doc.find_one(self.refresh_token_doc.id == oid).delete()

    async def delete_refresh_tokens_for_user(self, user_id: str) -> int:
        oid = to_object_id_or_none(user_id)
        if oid is None:
            return 0
        result = await self.refresh_token_doc.find({"user_id": oid}).delete()
        return int(result.deleted_count) if result and result.deleted_count else 0

    async def delete_refresh_tokens_in_family(self, family_id: str) -> int:
        oid = to_object_id_or_none(family_id)
        if oid is None:
            return 0
        result = await self.refresh_token_doc.find({"family_id": oid}).delete()
        return int(result.deleted_count) if result and result.deleted_count else 0

    # ----- Account -----
    async def create_account(self, account: Account) -> Account:
        normalise_datetimes(account)
        doc = from_account(account, include_id=False)
        await doc.insert()
        if doc.id is not None:
            account.id = str(doc.id)
        return account

    async def get_account_for_user(
        self,
        user_id: str,
        provider_id: ProviderId,
    ) -> Account | None:
        oid = to_object_id_or_none(user_id)
        if oid is None:
            return None
        doc = await self.account_doc.find_one(
            {"user_id": oid, "provider_id": provider_id.value},
        )
        return to_account(doc) if doc else None

    async def list_accounts_for_user(self, user_id: str) -> list[Account]:
        oid = to_object_id_or_none(user_id)
        if oid is None:
            return []
        docs = await self.account_doc.find({"user_id": oid}).to_list()
        return [to_account(doc) for doc in docs]

    async def update_account(self, account: Account) -> Account:
        oid = to_object_id_or_none(account.id)
        if oid is None:
            raise NotFoundError(resource="account")
        doc = await self.account_doc.find_one(self.account_doc.id == oid)
        if doc is None:
            raise NotFoundError(resource="account")
        account.updated_at = datetime.now(UTC)
        normalise_datetimes(account)
        apply_model_updates(doc, account)
        await doc.replace()
        return account

    async def delete_account(self, account_id: str) -> None:
        oid = to_object_id_or_none(account_id)
        if oid is None:
            return
        doc = await self.account_doc.find_one(self.account_doc.id == oid)
        if doc:
            await doc.delete()

    # ----- Verification -----
    async def create_verification(self, verification: Verification) -> Verification:
        normalise_datetimes(verification)
        doc = from_verification(verification, include_id=False)
        await doc.insert()
        if doc.id is not None:
            verification.id = str(doc.id)
        return verification

    async def get_verification(
        self,
        identifier: str,
        purpose: VerificationPurpose,
        value_hash: str,
    ) -> Verification | None:
        doc = await self.verification_doc.find_one(
            {
                "identifier": identifier,
                "purpose": purpose.value,
                "value_hash": value_hash,
            },
        )
        return to_verification(doc) if doc else None

    async def get_active_verification(
        self,
        identifier: str,
        purpose: VerificationPurpose,
    ) -> Verification | None:
        doc = (
            await self.verification_doc.find(
                {"identifier": identifier, "purpose": purpose.value},
            )
            .sort("-created_at")
            .first_or_none()
        )
        return to_verification(doc) if doc else None

    async def update_verification(self, verification: Verification) -> Verification:
        oid = to_object_id_or_none(verification.id)
        if oid is None:
            raise NotFoundError(resource="verification")
        doc = await self.verification_doc.find_one(self.verification_doc.id == oid)
        if doc is None:
            raise NotFoundError(resource="verification")
        verification.updated_at = datetime.now(UTC)
        normalise_datetimes(verification)
        apply_model_updates(doc, verification)
        await doc.replace()
        return verification

    async def delete_verification(self, verification_id: str) -> None:
        oid = to_object_id_or_none(verification_id)
        if oid is None:
            return
        doc = await self.verification_doc.find_one(self.verification_doc.id == oid)
        if doc:
            await doc.delete()

    async def delete_verifications_for_identifier(
        self,
        identifier: str,
        purpose: VerificationPurpose,
    ) -> int:
        result = await self.verification_doc.find(
            {"identifier": identifier, "purpose": purpose.value},
        ).delete()
        return int(result.deleted_count) if result and result.deleted_count else 0

    # ----- ApiKey -----
    async def create_api_key(self, api_key: ApiKey) -> ApiKey:
        normalise_datetimes(api_key)
        doc = from_api_key(api_key, include_id=False)
        await doc.insert()
        if doc.id is not None:
            api_key.id = str(doc.id)
        return api_key

    async def get_api_key_by_hash(self, key_hash: str) -> ApiKey | None:
        doc = await self.api_key_doc.find_one({"key_hash": key_hash})
        return to_api_key(doc) if doc else None

    async def get_api_key_by_id(self, api_key_id: str) -> ApiKey | None:
        oid = to_object_id_or_none(api_key_id)
        if oid is None:
            return None
        doc = await self.api_key_doc.find_one(self.api_key_doc.id == oid)
        return to_api_key(doc) if doc else None

    async def list_api_keys_for_user(
        self,
        user_id: str,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[ApiKey], int]:
        oid = to_object_id_or_none(user_id)
        if oid is None:
            return [], 0
        cursor = self.api_key_doc.find({"user_id": oid})
        total = await cursor.count()
        docs = await cursor.skip(offset).limit(limit).to_list()
        return [to_api_key(doc) for doc in docs], total

    async def update_api_key(self, api_key: ApiKey) -> ApiKey:
        oid = to_object_id_or_none(api_key.id)
        if oid is None:
            raise NotFoundError(resource="api_key")
        doc = await self.api_key_doc.find_one(self.api_key_doc.id == oid)
        if doc is None:
            raise NotFoundError(resource="api_key")
        api_key.updated_at = datetime.now(UTC)
        normalise_datetimes(api_key)
        apply_model_updates(doc, api_key)
        await doc.replace()
        return api_key

    async def delete_api_key(self, api_key_id: str) -> None:
        oid = to_object_id_or_none(api_key_id)
        if oid is None:
            return
        doc = await self.api_key_doc.find_one(self.api_key_doc.id == oid)
        if doc:
            await doc.delete()

    async def delete_expired_api_keys(self) -> int:
        result = await self.api_key_doc.find({"expires_at": {"$lt": datetime.now(UTC)}}).delete()
        return int(result.deleted_count) if result and result.deleted_count else 0

    # ----- JwksKey -----
    async def create_jwks_key(self, key: JwksKey) -> JwksKey:
        normalise_datetimes(key)
        doc = from_jwks_key(key, include_id=False)
        await doc.insert()
        if doc.id is not None:
            key.id = str(doc.id)
        return key

    async def list_jwks_keys(self) -> list[JwksKey]:
        docs = await self.jwks_key_doc.find_all().to_list()
        return [to_jwks_key(doc) for doc in docs]

    async def update_jwks_key(self, key: JwksKey) -> JwksKey:
        oid = to_object_id_or_none(key.id)
        if oid is None:
            raise NotFoundError(resource="jwks_key")
        doc = await self.jwks_key_doc.find_one(self.jwks_key_doc.id == oid)
        if doc is None:
            raise NotFoundError(resource="jwks_key")
        normalise_datetimes(key)
        apply_model_updates(doc, key)
        await doc.replace()
        return key

    async def delete_jwks_key(self, key_id: str) -> None:
        oid = to_object_id_or_none(key_id)
        if oid is None:
            return
        doc = await self.jwks_key_doc.find_one(self.jwks_key_doc.id == oid)
        if doc:
            await doc.delete()

    # ----- AuditLog -----
    async def create_audit_log(self, row: AuditLog) -> AuditLog:
        normalise_datetimes(row)
        doc = from_audit_log(row, include_id=False)
        await doc.insert()
        if doc.id is not None:
            row.id = str(doc.id)
        return row

    async def list_audit_logs(
        self,
        *,
        user_id: str | None,
        event_type: AuditEventType | None,
        identifier: str | None,
        limit: int,
        offset: int,
    ) -> tuple[list[AuditLog], int]:
        query: dict[str, object] = {}
        if user_id is not None:
            oid = to_object_id_or_none(user_id)
            if oid is None:
                return [], 0
            query["user_id"] = oid
        if event_type is not None:
            query["event_type"] = event_type.value
        if identifier is not None:
            query["identifier"] = identifier
        cursor = self.audit_log_doc.find(query)
        total = await cursor.count()
        docs = await cursor.sort("-created_at").skip(offset).limit(limit).to_list()
        return [to_audit_log(doc) for doc in docs], total

    # ----- RateLimit -----
    async def get_rate_limit(self, key: str) -> RateLimit | None:
        doc = await self.rate_limit_doc.find_one({"key": key})
        return to_rate_limit(doc) if doc else None

    async def increment_rate_limit(
        self,
        key: str,
        *,
        window_ms: int,
        now_ms: int,
    ) -> tuple[int, int]:
        threshold_ms = now_ms - window_ms
        collection = self.database[self.rate_limit_doc.Settings.name]
        row = await collection.find_one_and_update(
            {"key": key},
            [
                {
                    "$set": {
                        "key": key,
                        "count": {
                            "$cond": [
                                {
                                    "$lte": [
                                        {"$ifNull": ["$last_request_ms", 0]},
                                        threshold_ms,
                                    ],
                                },
                                1,
                                {"$add": [{"$ifNull": ["$count", 0]}, 1]},
                            ],
                        },
                        "last_request_ms": now_ms,
                    },
                },
            ],
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )
        if row is None:
            raise RuntimeError("rate-limit increment failed")
        return int(row["count"]), int(row["last_request_ms"]) - window_ms

    async def upsert_rate_limit(self, rate_limit: RateLimit) -> RateLimit:
        doc = await self.rate_limit_doc.find_one({"key": rate_limit.key})
        if doc is None:
            new_doc = from_rate_limit(rate_limit, include_id=False)
            await new_doc.insert()
            if new_doc.id is not None:
                rate_limit.id = str(new_doc.id)
        else:
            await doc.set(
                {
                    "count": rate_limit.count,
                    "last_request_ms": rate_limit.last_request_ms,
                },
            )
        return rate_limit

    async def delete_rate_limit(self, key: str) -> None:
        doc = await self.rate_limit_doc.find_one({"key": key})
        if doc:
            await doc.delete()
