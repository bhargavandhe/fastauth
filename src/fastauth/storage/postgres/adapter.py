"""Postgres storage adapter implemented with SQLAlchemy Core."""

from __future__ import annotations

from collections.abc import AsyncGenerator, Callable, Mapping
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Protocol, TypeVar, cast

from fastapi import FastAPI
from sqlalchemy import and_, delete, func, insert, select, update
from sqlalchemy.dialects.postgresql import insert as postgres_insert
from sqlalchemy.engine import RowMapping
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine
from sqlalchemy.sql import Select
from sqlalchemy.sql.schema import Table

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
from fastauth.storage.base import (
    ApiKeyStore,
    AuditLogStore,
    BaseDatabaseAdapter,
    JwksKeyStore,
    RateLimitStore,
)
from fastauth.storage.postgres.migrations import (
    CURRENT_SCHEMA_VERSION,
    pending_postgres_migrations,
)
from fastauth.storage.postgres.schema import build_postgres_schema

__all__ = ["PostgresAdapter"]


MIGRATION_ADVISORY_LOCK_ID = 464_901_337

if TYPE_CHECKING:
    from fastauth.runtime.auth import FastAuth

T = TypeVar("T")


class ModelDumpable(Protocol):
    def model_dump(self) -> dict[str, Any]: ...


def current_utc_time() -> datetime:
    return datetime.now(UTC)


def row_data(row: RowMapping) -> dict[str, Any]:
    return dict(row)


def model_data(model: ModelDumpable, *, enum_fields: tuple[str, ...] = ()) -> dict[str, Any]:
    data = model.model_dump()
    for field in enum_fields:
        value = data.get(field)
        if value is not None:
            data[field] = value.value
    return data


def row_to_user(row: RowMapping) -> User:
    return User.model_validate(row_data(row))


def row_to_session(row: RowMapping) -> Session:
    return Session.model_validate(row_data(row))


def row_to_refresh_token(row: RowMapping) -> RefreshToken:
    return RefreshToken.model_validate(row_data(row))


def row_to_account(row: RowMapping) -> Account:
    data = row_data(row)
    data["provider_id"] = ProviderId(data["provider_id"])
    return Account.model_validate(data)


def row_to_verification(row: RowMapping) -> Verification:
    data = row_data(row)
    data["purpose"] = VerificationPurpose(data["purpose"])
    return Verification.model_validate(data)


def row_to_api_key(row: RowMapping) -> ApiKey:
    return ApiKey.model_validate(row_data(row))


def row_to_jwks_key(row: RowMapping) -> JwksKey:
    data = row_data(row)
    private_key = data["private_key_encrypted"]
    if isinstance(private_key, memoryview):
        data["private_key_encrypted"] = private_key.tobytes()
    return JwksKey.model_validate(data)


def row_to_audit_log(row: RowMapping) -> AuditLog:
    data = row_data(row)
    data["event_type"] = AuditEventType(data["event_type"])
    return AuditLog.model_validate(data)


def row_to_rate_limit(row: RowMapping) -> RateLimit:
    return RateLimit.model_validate(row_data(row))


class PostgresAdapter(
    BaseDatabaseAdapter,
    ApiKeyStore,
    JwksKeyStore,
    AuditLogStore,
    RateLimitStore,
):
    """Async Postgres adapter backed by SQLAlchemy Core.

    FastAuth domain IDs are persisted as strings. The adapter does not read
    environment variables; callers pass an ``AsyncEngine`` or explicit URL.
    """

    def __init__(
        self,
        engine: AsyncEngine,
        *,
        table_prefix: str = "fastauth_",
        table_suffix: str = "",
    ) -> None:
        self.engine = engine
        self.schema = build_postgres_schema(table_prefix, table_suffix)

    @classmethod
    def from_url(
        cls,
        url: str,
        *,
        table_prefix: str = "fastauth_",
        table_suffix: str = "",
        **engine_kwargs: object,
    ) -> PostgresAdapter:
        return cls(
            create_async_engine(url, **cast(dict[str, Any], engine_kwargs)),
            table_prefix=table_prefix,
            table_suffix=table_suffix,
        )

    async def create_schema_migrations_table(self, connection: AsyncConnection) -> None:
        await connection.run_sync(self.schema.schema_migrations.create, checkfirst=True)

    async def lock_migrations(self, connection: AsyncConnection) -> None:
        await connection.execute(select(func.pg_advisory_xact_lock(MIGRATION_ADVISORY_LOCK_ID)))

    async def schema_version_for_connection(self, connection: AsyncConnection) -> int:
        result = await connection.execute(
            select(
                func.coalesce(
                    func.max(self.schema.schema_migrations.c.version),
                    0,
                )
            )
        )
        return int(result.scalar_one())

    async def schema_version(self) -> int:
        async with self.engine.begin() as connection:
            await self.create_schema_migrations_table(connection)
            return await self.schema_version_for_connection(connection)

    async def apply_migrations(self) -> list[int]:
        applied: list[int] = []
        async with self.engine.begin() as connection:
            await self.lock_migrations(connection)
            await self.create_schema_migrations_table(connection)
            current_version = await self.schema_version_for_connection(connection)
            for migration in pending_postgres_migrations(current_version):
                await migration.apply(connection, self.schema)
                await connection.execute(
                    postgres_insert(self.schema.schema_migrations)
                    .values(version=migration.version, applied_at=current_utc_time())
                    .on_conflict_do_nothing(
                        index_elements=[self.schema.schema_migrations.c.version],
                    )
                )
                applied.append(migration.version)
        return applied

    async def assert_schema_current(self) -> None:
        version = await self.schema_version()
        if version > CURRENT_SCHEMA_VERSION:
            raise RuntimeError(
                "Postgres fastauth schema is newer than this fastauth version; "
                "upgrade fastauth before startup."
            )
        if version < CURRENT_SCHEMA_VERSION:
            raise RuntimeError(
                "Postgres schema is behind fastauth; run "
                "`fastauth migrate --postgres-url ...` before startup."
            )

    def migration_lifespan(
        self,
        auth: FastAuth,
    ) -> Callable[[FastAPI], AbstractAsyncContextManager[None]]:
        return self.lifespan(auth, apply_migrations=True)

    def checked_lifespan(
        self,
        auth: FastAuth,
    ) -> Callable[[FastAPI], AbstractAsyncContextManager[None]]:
        return self.lifespan(auth, apply_migrations=False)

    def lifespan(
        self,
        auth: FastAuth,
        *,
        apply_migrations: bool = True,
    ) -> Callable[[FastAPI], AbstractAsyncContextManager[None]]:
        """Return a FastAPI lifespan that handles schema state, then starts fastauth.

        ``apply_migrations=True`` is convenient for examples and small
        deployments. Production deployments can pass ``False`` to fail fast
        unless ``fastauth migrate --postgres-url ...`` has already applied the
        tracked schema version.
        """

        @asynccontextmanager
        async def app_lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
            if apply_migrations:
                await self.apply_migrations()
            else:
                await self.assert_schema_current()
            async with auth.lifespan(app):
                yield

        return app_lifespan

    async def fetch_one_or_none(
        self,
        statement: Select[tuple[Any, ...]],
        converter: Callable[[RowMapping], T],
    ) -> T | None:
        async with self.engine.begin() as connection:
            result = await connection.execute(statement)
            row = result.mappings().one_or_none()
        return converter(row) if row is not None else None

    async def insert_row(
        self,
        table: Table,
        data: Mapping[str, Any],
        converter: Callable[[RowMapping], T],
        *,
        duplicate_resource: str,
        duplicate_field: str,
    ) -> T:
        try:
            async with self.engine.begin() as connection:
                result = await connection.execute(
                    insert(table).values(**data).returning(*table.c),
                )
                row = result.mappings().one()
        except IntegrityError as exc:
            raise DuplicateError(resource=duplicate_resource, field=duplicate_field) from exc
        return converter(row)

    async def update_row_by_id(
        self,
        table: Table,
        row_id: str,
        data: Mapping[str, Any],
        converter: Callable[[RowMapping], T],
        *,
        resource: str,
    ) -> T:
        async with self.engine.begin() as connection:
            result = await connection.execute(
                update(table)
                .where(table.c.id == row_id)
                .values(**data)
                .returning(*table.c),
            )
            row = result.mappings().one_or_none()
        if row is None:
            raise NotFoundError(resource=resource)
        return converter(row)

    async def create_user(self, user: User) -> User:
        return await self.insert_row(
            self.schema.users,
            model_data(user),
            row_to_user,
            duplicate_resource="user",
            duplicate_field="email",
        )

    async def get_user_by_id(self, user_id: str) -> User | None:
        return await self.fetch_one_or_none(
            select(self.schema.users).where(self.schema.users.c.id == user_id),
            row_to_user,
        )

    async def get_user_by_email(self, email: str) -> User | None:
        return await self.fetch_one_or_none(
            select(self.schema.users).where(self.schema.users.c.email == email),
            row_to_user,
        )

    async def get_user_by_username(self, username: str) -> User | None:
        return await self.fetch_one_or_none(
            select(self.schema.users).where(self.schema.users.c.username == username),
            row_to_user,
        )

    async def find_user_by_pending_email_change(self, new_email: str) -> User | None:
        return await self.fetch_one_or_none(
            select(self.schema.users).where(
                self.schema.users.c.pending_email_change == new_email,
            ),
            row_to_user,
        )

    async def update_user(self, user: User) -> User:
        user.updated_at = current_utc_time()
        return await self.update_row_by_id(
            self.schema.users,
            user.id,
            model_data(user),
            row_to_user,
            resource="user",
        )

    async def delete_user(self, user_id: str) -> None:
        async with self.engine.begin() as connection:
            result = await connection.execute(
                select(
                    self.schema.users.c.email,
                    self.schema.users.c.pending_email_change,
                ).where(self.schema.users.c.id == user_id),
            )
            row = result.mappings().first()
            if row is not None:
                identifiers = [row["email"]]
                if row["pending_email_change"] is not None:
                    identifiers.append(row["pending_email_change"])
                await connection.execute(
                    delete(self.schema.verifications).where(
                        self.schema.verifications.c.identifier.in_(identifiers),
                    ),
                )
            await connection.execute(
                delete(self.schema.users).where(self.schema.users.c.id == user_id),
            )

    async def create_session(self, session: Session) -> Session:
        return await self.insert_row(
            self.schema.sessions,
            model_data(session),
            row_to_session,
            duplicate_resource="session",
            duplicate_field="token_hash",
        )

    async def get_session_by_token_hash(self, token_hash: str) -> Session | None:
        return await self.fetch_one_or_none(
            select(self.schema.sessions).where(self.schema.sessions.c.token_hash == token_hash),
            row_to_session,
        )

    async def list_sessions_for_user(self, user_id: str) -> list[Session]:
        async with self.engine.begin() as connection:
            result = await connection.execute(
                select(self.schema.sessions).where(self.schema.sessions.c.user_id == user_id),
            )
            return [row_to_session(row) for row in result.mappings()]

    async def update_session(self, session: Session) -> Session:
        session.updated_at = current_utc_time()
        return await self.update_row_by_id(
            self.schema.sessions,
            session.id,
            model_data(session),
            row_to_session,
            resource="session",
        )

    async def delete_session(self, session_id: str) -> None:
        async with self.engine.begin() as connection:
            await connection.execute(
                delete(self.schema.sessions).where(self.schema.sessions.c.id == session_id),
            )

    async def delete_sessions_for_user(
        self,
        user_id: str,
        *,
        except_session_id: str | None = None,
    ) -> int:
        predicate = self.schema.sessions.c.user_id == user_id
        if except_session_id is not None:
            predicate = and_(predicate, self.schema.sessions.c.id != except_session_id)
        async with self.engine.begin() as connection:
            result = await connection.execute(delete(self.schema.sessions).where(predicate))
        return int(result.rowcount or 0)

    async def create_refresh_token(self, token: RefreshToken) -> RefreshToken:
        return await self.insert_row(
            self.schema.refresh_tokens,
            model_data(token),
            row_to_refresh_token,
            duplicate_resource="refresh_token",
            duplicate_field="token_hash",
        )

    async def get_refresh_token_by_hash(self, token_hash: str) -> RefreshToken | None:
        return await self.fetch_one_or_none(
            select(self.schema.refresh_tokens).where(
                self.schema.refresh_tokens.c.token_hash == token_hash,
            ),
            row_to_refresh_token,
        )

    async def update_refresh_token(self, token: RefreshToken) -> RefreshToken:
        token.updated_at = current_utc_time()
        return await self.update_row_by_id(
            self.schema.refresh_tokens,
            token.id,
            model_data(token),
            row_to_refresh_token,
            resource="refresh_token",
        )

    async def rotate_refresh_token(
        self,
        *,
        current_token_id: str,
        new_token: RefreshToken,
        consumed_at: datetime,
    ) -> RefreshToken | None:
        now = current_utc_time()
        new_token.updated_at = now
        async with self.engine.begin() as connection:
            result = await connection.execute(
                update(self.schema.refresh_tokens)
                .where(
                    self.schema.refresh_tokens.c.id == current_token_id,
                    self.schema.refresh_tokens.c.consumed_at.is_(None),
                )
                .values(consumed_at=consumed_at, replaced_by=new_token.id, updated_at=now)
                .returning(self.schema.refresh_tokens.c.id),
            )
            if result.first() is None:
                return None
            inserted = await connection.execute(
                insert(self.schema.refresh_tokens)
                .values(**model_data(new_token))
                .returning(*self.schema.refresh_tokens.c),
            )
            row = inserted.mappings().one()
        return row_to_refresh_token(row)

    async def delete_refresh_token(self, token_id: str) -> None:
        async with self.engine.begin() as connection:
            await connection.execute(
                delete(self.schema.refresh_tokens).where(
                    self.schema.refresh_tokens.c.id == token_id,
                ),
            )

    async def delete_refresh_tokens_for_user(self, user_id: str) -> int:
        async with self.engine.begin() as connection:
            result = await connection.execute(
                delete(self.schema.refresh_tokens).where(
                    self.schema.refresh_tokens.c.user_id == user_id,
                ),
            )
        return int(result.rowcount or 0)

    async def delete_refresh_tokens_in_family(self, family_id: str) -> int:
        async with self.engine.begin() as connection:
            result = await connection.execute(
                delete(self.schema.refresh_tokens).where(
                    self.schema.refresh_tokens.c.family_id == family_id,
                ),
            )
        return int(result.rowcount or 0)

    async def create_account(self, account: Account) -> Account:
        return await self.insert_row(
            self.schema.accounts,
            model_data(account, enum_fields=("provider_id",)),
            row_to_account,
            duplicate_resource="account",
            duplicate_field="provider_id",
        )

    async def get_account_for_user(
        self,
        user_id: str,
        provider_id: ProviderId,
    ) -> Account | None:
        return await self.fetch_one_or_none(
            select(self.schema.accounts).where(
                self.schema.accounts.c.user_id == user_id,
                self.schema.accounts.c.provider_id == provider_id.value,
            ),
            row_to_account,
        )

    async def list_accounts_for_user(self, user_id: str) -> list[Account]:
        async with self.engine.begin() as connection:
            result = await connection.execute(
                select(self.schema.accounts).where(self.schema.accounts.c.user_id == user_id),
            )
            return [row_to_account(row) for row in result.mappings()]

    async def update_account(self, account: Account) -> Account:
        account.updated_at = current_utc_time()
        return await self.update_row_by_id(
            self.schema.accounts,
            account.id,
            model_data(account, enum_fields=("provider_id",)),
            row_to_account,
            resource="account",
        )

    async def delete_account(self, account_id: str) -> None:
        async with self.engine.begin() as connection:
            await connection.execute(
                delete(self.schema.accounts).where(self.schema.accounts.c.id == account_id),
            )

    async def create_verification(self, verification: Verification) -> Verification:
        return await self.insert_row(
            self.schema.verifications,
            model_data(verification, enum_fields=("purpose",)),
            row_to_verification,
            duplicate_resource="verification",
            duplicate_field="value_hash",
        )

    async def get_verification(
        self,
        identifier: str,
        purpose: VerificationPurpose,
        value_hash: str,
    ) -> Verification | None:
        return await self.fetch_one_or_none(
            select(self.schema.verifications).where(
                self.schema.verifications.c.identifier == identifier,
                self.schema.verifications.c.purpose == purpose.value,
                self.schema.verifications.c.value_hash == value_hash,
            ),
            row_to_verification,
        )

    async def get_active_verification(
        self,
        identifier: str,
        purpose: VerificationPurpose,
    ) -> Verification | None:
        return await self.fetch_one_or_none(
            select(self.schema.verifications)
            .where(
                self.schema.verifications.c.identifier == identifier,
                self.schema.verifications.c.purpose == purpose.value,
            )
            .order_by(self.schema.verifications.c.created_at.desc())
            .limit(1),
            row_to_verification,
        )

    async def update_verification(self, verification: Verification) -> Verification:
        verification.updated_at = current_utc_time()
        return await self.update_row_by_id(
            self.schema.verifications,
            verification.id,
            model_data(verification, enum_fields=("purpose",)),
            row_to_verification,
            resource="verification",
        )

    async def delete_verification(self, verification_id: str) -> None:
        async with self.engine.begin() as connection:
            await connection.execute(
                delete(self.schema.verifications).where(
                    self.schema.verifications.c.id == verification_id,
                ),
            )

    async def delete_verifications_for_identifier(
        self,
        identifier: str,
        purpose: VerificationPurpose,
    ) -> int:
        async with self.engine.begin() as connection:
            result = await connection.execute(
                delete(self.schema.verifications).where(
                    self.schema.verifications.c.identifier == identifier,
                    self.schema.verifications.c.purpose == purpose.value,
                ),
            )
        return int(result.rowcount or 0)

    async def create_api_key(self, api_key: ApiKey) -> ApiKey:
        return await self.insert_row(
            self.schema.api_keys,
            model_data(api_key),
            row_to_api_key,
            duplicate_resource="api_key",
            duplicate_field="key_hash",
        )

    async def get_api_key_by_hash(self, key_hash: str) -> ApiKey | None:
        return await self.fetch_one_or_none(
            select(self.schema.api_keys).where(self.schema.api_keys.c.key_hash == key_hash),
            row_to_api_key,
        )

    async def get_api_key_by_id(self, api_key_id: str) -> ApiKey | None:
        return await self.fetch_one_or_none(
            select(self.schema.api_keys).where(self.schema.api_keys.c.id == api_key_id),
            row_to_api_key,
        )

    async def list_api_keys_for_user(
        self,
        user_id: str,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[ApiKey], int]:
        async with self.engine.begin() as connection:
            total_result = await connection.execute(
                select(func.count()).select_from(self.schema.api_keys).where(
                    self.schema.api_keys.c.user_id == user_id,
                ),
            )
            total = int(total_result.scalar_one())
            result = await connection.execute(
                select(self.schema.api_keys)
                .where(self.schema.api_keys.c.user_id == user_id)
                .offset(offset)
                .limit(limit),
            )
            rows = [row_to_api_key(row) for row in result.mappings()]
        return rows, total

    async def update_api_key(self, api_key: ApiKey) -> ApiKey:
        api_key.updated_at = current_utc_time()
        return await self.update_row_by_id(
            self.schema.api_keys,
            api_key.id,
            model_data(api_key),
            row_to_api_key,
            resource="api_key",
        )

    async def delete_api_key(self, api_key_id: str) -> None:
        async with self.engine.begin() as connection:
            await connection.execute(
                delete(self.schema.api_keys).where(self.schema.api_keys.c.id == api_key_id),
            )

    async def delete_expired_api_keys(self) -> int:
        async with self.engine.begin() as connection:
            result = await connection.execute(
                delete(self.schema.api_keys).where(
                    self.schema.api_keys.c.expires_at.is_not(None),
                    self.schema.api_keys.c.expires_at < current_utc_time(),
                ),
            )
        return int(result.rowcount or 0)

    async def create_jwks_key(self, key: JwksKey) -> JwksKey:
        return await self.insert_row(
            self.schema.jwks_keys,
            model_data(key),
            row_to_jwks_key,
            duplicate_resource="jwks_key",
            duplicate_field="kid",
        )

    async def list_jwks_keys(self) -> list[JwksKey]:
        async with self.engine.begin() as connection:
            result = await connection.execute(select(self.schema.jwks_keys))
            return [row_to_jwks_key(row) for row in result.mappings()]

    async def update_jwks_key(self, key: JwksKey) -> JwksKey:
        return await self.update_row_by_id(
            self.schema.jwks_keys,
            key.id,
            model_data(key),
            row_to_jwks_key,
            resource="jwks_key",
        )

    async def delete_jwks_key(self, key_id: str) -> None:
        async with self.engine.begin() as connection:
            await connection.execute(
                delete(self.schema.jwks_keys).where(self.schema.jwks_keys.c.id == key_id),
            )

    async def create_audit_log(self, row: AuditLog) -> AuditLog:
        return await self.insert_row(
            self.schema.audit_logs,
            model_data(row, enum_fields=("event_type",)),
            row_to_audit_log,
            duplicate_resource="audit_log",
            duplicate_field="id",
        )

    async def list_audit_logs(
        self,
        *,
        user_id: str | None,
        event_type: AuditEventType | None,
        identifier: str | None,
        limit: int,
        offset: int,
    ) -> tuple[list[AuditLog], int]:
        predicates: list[Any] = []
        if user_id is not None:
            predicates.append(self.schema.audit_logs.c.user_id == user_id)
        if event_type is not None:
            predicates.append(self.schema.audit_logs.c.event_type == event_type.value)
        if identifier is not None:
            predicates.append(self.schema.audit_logs.c.identifier == identifier)

        async with self.engine.begin() as connection:
            total_statement = select(func.count()).select_from(self.schema.audit_logs)
            rows_statement = (
                select(self.schema.audit_logs)
                .order_by(self.schema.audit_logs.c.created_at.desc())
                .offset(offset)
                .limit(limit)
            )
            if predicates:
                total_statement = total_statement.where(*predicates)
                rows_statement = rows_statement.where(*predicates)
            total_result = await connection.execute(total_statement)
            total = int(total_result.scalar_one())
            rows_result = await connection.execute(rows_statement)
            rows = [row_to_audit_log(row) for row in rows_result.mappings()]
        return rows, total

    async def get_rate_limit(self, key: str) -> RateLimit | None:
        return await self.fetch_one_or_none(
            select(self.schema.rate_limits).where(self.schema.rate_limits.c.key == key),
            row_to_rate_limit,
        )

    async def upsert_rate_limit(self, rate_limit: RateLimit) -> RateLimit:
        statement = (
            postgres_insert(self.schema.rate_limits)
            .values(**model_data(rate_limit))
            .on_conflict_do_update(
                index_elements=[self.schema.rate_limits.c.key],
                set_={
                    "count": rate_limit.count,
                    "last_request_ms": rate_limit.last_request_ms,
                },
            )
            .returning(*self.schema.rate_limits.c)
        )
        async with self.engine.begin() as connection:
            result = await connection.execute(statement)
            row = result.mappings().one()
        return row_to_rate_limit(row)

    async def delete_rate_limit(self, key: str) -> None:
        async with self.engine.begin() as connection:
            await connection.execute(
                delete(self.schema.rate_limits).where(self.schema.rate_limits.c.key == key),
            )
