"""Tracked migrations for the first-party Postgres adapter."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from sqlalchemy import DDL, inspect
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import AsyncConnection

if TYPE_CHECKING:
    from fastauth.storage.postgres.schema import PostgresSchema

__all__ = [
    "CURRENT_SCHEMA_VERSION",
    "POSTGRES_MIGRATIONS",
    "PostgresMigration",
    "pending_postgres_migrations",
]

MigrationApply = Callable[[AsyncConnection, "PostgresSchema"], Awaitable[None]]


@dataclass(frozen=True)
class PostgresMigration:
    version: int
    description: str
    apply: MigrationApply


async def apply_initial_fastauth_schema(
    connection: AsyncConnection,
    schema: PostgresSchema,
) -> None:
    await connection.run_sync(schema.metadata.create_all)


async def add_refresh_token_session_fields(
    connection: AsyncConnection,
    schema: PostgresSchema,
) -> None:
    def load_refresh_token_columns(sync_connection: Connection) -> set[str]:
        inspector = inspect(sync_connection)
        return {
            column["name"]
            for column in inspector.get_columns(schema.refresh_tokens.name)
        }

    existing_columns = await connection.run_sync(load_refresh_token_columns)
    missing_session_id = "session_id" not in existing_columns
    missing_family_created_at = "family_created_at" not in existing_columns
    if not missing_session_id and not missing_family_created_at:
        return

    quote = connection.dialect.identifier_preparer.quote
    refresh_tokens = quote(schema.refresh_tokens.name)
    refresh_tokens_session_id_idx = quote(f"{schema.refresh_tokens.name}_session_id_idx")

    await connection.execute(schema.refresh_tokens.delete())
    if missing_session_id:
        await connection.execute(
            DDL(
                f"ALTER TABLE {refresh_tokens} "
                "ADD COLUMN session_id VARCHAR(64) NOT NULL",
            ),
        )
    if missing_family_created_at:
        await connection.execute(
            DDL(
                f"ALTER TABLE {refresh_tokens} "
                "ADD COLUMN family_created_at TIMESTAMP WITH TIME ZONE NOT NULL",
            ),
        )
    if missing_session_id:
        await connection.execute(
            DDL(
                f"CREATE INDEX IF NOT EXISTS {refresh_tokens_session_id_idx} "
                f"ON {refresh_tokens} (session_id)",
            ),
        )


async def decouple_refresh_tokens_from_sessions(
    connection: AsyncConnection,
    schema: PostgresSchema,
) -> None:
    def load_refresh_token_foreign_keys(sync_connection: Connection) -> list[str]:
        inspector = inspect(sync_connection)
        keys = inspector.get_foreign_keys(schema.refresh_tokens.name)
        constraint_names: list[str] = []
        for key in keys:
            name = key.get("name")
            if isinstance(name, str) and key.get("constrained_columns") == ["session_id"]:
                constraint_names.append(name)
        return constraint_names

    constraint_names = await connection.run_sync(load_refresh_token_foreign_keys)
    if not constraint_names:
        return

    quote = connection.dialect.identifier_preparer.quote
    refresh_tokens = quote(schema.refresh_tokens.name)
    for constraint_name in constraint_names:
        await connection.execute(
            DDL(
                f"ALTER TABLE {refresh_tokens} "
                f"DROP CONSTRAINT IF EXISTS {quote(constraint_name)}",
            ),
        )


POSTGRES_MIGRATIONS: tuple[PostgresMigration, ...] = (
    PostgresMigration(
        version=1,
        description="initial fastauth schema",
        apply=apply_initial_fastauth_schema,
    ),
    PostgresMigration(
        version=2,
        description="link refresh tokens to sessions",
        apply=add_refresh_token_session_fields,
    ),
    PostgresMigration(
        version=3,
        description="preserve refresh token evidence after session rotation",
        apply=decouple_refresh_tokens_from_sessions,
    ),
)

CURRENT_SCHEMA_VERSION = POSTGRES_MIGRATIONS[-1].version


def pending_postgres_migrations(current_version: int) -> list[PostgresMigration]:
    if current_version > CURRENT_SCHEMA_VERSION:
        raise RuntimeError(
            "Postgres fastauth schema is newer than this fastauth version; "
            "upgrade fastauth before startup."
        )
    return [
        migration for migration in POSTGRES_MIGRATIONS if migration.version > current_version
    ]
