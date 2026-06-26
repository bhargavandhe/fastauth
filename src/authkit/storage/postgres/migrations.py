"""Tracked migrations for the first-party Postgres adapter."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from sqlalchemy.ext.asyncio import AsyncConnection

if TYPE_CHECKING:
    from authkit.storage.postgres.schema import PostgresSchema

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


async def apply_initial_authkit_schema(
    connection: AsyncConnection,
    schema: PostgresSchema,
) -> None:
    await connection.run_sync(schema.metadata.create_all)


POSTGRES_MIGRATIONS: tuple[PostgresMigration, ...] = (
    PostgresMigration(
        version=1,
        description="initial authkit schema",
        apply=apply_initial_authkit_schema,
    ),
)

CURRENT_SCHEMA_VERSION = POSTGRES_MIGRATIONS[-1].version


def pending_postgres_migrations(current_version: int) -> list[PostgresMigration]:
    if current_version > CURRENT_SCHEMA_VERSION:
        raise RuntimeError(
            "Postgres authkit schema is newer than this authkit version; "
            "upgrade authkit before startup."
        )
    return [
        migration for migration in POSTGRES_MIGRATIONS if migration.version > current_version
    ]
