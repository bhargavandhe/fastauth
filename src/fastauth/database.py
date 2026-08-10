"""Database option factories for FastAuth."""

from __future__ import annotations

from typing import Literal

from fastauth.domain.enums import DatabaseBackendKind
from fastauth.options import (
    CustomDatabaseOptions,
    DatabaseLifespanFactory,
    MemoryDatabaseOptions,
    MongoDatabase,
    MongoDatabaseOptions,
    PostgresDatabaseOptions,
)
from fastauth.storage.base import DatabaseAdapter

__all__ = ["custom", "memory", "mongo", "postgres"]


def memory() -> MemoryDatabaseOptions:
    return MemoryDatabaseOptions()


def mongo(
    *,
    database: MongoDatabase,
    collection_prefix: str = "",
    collection_suffix: str = "",
    plugin_migration_mode: Literal["apply", "check", "disabled"] | None = None,
) -> MongoDatabaseOptions:
    return MongoDatabaseOptions(
        database=database,
        collection_prefix=collection_prefix,
        collection_suffix=collection_suffix,
        plugin_migration_mode=plugin_migration_mode,
    )


def postgres(
    *,
    url: str,
    table_prefix: str = "fastauth_",
    table_suffix: str = "",
    migration_mode: Literal["apply", "check", "disabled"] = "apply",
    plugin_migration_mode: Literal["apply", "check", "disabled"] | None = None,
) -> PostgresDatabaseOptions:
    return PostgresDatabaseOptions.model_validate(
        {
            "kind": "postgres",
            "url": url,
            "table_prefix": table_prefix,
            "table_suffix": table_suffix,
            "migration_mode": migration_mode,
            "plugin_migration_mode": plugin_migration_mode,
        },
    )


def custom(
    *,
    adapter: DatabaseAdapter,
    backend: DatabaseBackendKind = DatabaseBackendKind.MEMORY,
    lifespan: DatabaseLifespanFactory | None = None,
) -> CustomDatabaseOptions:
    return CustomDatabaseOptions(adapter=adapter, backend=backend, lifespan=lifespan)
