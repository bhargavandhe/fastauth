"""Database option factories for FastAuth."""

from __future__ import annotations

from typing import Literal

from fastauth.options import (
    CustomDatabaseOptions,
    MemoryDatabaseOptions,
    MongoDatabaseOptions,
    PostgresDatabaseOptions,
)
from fastauth.storage.base import DatabaseAdapter

__all__ = ["custom", "memory", "mongo", "postgres"]


def memory() -> MemoryDatabaseOptions:
    return MemoryDatabaseOptions()


def mongo(
    database: object,
    *,
    collection_prefix: str = "",
    collection_suffix: str = "",
) -> MongoDatabaseOptions:
    return MongoDatabaseOptions(
        database=database,
        collection_prefix=collection_prefix,
        collection_suffix=collection_suffix,
    )


def postgres(
    url: str,
    *,
    table_prefix: str = "fastauth_",
    table_suffix: str = "",
    migration_mode: Literal["apply", "check", "disabled"] = "apply",
) -> PostgresDatabaseOptions:
    return PostgresDatabaseOptions.model_validate(
        {
            "kind": "postgres",
            "url": url,
            "table_prefix": table_prefix,
            "table_suffix": table_suffix,
            "migration_mode": migration_mode,
        },
    )


def custom(adapter: DatabaseAdapter) -> CustomDatabaseOptions:
    return CustomDatabaseOptions(adapter=adapter)
