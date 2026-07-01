"""Database option factories for FastAuth."""

from __future__ import annotations

from typing import Literal

from fastauth.options import CustomDatabase, MemoryDatabase, MongoDatabase, PostgresDatabase
from fastauth.storage.base import DatabaseAdapter

__all__ = ["custom", "memory", "mongo", "postgres"]


def memory() -> MemoryDatabase:
    return MemoryDatabase()


def mongo(
    database: object,
    *,
    collection_prefix: str = "",
    collection_suffix: str = "",
) -> MongoDatabase:
    return MongoDatabase(
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
) -> PostgresDatabase:
    return PostgresDatabase.model_validate(
        {
            "kind": "postgres",
            "url": url,
            "table_prefix": table_prefix,
            "table_suffix": table_suffix,
            "migration_mode": migration_mode,
        },
    )


def custom(adapter: DatabaseAdapter) -> CustomDatabase:
    return CustomDatabase(adapter=adapter)
