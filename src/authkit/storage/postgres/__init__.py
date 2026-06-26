"""SQLAlchemy/Postgres storage backend for authkit."""

from __future__ import annotations

from authkit.storage.postgres.adapter import PostgresAdapter
from authkit.storage.postgres.migrations import (
    CURRENT_SCHEMA_VERSION,
    POSTGRES_MIGRATIONS,
    PostgresMigration,
    pending_postgres_migrations,
)
from authkit.storage.postgres.schema import (
    PostgresSchema,
    build_postgres_schema,
)

__all__ = [
    "CURRENT_SCHEMA_VERSION",
    "POSTGRES_MIGRATIONS",
    "PostgresAdapter",
    "PostgresMigration",
    "PostgresSchema",
    "build_postgres_schema",
    "pending_postgres_migrations",
]
