from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import AbstractAsyncContextManager, asynccontextmanager

import pytest
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import create_async_engine

from fastauth.storage.postgres import (
    CURRENT_SCHEMA_VERSION,
    POSTGRES_MIGRATIONS,
    PostgresAdapter,
    pending_postgres_migrations,
)


def test_postgres_schema_uses_configurable_table_prefix() -> None:
    adapter = PostgresAdapter.from_url(
        "postgresql+asyncpg://fastauth:fastauth@localhost/fastauth",
        table_prefix="custom_",
    )

    table_names = set(adapter.schema.metadata.tables)
    assert "custom_users" in table_names
    assert "custom_refresh_tokens" in table_names
    assert "custom_schema_migrations" in table_names
    assert "fastauth_users" not in table_names


def test_postgres_schema_uses_configurable_table_prefix_and_suffix() -> None:
    adapter = PostgresAdapter.from_url(
        "postgresql+asyncpg://fastauth:fastauth@localhost/fastauth",
        table_prefix="tenant_",
        table_suffix="_auth",
    )

    table_names = set(adapter.schema.metadata.tables)
    assert "tenant_users_auth" in table_names
    assert "tenant_refresh_tokens_auth" in table_names
    assert "tenant_schema_migrations_auth" in table_names
    assert "tenant_users" not in table_names


def test_postgres_schema_tracks_current_version_table() -> None:
    adapter = PostgresAdapter.from_url(
        "postgresql+asyncpg://fastauth:fastauth@localhost/fastauth",
    )

    assert "fastauth_schema_migrations" in adapter.schema.metadata.tables
    assert "version" in adapter.schema.schema_migrations.c
    assert "applied_at" in adapter.schema.schema_migrations.c


def test_postgres_migration_registry_is_ordered() -> None:
    versions = [migration.version for migration in POSTGRES_MIGRATIONS]

    assert versions == sorted(versions)
    assert versions == list(range(1, CURRENT_SCHEMA_VERSION + 1))
    assert POSTGRES_MIGRATIONS[-1].description == "initial fastauth schema"


def test_postgres_pending_migrations_rejects_future_database_version() -> None:
    with pytest.raises(RuntimeError, match="newer than this fastauth version"):
        pending_postgres_migrations(CURRENT_SCHEMA_VERSION + 1)


async def test_postgres_lifespan_applies_migrations_then_auth_lifespan() -> None:
    engine = create_async_engine("postgresql+asyncpg://fastauth:fastauth@localhost/fastauth")
    adapter = PostgresAdapter(engine)
    calls: list[str] = []

    async def apply_migrations() -> list[int]:
        calls.append("migrations")
        return [1]

    adapter.apply_migrations = apply_migrations  # type: ignore[method-assign]

    class Auth:
        def lifespan(self, app: FastAPI) -> AbstractAsyncContextManager[None]:
            @asynccontextmanager
            async def lifespan_context(app: FastAPI) -> AsyncGenerator[None, None]:
                calls.append("auth")
                yield

            return lifespan_context(app)

    app = FastAPI()
    async with adapter.lifespan(Auth())(app):  # type: ignore[arg-type]
        calls.append("inside")

    await engine.dispose()
    assert calls == ["migrations", "auth", "inside"]


async def test_postgres_checked_lifespan_asserts_schema_then_auth_lifespan() -> None:
    engine = create_async_engine("postgresql+asyncpg://fastauth:fastauth@localhost/fastauth")
    adapter = PostgresAdapter(engine)
    calls: list[str] = []

    async def assert_schema_current() -> None:
        calls.append("checked")

    adapter.assert_schema_current = assert_schema_current  # type: ignore[method-assign]

    class Auth:
        def lifespan(self, app: FastAPI) -> AbstractAsyncContextManager[None]:
            @asynccontextmanager
            async def lifespan_context(app: FastAPI) -> AsyncGenerator[None, None]:
                calls.append("auth")
                yield

            return lifespan_context(app)

    app = FastAPI()
    async with adapter.checked_lifespan(Auth())(app):  # type: ignore[arg-type]
        calls.append("inside")

    await engine.dispose()
    assert calls == ["checked", "auth", "inside"]
