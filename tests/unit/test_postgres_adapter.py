from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import AbstractAsyncContextManager, asynccontextmanager

from fastapi import FastAPI
from sqlalchemy.ext.asyncio import create_async_engine

from authkit.storage.postgres import PostgresAdapter


def test_postgres_adapter_uses_configurable_table_prefix() -> None:
    adapter = PostgresAdapter.from_url(
        "postgresql+asyncpg://authkit:authkit@localhost/authkit",
        table_prefix="custom_",
    )

    table_names = set(adapter.schema.metadata.tables)
    assert "custom_users" in table_names
    assert "custom_refresh_tokens" in table_names
    assert "authkit_users" not in table_names


async def test_postgres_lifespan_creates_schema_then_auth_lifespan() -> None:
    engine = create_async_engine("postgresql+asyncpg://authkit:authkit@localhost/authkit")
    adapter = PostgresAdapter(engine)
    calls: list[str] = []

    async def create_schema() -> None:
        calls.append("schema")

    adapter.create_schema = create_schema  # type: ignore[method-assign]

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
    assert calls == ["schema", "auth", "inside"]
