"""Contract tests for the SQLAlchemy/Postgres adapter."""

from __future__ import annotations

from collections.abc import AsyncIterator
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from testcontainers.postgres import PostgresContainer  # pyright: ignore[reportMissingTypeStubs]

from authkit.storage.postgres import PostgresAdapter
from tests.adapters.adapter_contract import AdapterContract


@pytest.fixture(scope="session")
def postgres_url() -> str:
    try:
        container = PostgresContainer("postgres:16-alpine")
        container.start()
    except Exception as exc:
        pytest.skip(f"Docker is required for Postgres adapter tests: {exc}")

    url = container.get_connection_url()
    if url.startswith("postgresql+psycopg2://"):
        url = url.replace("postgresql+psycopg2://", "postgresql+asyncpg://", 1)
    elif url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)

    def stop_container() -> None:
        container.stop()

    import atexit

    atexit.register(stop_container)
    return url


@pytest.fixture
async def postgres_engine(postgres_url: str) -> AsyncIterator[AsyncEngine]:
    engine = create_async_engine(postgres_url)
    yield engine
    await engine.dispose()


class TestPostgresAdapter(AdapterContract):
    @pytest.fixture
    async def adapter(self, postgres_engine: AsyncEngine) -> PostgresAdapter:
        adapter = PostgresAdapter(
            postgres_engine,
            table_prefix=f"authkit_test_{uuid4().hex[:8]}_",
        )
        await adapter.apply_migrations()
        return adapter
