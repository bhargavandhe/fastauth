"""Contract tests for the SQLAlchemy/Postgres adapter."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator, AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from testcontainers.postgres import PostgresContainer  # pyright: ignore[reportMissingTypeStubs]

from fastauth.domain.enums import PluginMigrationMode
from fastauth.domain.models import RefreshToken, Session, User, new_id
from fastauth.plugins.migrations import (
    PluginMigrationFingerprintError,
    PluginMigrationPendingError,
    PluginSchemaPlan,
    build_schema_plan,
)
from fastauth.plugins.schema import (
    FieldSpec,
    IndexSpec,
    MigrationSpec,
    PluginFieldType,
    PluginSchema,
    TableSpec,
)
from fastauth.storage.postgres import PostgresAdapter
from fastauth.storage.postgres.plugin_migrations import execute_postgres_plugin_migrations
from tests.adapters.adapter_contract import FullAdapterContract


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


@asynccontextmanager
async def acquire_refresh_family_lock(
    engine: AsyncEngine,
    adapter: PostgresAdapter,
    family_id: str,
) -> AsyncGenerator[None, None]:
    lock_value = f"{adapter.schema.refresh_tokens.name}:{family_id}"
    async with engine.begin() as connection:
        await connection.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:lock_value, 0))"),
            {"lock_value": lock_value},
        )
        yield


async def create_refresh_family(
    adapter: PostgresAdapter,
    *,
    email: str,
    token_hash: str,
) -> tuple[Session, RefreshToken]:
    user = await adapter.create_user(User(email=email))
    session = await adapter.create_session(
        Session(
            user_id=user.id,
            token_hash=f"{token_hash}-session",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
    )
    root_id = new_id()
    family_created_at = datetime.now(UTC)
    token = await adapter.create_refresh_token(
        RefreshToken(
            id=root_id,
            user_id=user.id,
            session_id=session.id,
            token_hash=token_hash,
            family_id=root_id,
            family_created_at=family_created_at,
            expires_at=datetime.now(UTC) + timedelta(days=1),
        )
    )
    return session, token


def plugin_plan(
    *,
    versions: tuple[int, ...] = (1,),
    field_type: PluginFieldType = "str",
) -> PluginSchemaPlan:
    return build_schema_plan(
        (
            PluginSchema(
                plugin_id="adapter-contract",
                tables=(
                    TableSpec(
                        name="plugin_records",
                        fields=(
                            FieldSpec(name="id", python_type=field_type),
                            FieldSpec(name="label", python_type="str"),
                        ),
                        indexes=(
                            IndexSpec(
                                name="plugin_records_label_idx",
                                fields=("label",),
                            ),
                        ),
                    ),
                ),
                migrations=tuple(
                    MigrationSpec(name=f"plugin_records_v{version}", version=version)
                    for version in versions
                ),
            ),
        ),
    )


@pytest.fixture
async def postgres_engine(postgres_url: str) -> AsyncIterator[AsyncEngine]:
    engine = create_async_engine(postgres_url)
    yield engine
    await engine.dispose()


class TestPostgresAdapter(FullAdapterContract):
    @pytest.fixture
    async def adapter(self, postgres_engine: AsyncEngine) -> PostgresAdapter:
        adapter = PostgresAdapter(
            postgres_engine,
            table_prefix=f"fastauth_test_{uuid4().hex[:8]}_",
        )
        await adapter.apply_migrations()
        return adapter

    async def test_rotate_refresh_token_blocks_on_family_advisory_lock(
        self,
        postgres_engine: AsyncEngine,
        adapter: PostgresAdapter,
    ) -> None:
        session, token = await create_refresh_family(
            adapter,
            email="lock-rotate@example.com",
            token_hash="lock-rotate-root",
        )
        successor = RefreshToken(
            user_id=token.user_id,
            session_id=session.id,
            token_hash="lock-rotate-successor",
            family_id=token.family_id,
            family_created_at=token.family_created_at,
            expires_at=datetime.now(UTC) + timedelta(days=1),
        )

        async with acquire_refresh_family_lock(postgres_engine, adapter, token.family_id):
            task = asyncio.create_task(
                adapter.rotate_refresh_token(
                    current_token_id=token.id,
                    new_token=successor,
                    consumed_at=datetime.now(UTC),
                )
            )
            await asyncio.sleep(0.2)
            assert not task.done()

        rotated = await asyncio.wait_for(task, timeout=2)
        assert rotated is not None
        assert rotated.token_hash == "lock-rotate-successor"

    async def test_delete_refresh_token_family_blocks_on_family_advisory_lock(
        self,
        postgres_engine: AsyncEngine,
        adapter: PostgresAdapter,
    ) -> None:
        _session, token = await create_refresh_family(
            adapter,
            email="lock-delete@example.com",
            token_hash="lock-delete-root",
        )

        async with acquire_refresh_family_lock(postgres_engine, adapter, token.family_id):
            task = asyncio.create_task(adapter.delete_refresh_token_family(token.family_id))
            await asyncio.sleep(0.2)
            assert not task.done()

        revoked = await asyncio.wait_for(task, timeout=2)
        assert revoked.deleted_tokens == 1
        assert revoked.deleted_sessions == 1

    async def test_refresh_family_advisory_lock_releases_on_rollback(
        self,
        postgres_engine: AsyncEngine,
        adapter: PostgresAdapter,
    ) -> None:
        _session, token = await create_refresh_family(
            adapter,
            email="lock-rollback@example.com",
            token_hash="lock-rollback-root",
        )

        with pytest.raises(RuntimeError, match="rollback lock holder"):
            async with acquire_refresh_family_lock(postgres_engine, adapter, token.family_id):
                raise RuntimeError("rollback lock holder")

        revoked = await asyncio.wait_for(
            adapter.delete_refresh_token_family(token.family_id),
            timeout=2,
        )
        assert revoked.deleted_tokens == 1

    async def test_different_refresh_families_do_not_block_each_other(
        self,
        postgres_engine: AsyncEngine,
        adapter: PostgresAdapter,
    ) -> None:
        _first_session, first = await create_refresh_family(
            adapter,
            email="lock-first@example.com",
            token_hash="lock-first-root",
        )
        second_session, second = await create_refresh_family(
            adapter,
            email="lock-second@example.com",
            token_hash="lock-second-root",
        )
        successor = RefreshToken(
            user_id=second.user_id,
            session_id=second_session.id,
            token_hash="lock-second-successor",
            family_id=second.family_id,
            family_created_at=second.family_created_at,
            expires_at=datetime.now(UTC) + timedelta(days=1),
        )

        async with acquire_refresh_family_lock(postgres_engine, adapter, first.family_id):
            rotated = await asyncio.wait_for(
                adapter.rotate_refresh_token(
                    current_token_id=second.id,
                    new_token=successor,
                    consumed_at=datetime.now(UTC),
                ),
                timeout=2,
            )

        assert rotated is not None
        assert rotated.family_id == second.family_id

    async def test_plugin_migrations_apply_replay_check_and_fingerprint(
        self,
        adapter: PostgresAdapter,
    ) -> None:
        async with adapter.engine.begin() as connection:
            first = await execute_postgres_plugin_migrations(
                connection,
                metadata=adapter.schema.metadata,
                plan=plugin_plan(),
                mode=PluginMigrationMode.APPLY,
                table_prefix=adapter.schema.table_prefix,
                table_suffix=adapter.schema.table_suffix,
            )
        assert len(first.applied) == 1

        async with adapter.engine.begin() as connection:
            replay = await execute_postgres_plugin_migrations(
                connection,
                metadata=adapter.schema.metadata,
                plan=plugin_plan(),
                mode=PluginMigrationMode.APPLY,
                table_prefix=adapter.schema.table_prefix,
                table_suffix=adapter.schema.table_suffix,
            )
        assert replay.applied == ()

        async with adapter.engine.begin() as connection:
            with pytest.raises(PluginMigrationPendingError):
                await execute_postgres_plugin_migrations(
                    connection,
                    metadata=adapter.schema.metadata,
                    plan=plugin_plan(versions=(1, 2)),
                    mode=PluginMigrationMode.CHECK,
                    table_prefix=adapter.schema.table_prefix,
                    table_suffix=adapter.schema.table_suffix,
                )

        async with adapter.engine.begin() as connection:
            with pytest.raises(PluginMigrationFingerprintError):
                await execute_postgres_plugin_migrations(
                    connection,
                    metadata=adapter.schema.metadata,
                    plan=plugin_plan(field_type="int"),
                    mode=PluginMigrationMode.CHECK,
                    table_prefix=adapter.schema.table_prefix,
                    table_suffix=adapter.schema.table_suffix,
                )

        physical_table = f"{adapter.schema.table_prefix}plugin_records"
        async with adapter.engine.connect() as connection:
            result = await connection.execute(
                text("SELECT to_regclass(:table_name)"),
                {"table_name": physical_table},
            )
        assert result.scalar_one() == physical_table

    async def test_plugin_migrations_serialize_concurrent_application(
        self,
        adapter: PostgresAdapter,
    ) -> None:
        async def apply_once() -> int:
            async with adapter.engine.begin() as connection:
                result = await execute_postgres_plugin_migrations(
                    connection,
                    metadata=adapter.schema.metadata,
                    plan=plugin_plan(),
                    mode=PluginMigrationMode.APPLY,
                    table_prefix=adapter.schema.table_prefix,
                    table_suffix=adapter.schema.table_suffix,
                )
            return len(result.applied)

        assert sorted(await asyncio.gather(apply_once(), apply_once())) == [0, 1]
