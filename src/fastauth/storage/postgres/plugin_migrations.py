"""Transactional Postgres executor for additive plugin schema migrations."""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    MetaData,
    String,
    Table,
    Text,
    func,
    insert,
    inspect,
    select,
)
from sqlalchemy.ext.asyncio import AsyncConnection
from sqlalchemy.sql.schema import SchemaItem
from sqlalchemy.sql.type_api import TypeEngine

from fastauth.domain.enums import PluginMigrationMode
from fastauth.plugins.migrations import (
    PlannedMigration,
    PlannedTable,
    PluginMigrationError,
    PluginMigrationFingerprintError,
    PluginMigrationPendingError,
    PluginMigrationResult,
    PluginSchemaPlan,
    schema_fingerprint,
)

__all__ = ["execute_postgres_plugin_migrations"]

PLUGIN_MIGRATION_ADVISORY_LOCK_ID = 464_901_338


def physical_name(name: str, prefix: str, suffix: str) -> str:
    return f"{prefix}{name}{suffix}"


def sqlalchemy_type(python_type: str, max_length: int | None) -> TypeEngine[Any]:
    if python_type == "str":
        return String(max_length) if max_length is not None else Text()
    if python_type == "int":
        return Integer()
    if python_type == "float":
        return Float()
    if python_type == "bool":
        return Boolean()
    if python_type == "datetime":
        return DateTime(timezone=True)
    if python_type == "bytes":
        return LargeBinary()
    if python_type == "json":
        return JSON()
    raise PluginMigrationError(
        code="PLUGIN_MIGRATION_UNSUPPORTED_FIELD_TYPE",
        message=f"unsupported plugin field type: {python_type}",
    )


def plugin_ledger(metadata: MetaData, prefix: str, suffix: str) -> Table:
    name = physical_name("plugin_migrations", prefix, suffix)
    existing = metadata.tables.get(name)
    if existing is not None:
        return existing
    return Table(
        name,
        metadata,
        Column("plugin_id", String(255), primary_key=True),
        Column("migration_name", String(255), nullable=False),
        Column("version", Integer, primary_key=True),
        Column("schema_fingerprint", String(64), nullable=False),
        Column("applied_at", DateTime(timezone=True), nullable=False),
    )


def build_plugin_table(
    metadata: MetaData,
    table: PlannedTable,
    prefix: str,
    suffix: str,
) -> Table:
    name = physical_name(table.name, prefix, suffix)
    existing = metadata.tables.get(name)
    if existing is not None:
        return existing
    columns: list[Column[Any]] = []
    for field in table.fields:
        arguments: list[SchemaItem] = []
        if field.references is not None:
            referenced_table, referenced_field = field.references.split(".", 1)
            arguments.append(
                ForeignKey(
                    f"{physical_name(referenced_table, prefix, suffix)}.{referenced_field}",
                ),
            )
        columns.append(
            Column(
                field.name,
                sqlalchemy_type(field.python_type, field.max_length),
                *arguments,
                nullable=field.nullable,
                unique=field.unique,
            ),
        )
    created = Table(name, metadata, *columns)
    explicit_fields = {field_name for index in table.indexes for field_name in index.fields}
    for field in table.fields:
        if field.indexed and field.name not in explicit_fields:
            Index(
                physical_name(f"{table.name}_{field.name}_idx", prefix, suffix),
                created.c[field.name],
            )
    for index in table.indexes:
        Index(
            physical_name(index.name, prefix, suffix),
            *(created.c[field_name] for field_name in index.fields),
            unique=index.unique,
        )
    return created


def pending_migrations(
    plan: PluginSchemaPlan,
    records: dict[tuple[str, int], tuple[str, str]],
) -> tuple[PlannedMigration, ...]:
    declared = {(item.plugin_id, item.version): item for item in plan.migrations}
    unknown = sorted(set(records).difference(declared))
    if unknown:
        plugin_id, version = unknown[0]
        raise PluginMigrationError(
            code="PLUGIN_MIGRATION_LEDGER_DIVERGED",
            message=f"database contains unknown plugin migration: {plugin_id}:{version}",
        )

    by_plugin: dict[str, list[PlannedMigration]] = defaultdict(list)
    for migration in plan.migrations:
        by_plugin[migration.plugin_id].append(migration)
    for migrations in by_plugin.values():
        latest = max(migrations, key=lambda item: item.version)
        record = records.get((latest.plugin_id, latest.version))
        if record is not None:
            recorded_name, recorded_fingerprint = record
            if recorded_name != latest.name or recorded_fingerprint != schema_fingerprint(
                plan, latest
            ):
                raise PluginMigrationFingerprintError(latest.plugin_id, latest.version)

    return tuple(
        migration
        for migration in plan.migrations
        if (migration.plugin_id, migration.version) not in records
    )


async def load_records(
    connection: AsyncConnection,
    ledger: Table,
) -> dict[tuple[str, int], tuple[str, str]]:
    result = await connection.execute(
        select(
            ledger.c.plugin_id,
            ledger.c.migration_name,
            ledger.c.version,
            ledger.c.schema_fingerprint,
        ),
    )
    return {
        (str(row.plugin_id), int(row.version)): (
            str(row.migration_name),
            str(row.schema_fingerprint),
        )
        for row in result
    }


async def execute_postgres_plugin_migrations(
    connection: AsyncConnection,
    *,
    metadata: MetaData,
    plan: PluginSchemaPlan,
    mode: PluginMigrationMode,
    table_prefix: str,
    table_suffix: str,
) -> PluginMigrationResult:
    """Check or apply one deterministic plugin plan inside an existing transaction."""
    if mode is PluginMigrationMode.DISABLED:
        return PluginMigrationResult(mode=mode)
    if plan.tables and not plan.migrations:
        raise PluginMigrationError(
            code="PLUGIN_MIGRATION_INVALID_PLAN",
            message="plugin tables require at least one migration marker",
        )

    await connection.execute(
        select(func.pg_advisory_xact_lock(PLUGIN_MIGRATION_ADVISORY_LOCK_ID)),
    )
    ledger = plugin_ledger(metadata, table_prefix, table_suffix)
    ledger_exists = await connection.run_sync(
        lambda sync_connection: inspect(sync_connection).has_table(ledger.name),
    )
    records = await load_records(connection, ledger) if ledger_exists else {}
    pending = pending_migrations(plan, records)
    if mode is PluginMigrationMode.CHECK:
        if pending:
            raise PluginMigrationPendingError(pending)
        return PluginMigrationResult(mode=mode)
    if not pending:
        return PluginMigrationResult(mode=mode)

    if not ledger_exists:
        await connection.run_sync(ledger.create, checkfirst=True)
    tables = [
        build_plugin_table(metadata, table, table_prefix, table_suffix) for table in plan.tables
    ]
    for table in tables:
        await connection.run_sync(table.create, checkfirst=True)
        for index in sorted(table.indexes, key=lambda item: item.name or ""):
            await connection.run_sync(index.create, checkfirst=True)

    applied_at = datetime.now(UTC)
    for migration in pending:
        await connection.execute(
            insert(ledger).values(
                plugin_id=migration.plugin_id,
                migration_name=migration.name,
                version=migration.version,
                schema_fingerprint=schema_fingerprint(plan, migration),
                applied_at=applied_at,
            ),
        )
    return PluginMigrationResult(mode=mode, applied=pending)
