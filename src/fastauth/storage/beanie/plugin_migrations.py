"""Idempotent MongoDB executor for additive plugin schema migrations."""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime
from typing import Any, cast

from pymongo import ASCENDING
from pymongo.errors import CollectionInvalid, DuplicateKeyError, OperationFailure

from fastauth.domain.enums import PluginMigrationMode
from fastauth.plugins.migrations import (
    PlannedMigration,
    PluginMigrationFingerprintError,
    PluginMigrationPendingError,
    PluginMigrationResult,
    PluginSchemaPlan,
    schema_fingerprint,
)

__all__ = ["execute_mongo_plugin_migrations"]


def physical_name(name: str, prefix: str, suffix: str) -> str:
    return f"{prefix}{name}{suffix}"


async def ensure_collection(database: object, name: str) -> None:
    mongo_database = cast(Any, database)
    try:
        await mongo_database.create_collection(name)
    except CollectionInvalid:
        return
    except OperationFailure as exc:
        if exc.code != 48:
            raise


async def load_records(collection: object) -> dict[tuple[str, int], tuple[str, str]]:
    mongo_collection = cast(Any, collection)
    records: dict[tuple[str, int], tuple[str, str]] = {}
    async for row in mongo_collection.find(
        {},
        {
            "_id": 0,
            "plugin_id": 1,
            "migration_name": 1,
            "version": 1,
            "schema_fingerprint": 1,
        },
    ):
        records[(str(row["plugin_id"]), int(row["version"]))] = (
            str(row["migration_name"]),
            str(row["schema_fingerprint"]),
        )
    return records


def pending_migrations(
    plan: PluginSchemaPlan,
    records: dict[tuple[str, int], tuple[str, str]],
) -> tuple[PlannedMigration, ...]:
    declared = {(item.plugin_id, item.version): item for item in plan.migrations}
    unknown = sorted(set(records).difference(declared))
    if unknown:
        plugin_id, version = unknown[0]
        raise RuntimeError(
            f"database contains unknown plugin migration: {plugin_id}:{version}",
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


async def execute_mongo_plugin_migrations(
    database: object,
    *,
    plan: PluginSchemaPlan,
    mode: PluginMigrationMode,
    collection_prefix: str,
    collection_suffix: str,
) -> PluginMigrationResult:
    """Check or idempotently apply a deterministic plugin schema plan."""
    mongo_database = cast(Any, database)
    if mode is PluginMigrationMode.DISABLED:
        return PluginMigrationResult(mode=mode)
    if plan.tables and not plan.migrations:
        raise RuntimeError("plugin collections require at least one migration marker")

    ledger_name = physical_name("plugin_migrations", collection_prefix, collection_suffix)
    collection_names = set(await mongo_database.list_collection_names())
    ledger_exists = ledger_name in collection_names
    ledger = mongo_database[ledger_name]
    records = await load_records(ledger) if ledger_exists else {}
    pending = pending_migrations(plan, records)
    if mode is PluginMigrationMode.CHECK:
        if pending:
            raise PluginMigrationPendingError(pending)
        return PluginMigrationResult(mode=mode)
    if not pending:
        return PluginMigrationResult(mode=mode)

    if not ledger_exists:
        await ensure_collection(database, ledger_name)
    await ledger.create_index(
        [("plugin_id", ASCENDING), ("version", ASCENDING)],
        name="plugin_migrations_plugin_version_idx",
        unique=True,
    )
    for table in plan.tables:
        collection_name = physical_name(table.name, collection_prefix, collection_suffix)
        await ensure_collection(database, collection_name)
        collection = mongo_database[collection_name]
        explicit_fields = {field_name for index in table.indexes for field_name in index.fields}
        for field in table.fields:
            if (field.indexed or field.unique) and field.name not in explicit_fields:
                await collection.create_index(
                    [(field.name, ASCENDING)],
                    name=f"{table.name}_{field.name}_idx",
                    unique=field.unique,
                )
        for index in table.indexes:
            await collection.create_index(
                [(field_name, ASCENDING) for field_name in index.fields],
                name=index.name,
                unique=index.unique,
            )

    applied: list[PlannedMigration] = []
    for migration in pending:
        document = {
            "plugin_id": migration.plugin_id,
            "migration_name": migration.name,
            "version": migration.version,
            "schema_fingerprint": schema_fingerprint(plan, migration),
            "applied_at": datetime.now(UTC),
        }
        try:
            await ledger.insert_one(document)
            applied.append(migration)
        except DuplicateKeyError:
            current = await ledger.find_one(
                {"plugin_id": migration.plugin_id, "version": migration.version},
            )
            if (
                current is None
                or current.get("migration_name") != migration.name
                or current.get("schema_fingerprint") != schema_fingerprint(plan, migration)
            ):
                raise PluginMigrationFingerprintError(
                    migration.plugin_id,
                    migration.version,
                ) from None
    return PluginMigrationResult(mode=mode, applied=tuple(applied))
