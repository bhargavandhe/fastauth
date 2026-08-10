"""Planning helpers for plugin-owned schema declarations."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Sequence
from datetime import datetime
from typing import Literal, Protocol, Self

from pydantic import Field, field_validator, model_validator

from fastauth.domain.enums import PluginMigrationMode
from fastauth.plugins.schema import (
    FieldSpec,
    IndexSpec,
    PluginSchema,
    PluginSchemaModel,
    TableSpec,
    validate_identifier,
)

__all__ = [
    "MigrationOperation",
    "PlannedMigration",
    "PlannedTable",
    "PluginMigrationFingerprintError",
    "PluginMigrationMode",
    "PluginMigrationPendingError",
    "PluginMigrationRecord",
    "PluginMigrationResult",
    "PluginSchemaConflictError",
    "PluginSchemaPlan",
    "SchemaConflict",
    "SchemaProvider",
    "build_schema_plan",
    "build_schema_plan_from_registry",
    "render_migration_operations",
    "schema_fingerprint",
]

ConflictKind = Literal["duplicate_table", "field_conflict"]
OperationKind = Literal["create_table", "create_index", "record_migration"]


class PluginMigrationPendingError(RuntimeError):
    """Raised in check mode when declared plugin migrations are not recorded."""

    def __init__(self, pending: Sequence[PlannedMigration]) -> None:
        self.pending = tuple(pending)
        labels = ", ".join(
            f"{migration.plugin_id}:{migration.version}" for migration in self.pending
        )
        super().__init__(f"pending plugin migrations: {labels}")


class PluginMigrationFingerprintError(RuntimeError):
    """Raised when an already-recorded plugin migration changed in place."""

    def __init__(self, plugin_id: str, version: int) -> None:
        self.plugin_id = plugin_id
        self.version = version
        super().__init__(
            f"plugin migration fingerprint mismatch: {plugin_id}:{version}",
        )


class PluginMigrationRecord(PluginSchemaModel):
    """Backend-neutral row stored in each plugin migration ledger."""

    plugin_id: str
    migration_name: str
    version: int = Field(ge=1)
    schema_fingerprint: str = Field(min_length=64, max_length=64)
    applied_at: datetime


class SchemaProvider(Protocol):
    """Minimal PluginRegistry surface needed by schema planning."""

    def all_schemas(self) -> list[PluginSchema]:
        """Return every schema declaration in registry order."""
        ...


class SchemaConflict(PluginSchemaModel):
    """Structured conflict found while aggregating plugin schema declarations."""

    kind: ConflictKind
    table_name: str
    plugin_ids: tuple[str, ...]
    field_name: str | None = None
    message: str

    @field_validator("table_name")
    @classmethod
    def validate_table_name(cls, value: str) -> str:
        return validate_identifier(value, label="table name")

    @field_validator("field_name")
    @classmethod
    def validate_field_name(cls, value: str | None) -> str | None:
        if value is None:
            return value
        return validate_identifier(value, label="field name")

    @field_validator("plugin_ids")
    @classmethod
    def validate_plugin_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value:
            raise ValueError("conflict must include at least one plugin id")
        for plugin_id in value:
            if not plugin_id:
                raise ValueError("plugin id must be non-empty")
        return value


class PluginSchemaConflictError(ValueError):
    """Raised when multiple plugin schema declarations cannot be aggregated."""

    def __init__(self, conflicts: Sequence[SchemaConflict]) -> None:
        self.conflicts = tuple(conflicts)
        messages = "; ".join(conflict.message for conflict in self.conflicts)
        super().__init__(messages or "plugin schema declarations conflict")


class PlannedTable(PluginSchemaModel):
    """Deterministic table entry in an aggregated plugin schema plan."""

    plugin_id: str
    name: str
    fields: tuple[FieldSpec, ...] = ()
    indexes: tuple[IndexSpec, ...] = ()

    @field_validator("plugin_id")
    @classmethod
    def validate_plugin_id(cls, value: str) -> str:
        if not value:
            raise ValueError("plugin_id must be a non-empty plugin identifier")
        return value

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        return validate_identifier(value, label="table name")

    @model_validator(mode="after")
    def validate_indexes_reference_declared_fields(self) -> Self:
        field_names = {field.name for field in self.fields}
        for index in self.indexes:
            missing = tuple(
                field_name for field_name in index.fields if field_name not in field_names
            )
            if missing:
                missing_names = ", ".join(missing)
                raise ValueError(
                    f"index {index.name!r} references unknown field(s): {missing_names}",
                )
        return self


class PlannedMigration(PluginSchemaModel):
    """Deterministic migration marker in an aggregated plugin schema plan."""

    plugin_id: str
    name: str
    version: int = Field(ge=1)
    description: str | None = None

    @field_validator("plugin_id")
    @classmethod
    def validate_plugin_id(cls, value: str) -> str:
        if not value:
            raise ValueError("plugin_id must be a non-empty plugin identifier")
        return value

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        return validate_identifier(value, label="migration name")


class PluginMigrationResult(PluginSchemaModel):
    """Result returned by backend plugin migration executors."""

    mode: PluginMigrationMode
    applied: tuple[PlannedMigration, ...] = ()
    pending: tuple[PlannedMigration, ...] = ()


class MigrationOperation(PluginSchemaModel):
    """Adapter-neutral operation that can be consumed by CLI or adapters later."""

    op: OperationKind
    plugin_id: str
    table_name: str | None = None
    fields: tuple[FieldSpec, ...] = ()
    index: IndexSpec | None = None
    migration: PlannedMigration | None = None

    @field_validator("plugin_id")
    @classmethod
    def validate_plugin_id(cls, value: str) -> str:
        if not value:
            raise ValueError("plugin_id must be a non-empty plugin identifier")
        return value

    @field_validator("table_name")
    @classmethod
    def validate_table_name(cls, value: str | None) -> str | None:
        if value is None:
            return value
        return validate_identifier(value, label="table name")

    @model_validator(mode="after")
    def validate_operation_payload(self) -> Self:
        if self.op == "create_table":
            if self.table_name is None:
                raise ValueError("create_table operation requires table_name")
            if self.index is not None or self.migration is not None:
                raise ValueError("create_table operation only accepts fields payload")
        elif self.op == "create_index":
            if self.table_name is None or self.index is None:
                raise ValueError("create_index operation requires table_name and index")
            if self.fields or self.migration is not None:
                raise ValueError("create_index operation only accepts index payload")
        elif self.op == "record_migration":
            if self.migration is None:
                raise ValueError("record_migration operation requires migration")
            if self.table_name is not None or self.fields or self.index is not None:
                raise ValueError("record_migration operation only accepts migration payload")
        return self


class PluginSchemaPlan(PluginSchemaModel):
    """Aggregated, deterministic schema plan for plugin-owned storage."""

    tables: tuple[PlannedTable, ...] = ()
    migrations: tuple[PlannedMigration, ...] = ()

    @model_validator(mode="after")
    def validate_unique_entries(self) -> Self:
        seen_tables: set[str] = set()
        for table in self.tables:
            if table.name in seen_tables:
                raise ValueError(f"duplicate table in schema plan: {table.name}")
            seen_tables.add(table.name)

        seen_migration_names: set[tuple[str, str]] = set()
        seen_migration_versions: set[tuple[str, int]] = set()
        for migration in self.migrations:
            name_key = (migration.plugin_id, migration.name)
            if name_key in seen_migration_names:
                raise ValueError(
                    f"duplicate migration in schema plan: {migration.plugin_id}.{migration.name}",
                )
            seen_migration_names.add(name_key)

            version_key = (migration.plugin_id, migration.version)
            if version_key in seen_migration_versions:
                raise ValueError(
                    f"duplicate migration version in schema plan: "
                    f"{migration.plugin_id}.{migration.version}",
                )
            seen_migration_versions.add(version_key)

        return self

    def to_operations(self) -> tuple[MigrationOperation, ...]:
        """Render this plan as adapter-neutral migration operations."""
        return render_migration_operations(self)


def schema_fingerprint(plan: PluginSchemaPlan, migration: PlannedMigration) -> str:
    """Hash the deterministic schema state declared for one plugin version."""
    payload = {
        "plugin_id": migration.plugin_id,
        "migration": migration.model_dump(mode="json"),
        "tables": [
            table.model_dump(mode="json")
            for table in plan.tables
            if table.plugin_id == migration.plugin_id
        ],
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def build_schema_plan_from_registry(registry: SchemaProvider) -> PluginSchemaPlan:
    """Build a deterministic plan from any registry-like object with all_schemas()."""
    return build_schema_plan(registry.all_schemas())


def build_schema_plan(schemas: Iterable[PluginSchema]) -> PluginSchemaPlan:
    """Aggregate plugin schema declarations into a deterministic schema plan."""
    schema_tuple = tuple(schemas)
    conflicts = find_schema_conflicts(schema_tuple)
    if conflicts:
        raise PluginSchemaConflictError(conflicts)

    tables: list[PlannedTable] = []
    migrations: list[PlannedMigration] = []
    for schema in sorted(schema_tuple, key=lambda item: item.plugin_id):
        for table in sorted(schema.tables, key=lambda item: item.name):
            tables.append(
                PlannedTable(
                    plugin_id=schema.plugin_id,
                    name=table.name,
                    fields=tuple(sorted(table.fields, key=lambda item: item.name)),
                    indexes=tuple(sorted(table.indexes, key=lambda item: item.name)),
                ),
            )
        for migration in sorted(schema.migrations, key=lambda item: (item.version, item.name)):
            migrations.append(
                PlannedMigration(
                    plugin_id=schema.plugin_id,
                    name=migration.name,
                    version=migration.version,
                    description=migration.description,
                ),
            )

    return PluginSchemaPlan(
        tables=tuple(sorted(tables, key=lambda item: (item.name, item.plugin_id))),
        migrations=tuple(
            sorted(migrations, key=lambda item: (item.plugin_id, item.version, item.name)),
        ),
    )


def render_migration_operations(plan: PluginSchemaPlan) -> tuple[MigrationOperation, ...]:
    """Render a schema plan into deterministic adapter-neutral operations."""
    operations: list[MigrationOperation] = []
    for table in plan.tables:
        operations.append(
            MigrationOperation(
                op="create_table",
                plugin_id=table.plugin_id,
                table_name=table.name,
                fields=table.fields,
            ),
        )
        for index in table.indexes:
            operations.append(
                MigrationOperation(
                    op="create_index",
                    plugin_id=table.plugin_id,
                    table_name=table.name,
                    index=index,
                ),
            )

    for migration in plan.migrations:
        operations.append(
            MigrationOperation(
                op="record_migration",
                plugin_id=migration.plugin_id,
                migration=migration,
            ),
        )

    return tuple(operations)


def find_schema_conflicts(schemas: tuple[PluginSchema, ...]) -> tuple[SchemaConflict, ...]:
    conflicts: list[SchemaConflict] = []
    tables_by_name: dict[str, tuple[str, TableSpec]] = {}

    for schema in sorted(schemas, key=lambda item: item.plugin_id):
        for table in sorted(schema.tables, key=lambda item: item.name):
            existing = tables_by_name.get(table.name)
            if existing is None:
                tables_by_name[table.name] = (schema.plugin_id, table)
                continue

            existing_plugin_id, existing_table = existing
            plugin_ids = tuple(sorted({existing_plugin_id, schema.plugin_id}))
            conflicts.append(
                SchemaConflict(
                    kind="duplicate_table",
                    table_name=table.name,
                    plugin_ids=plugin_ids,
                    message=(
                        f"duplicate plugin table {table.name!r} declared by "
                        f"{format_plugin_ids(plugin_ids)}"
                    ),
                ),
            )

            existing_fields = {field.name: field for field in existing_table.fields}
            for field in sorted(table.fields, key=lambda item: item.name):
                existing_field = existing_fields.get(field.name)
                if existing_field is not None and existing_field != field:
                    conflicts.append(
                        SchemaConflict(
                            kind="field_conflict",
                            table_name=table.name,
                            field_name=field.name,
                            plugin_ids=plugin_ids,
                            message=(
                                f"field {table.name}.{field.name} has conflicting "
                                f"declarations from {format_plugin_ids(plugin_ids)}"
                            ),
                        ),
                    )

    return tuple(conflicts)


def format_plugin_ids(plugin_ids: tuple[str, ...]) -> str:
    return " and ".join(repr(plugin_id) for plugin_id in plugin_ids)
