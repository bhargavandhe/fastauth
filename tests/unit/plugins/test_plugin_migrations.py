from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from fastauth.plugins.migrations import (
    MigrationOperation,
    PlannedMigration,
    PlannedTable,
    PluginSchemaConflictError,
    PluginSchemaPlan,
    build_schema_plan,
    build_schema_plan_from_registry,
    render_migration_operations,
)
from fastauth.plugins.schema import FieldSpec, IndexSpec, MigrationSpec, PluginSchema, TableSpec


def test_build_schema_plan_is_deterministic() -> None:
    beta = PluginSchema(
        plugin_id="beta",
        tables=(
            TableSpec(
                name="beta_tokens",
                fields=(
                    FieldSpec(name="user_id", python_type="str", indexed=True),
                    FieldSpec(name="id", python_type="str", unique=True),
                ),
                indexes=(
                    IndexSpec(name="beta_tokens_user_id_idx", fields=("user_id",)),
                    IndexSpec(name="beta_tokens_id_idx", fields=("id",), unique=True),
                ),
            ),
        ),
        migrations=(
            MigrationSpec(name="add_beta_token_labels", version=2),
            MigrationSpec(name="create_beta_tokens", version=1),
        ),
    )
    alpha = PluginSchema(
        plugin_id="alpha",
        tables=(
            TableSpec(
                name="alpha_audit",
                fields=(FieldSpec(name="id", python_type="str"),),
            ),
        ),
        migrations=(MigrationSpec(name="create_alpha_audit", version=1),),
    )

    first_plan = build_schema_plan((beta, alpha))
    second_plan = build_schema_plan((alpha, beta))

    assert first_plan.model_dump(mode="json") == second_plan.model_dump(mode="json")
    assert [table.name for table in first_plan.tables] == ["alpha_audit", "beta_tokens"]
    assert [field.name for field in first_plan.tables[1].fields] == ["id", "user_id"]
    assert [index.name for index in first_plan.tables[1].indexes] == [
        "beta_tokens_id_idx",
        "beta_tokens_user_id_idx",
    ]
    assert [(migration.plugin_id, migration.version) for migration in first_plan.migrations] == [
        ("alpha", 1),
        ("beta", 1),
        ("beta", 2),
    ]


def test_build_schema_plan_from_registry_uses_all_schemas() -> None:
    schema = PluginSchema(
        plugin_id="api_key",
        tables=(TableSpec(name="api_keys", fields=(FieldSpec(name="id", python_type="str"),)),),
    )

    class RegistryLike:
        def all_schemas(self) -> list[PluginSchema]:
            return [schema]

    plan = build_schema_plan_from_registry(RegistryLike())

    assert plan.tables[0].name == "api_keys"


def test_build_schema_plan_reports_duplicate_table_and_field_conflicts() -> None:
    alpha = PluginSchema(
        plugin_id="alpha",
        tables=(
            TableSpec(
                name="shared_records",
                fields=(FieldSpec(name="external_id", python_type="str"),),
            ),
        ),
    )
    beta = PluginSchema(
        plugin_id="beta",
        tables=(
            TableSpec(
                name="shared_records",
                fields=(FieldSpec(name="external_id", python_type="int"),),
            ),
        ),
    )

    with pytest.raises(PluginSchemaConflictError) as exc_info:
        build_schema_plan((beta, alpha))

    conflicts = exc_info.value.conflicts
    assert [conflict.kind for conflict in conflicts] == ["duplicate_table", "field_conflict"]
    assert conflicts[0].plugin_ids == ("alpha", "beta")
    assert conflicts[1].field_name == "external_id"
    assert conflicts[1].model_dump(mode="json") == {
        "kind": "field_conflict",
        "table_name": "shared_records",
        "plugin_ids": ["alpha", "beta"],
        "field_name": "external_id",
        "message": (
            "field shared_records.external_id has conflicting declarations from 'alpha' and 'beta'"
        ),
    }


def test_schema_plan_and_operations_are_json_serializable() -> None:
    plan = build_schema_plan(
        (
            PluginSchema(
                plugin_id="api_key",
                tables=(
                    TableSpec(
                        name="api_keys",
                        fields=(
                            FieldSpec(name="id", python_type="str", unique=True),
                            FieldSpec(name="user_id", python_type="str", indexed=True),
                        ),
                        indexes=(IndexSpec(name="api_keys_user_id_idx", fields=("user_id",)),),
                    ),
                ),
                migrations=(MigrationSpec(name="create_api_keys", version=1),),
            ),
        ),
    )

    plan_payload = json.loads(plan.model_dump_json())
    operations_payload = [
        operation.model_dump(mode="json") for operation in render_migration_operations(plan)
    ]

    assert plan_payload["tables"][0]["fields"][0]["name"] == "id"
    assert operations_payload == [
        {
            "op": "create_table",
            "plugin_id": "api_key",
            "table_name": "api_keys",
            "fields": [
                {
                    "name": "id",
                    "python_type": "str",
                    "nullable": False,
                    "unique": True,
                    "default": None,
                    "max_length": None,
                    "indexed": False,
                    "references": None,
                    "input_allowed": True,
                    "output_allowed": True,
                },
                {
                    "name": "user_id",
                    "python_type": "str",
                    "nullable": False,
                    "unique": False,
                    "default": None,
                    "max_length": None,
                    "indexed": True,
                    "references": None,
                    "input_allowed": True,
                    "output_allowed": True,
                },
            ],
            "index": None,
            "migration": None,
        },
        {
            "op": "create_index",
            "plugin_id": "api_key",
            "table_name": "api_keys",
            "fields": [],
            "index": {
                "name": "api_keys_user_id_idx",
                "fields": ["user_id"],
                "unique": False,
            },
            "migration": None,
        },
        {
            "op": "record_migration",
            "plugin_id": "api_key",
            "table_name": None,
            "fields": [],
            "index": None,
            "migration": {
                "plugin_id": "api_key",
                "name": "create_api_keys",
                "version": 1,
                "description": None,
            },
        },
    ]
    assert plan.to_operations() == render_migration_operations(plan)


def test_schema_plan_validates_index_fields_and_duplicate_migration_versions() -> None:
    with pytest.raises(ValidationError, match="unknown field"):
        PlannedTable(
            plugin_id="search",
            name="search_items",
            fields=(FieldSpec(name="id", python_type="str"),),
            indexes=(IndexSpec(name="search_items_missing_idx", fields=("missing",)),),
        )

    with pytest.raises(ValidationError, match="duplicate migration version"):
        PluginSchemaPlan(
            migrations=(
                PlannedMigration(plugin_id="search", name="create_search_items", version=1),
                PlannedMigration(plugin_id="search", name="add_search_title", version=1),
            ),
        )


def test_migration_operation_validates_payload_for_operation_kind() -> None:
    with pytest.raises(ValidationError, match="requires table_name and index"):
        MigrationOperation(op="create_index", plugin_id="api_key", table_name="api_keys")

    with pytest.raises(ValidationError, match="only accepts migration payload"):
        MigrationOperation(
            op="record_migration",
            plugin_id="api_key",
            table_name="api_keys",
            migration=PlannedMigration(plugin_id="api_key", name="create_api_keys", version=1),
        )
