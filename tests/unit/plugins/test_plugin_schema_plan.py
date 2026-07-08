from __future__ import annotations

import pytest

from fastauth.plugins.migrations import build_schema_plan, render_migration_operations
from fastauth.plugins.schema import FieldSpec, IndexSpec, MigrationSpec, PluginSchema, TableSpec


def test_schema_plan_is_deterministic_and_json_serializable() -> None:
    beta = PluginSchema(
        plugin_id="beta",
        tables=(
            TableSpec(
                name="beta_records",
                fields=(FieldSpec(name="id", python_type="str", unique=True),),
                indexes=(IndexSpec(name="beta_records_id_idx", fields=("id",)),),
            ),
        ),
    )
    alpha = PluginSchema(
        plugin_id="alpha",
        tables=(
            TableSpec(
                name="alpha_records",
                fields=(FieldSpec(name="id", python_type="str"),),
            ),
        ),
        migrations=(MigrationSpec(name="create_alpha_records", version=1),),
    )

    plan = build_schema_plan((beta, alpha))

    assert [table.name for table in plan.tables] == ["alpha_records", "beta_records"]
    assert plan.tables[0].plugin_id == "alpha"
    assert plan.tables[1].indexes[0].name == "beta_records_id_idx"
    assert plan.model_dump(mode="json")["tables"][0]["fields"][0]["name"] == "id"


def test_schema_plan_rejects_duplicate_tables_across_plugins() -> None:
    first = PluginSchema(plugin_id="first", tables=(TableSpec(name="shared"),))
    second = PluginSchema(plugin_id="second", tables=(TableSpec(name="shared"),))

    with pytest.raises(ValueError, match="duplicate plugin table 'shared'"):
        build_schema_plan((first, second))


def test_schema_plan_rejects_duplicate_migration_versions_per_plugin() -> None:
    schema = PluginSchema(
        plugin_id="alpha",
        migrations=(
            MigrationSpec(name="create_alpha", version=1),
            MigrationSpec(name="alter_alpha", version=1),
        ),
    )

    with pytest.raises(ValueError, match="duplicate migration version in schema plan"):
        build_schema_plan((schema,))


def test_render_migration_operations_is_adapter_neutral() -> None:
    plan = build_schema_plan(
        (
            PluginSchema(
                plugin_id="alpha",
                tables=(
                    TableSpec(
                        name="alpha_records",
                        fields=(
                            FieldSpec(name="id", python_type="str", unique=True),
                            FieldSpec(name="user_id", python_type="str", references="users.id"),
                        ),
                        indexes=(IndexSpec(name="alpha_user_idx", fields=("user_id",)),),
                    ),
                ),
                migrations=(MigrationSpec(name="create_alpha_records", version=1),),
            ),
        ),
    )

    operations = render_migration_operations(plan)

    assert [operation.op for operation in operations] == [
        "create_table",
        "create_index",
        "record_migration",
    ]
    assert [field.name for field in operations[0].fields] == ["id", "user_id"]
    assert operations[0].fields[1].references == "users.id"
    assert operations[1].index is not None
    assert operations[1].index.name == "alpha_user_idx"
    assert operations[-1].migration is not None
    assert operations[-1].migration.name == "create_alpha_records"
    assert operations[-1].migration.version == 1
