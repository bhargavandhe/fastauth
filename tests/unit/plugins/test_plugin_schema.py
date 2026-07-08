from __future__ import annotations

import pytest
from pydantic import ValidationError

from fastauth.plugins.schema import FieldSpec, IndexSpec, MigrationSpec, PluginSchema, TableSpec


def test_plugin_schema_describes_plugin_owned_tables() -> None:
    schema = PluginSchema(
        plugin_id="api-key",
        tables=(
            TableSpec(
                name="api_keys",
                fields=(
                    FieldSpec(name="id", python_type="str", unique=True),
                    FieldSpec(
                        name="user_id",
                        python_type="str",
                        references="users.id",
                        indexed=True,
                    ),
                    FieldSpec(
                        name="label",
                        python_type="str",
                        nullable=True,
                        default=None,
                        max_length=80,
                        input_allowed=True,
                        output_allowed=True,
                    ),
                ),
                indexes=(
                    IndexSpec(name="api_keys_user_id_idx", fields=("user_id",)),
                    IndexSpec(
                        name="api_keys_user_label_idx",
                        fields=("user_id", "label"),
                        unique=True,
                    ),
                ),
            ),
        ),
        migrations=(
            MigrationSpec(
                name="create_api_keys",
                version=1,
                description="Create plugin-owned API key storage.",
            ),
        ),
    )

    assert schema.plugin_id == "api-key"
    assert schema.tables[0].fields[1].references == "users.id"
    assert schema.tables[0].indexes[1].fields == ("user_id", "label")
    assert schema.migrations[0].version == 1
    assert schema.model_dump(mode="json")["tables"][0]["fields"][2]["max_length"] == 80


def test_plugin_schema_models_are_strict_frozen_and_forbid_extra_fields() -> None:
    field = FieldSpec(name="email", python_type="str")

    with pytest.raises(ValidationError):
        field.name = "other"  # type: ignore[misc]

    with pytest.raises(ValidationError):
        FieldSpec(name="email", python_type="str", nullable="false")  # type: ignore[arg-type]

    with pytest.raises(ValidationError):
        FieldSpec(name="email", python_type="str", unexpected=True)  # type: ignore[call-arg]


@pytest.mark.parametrize(
    ("model", "kwargs"),
    [
        (PluginSchema, {"plugin_id": "", "tables": ()}),
        (TableSpec, {"name": "api-keys"}),
        (TableSpec, {"name": "1api_keys"}),
        (FieldSpec, {"name": "user-id", "python_type": "str"}),
        (FieldSpec, {"name": "1user_id", "python_type": "str"}),
        (IndexSpec, {"name": "api keys idx", "fields": ("user_id",)}),
        (MigrationSpec, {"name": "create api keys", "version": 1}),
    ],
)
def test_plugin_schema_rejects_invalid_names(model: type, kwargs: dict[str, object]) -> None:
    with pytest.raises(ValidationError, match="identifier"):
        model(**kwargs)


def test_table_spec_rejects_duplicate_field_names() -> None:
    with pytest.raises(ValidationError, match="duplicate field name"):
        TableSpec(
            name="accounts",
            fields=(
                FieldSpec(name="email", python_type="str"),
                FieldSpec(name="email", python_type="str"),
            ),
        )


def test_table_spec_rejects_duplicate_index_names() -> None:
    with pytest.raises(ValidationError, match="duplicate index name"):
        TableSpec(
            name="accounts",
            fields=(FieldSpec(name="email", python_type="str"),),
            indexes=(
                IndexSpec(name="accounts_email_idx", fields=("email",)),
                IndexSpec(name="accounts_email_idx", fields=("email",)),
            ),
        )


def test_plugin_schema_rejects_duplicate_table_and_migration_names() -> None:
    with pytest.raises(ValidationError, match="duplicate table name"):
        PluginSchema(
            plugin_id="accounts",
            tables=(TableSpec(name="accounts"), TableSpec(name="accounts")),
        )

    with pytest.raises(ValidationError, match="duplicate migration name"):
        PluginSchema(
            plugin_id="accounts",
            migrations=(
                MigrationSpec(name="create_accounts", version=1),
                MigrationSpec(name="create_accounts", version=2),
            ),
        )


def test_index_spec_rejects_duplicate_or_empty_field_lists() -> None:
    with pytest.raises(ValidationError, match="at least one field"):
        IndexSpec(name="accounts_empty_idx", fields=())

    with pytest.raises(ValidationError, match="duplicate index field"):
        IndexSpec(name="accounts_email_idx", fields=("email", "email"))
