"""Pydantic models for plugin-owned storage schema declarations."""

from __future__ import annotations

import re
from typing import Any, Literal, Self, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

__all__ = [
    "FieldSpec",
    "IndexSpec",
    "MigrationSpec",
    "PluginFieldType",
    "PluginSchema",
    "TableSpec",
]

IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
REFERENCE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*$")
PluginFieldType: TypeAlias = Literal[
    "bool",
    "bytes",
    "datetime",
    "float",
    "int",
    "json",
    "str",
]


def validate_identifier(value: str, *, label: str) -> str:
    if not IDENTIFIER_RE.fullmatch(value):
        raise ValueError(
            f"{label} must be a valid identifier: start with a letter or underscore, "
            "then use only letters, digits, or underscores",
        )
    return value


def find_duplicate(values: tuple[str, ...]) -> str | None:
    seen: set[str] = set()
    for value in values:
        if value in seen:
            return value
        seen.add(value)
    return None


class PluginSchemaModel(BaseModel):
    """Common immutable base for plugin schema declaration models."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
        revalidate_instances="always",
    )


class FieldSpec(PluginSchemaModel):
    """A field contributed by a plugin-owned table or collection."""

    name: str
    python_type: PluginFieldType
    nullable: bool = False
    unique: bool = False
    default: Any | None = None
    max_length: int | None = Field(default=None, gt=0)
    indexed: bool = False
    references: str | None = None
    input_allowed: bool = True
    output_allowed: bool = True

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        return validate_identifier(value, label="field name")

    @field_validator("references")
    @classmethod
    def validate_references(cls, value: str | None) -> str | None:
        if value is not None and REFERENCE_RE.fullmatch(value) is None:
            raise ValueError("references must use the form table.field")
        return value


class IndexSpec(PluginSchemaModel):
    """An index contributed by a plugin-owned table or collection."""

    name: str
    fields: tuple[str, ...]
    unique: bool = False

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        return validate_identifier(value, label="index name")

    @field_validator("fields")
    @classmethod
    def validate_fields(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value:
            raise ValueError("index must include at least one field")
        for field_name in value:
            validate_identifier(field_name, label="index field")
        duplicate = find_duplicate(value)
        if duplicate is not None:
            raise ValueError(f"duplicate index field name: {duplicate}")
        return value


class MigrationSpec(PluginSchemaModel):
    """A plugin-owned migration marker for future adapter-specific generation."""

    name: str
    version: int = Field(ge=1)
    description: str | None = None

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        return validate_identifier(value, label="migration name")


class TableSpec(PluginSchemaModel):
    """A plugin-owned table or collection declaration."""

    name: str
    fields: tuple[FieldSpec, ...] = ()
    indexes: tuple[IndexSpec, ...] = ()

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        return validate_identifier(value, label="table name")

    @model_validator(mode="after")
    def validate_unique_names(self) -> Self:
        duplicate_field = find_duplicate(tuple(field.name for field in self.fields))
        if duplicate_field is not None:
            raise ValueError(f"duplicate field name: {duplicate_field}")

        duplicate_index = find_duplicate(tuple(index.name for index in self.indexes))
        if duplicate_index is not None:
            raise ValueError(f"duplicate index name: {duplicate_index}")

        return self


class PluginSchema(PluginSchemaModel):
    """A plugin's complete storage schema contribution."""

    plugin_id: str
    tables: tuple[TableSpec, ...] = ()
    migrations: tuple[MigrationSpec, ...] = ()

    @field_validator("plugin_id")
    @classmethod
    def validate_plugin_id(cls, value: str) -> str:
        if not value:
            raise ValueError("plugin_id must be a non-empty plugin identifier")
        return value

    @model_validator(mode="after")
    def validate_unique_names(self) -> Self:
        duplicate_table = find_duplicate(tuple(table.name for table in self.tables))
        if duplicate_table is not None:
            raise ValueError(f"duplicate table name: {duplicate_table}")

        duplicate_migration = find_duplicate(
            tuple(migration.name for migration in self.migrations),
        )
        if duplicate_migration is not None:
            raise ValueError(f"duplicate migration name: {duplicate_migration}")

        return self
