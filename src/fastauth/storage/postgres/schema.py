"""SQLAlchemy Core schema for the first-party Postgres adapter."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB

__all__ = ["PostgresSchema", "build_postgres_schema"]


@dataclass(frozen=True)
class PostgresSchema:
    metadata: MetaData
    schema_migrations: Table
    users: Table
    sessions: Table
    refresh_tokens: Table
    accounts: Table
    verifications: Table
    api_keys: Table
    jwks_keys: Table
    audit_logs: Table
    rate_limits: Table


def id_column() -> Column[str]:
    return Column("id", String(64), primary_key=True)


def timestamp_columns() -> list[Column[Any]]:
    return [
        Column("created_at", DateTime(timezone=True), nullable=False),
        Column("updated_at", DateTime(timezone=True), nullable=False),
    ]


def postgres_table_name(base_name: str, table_prefix: str, table_suffix: str) -> str:
    return f"{table_prefix}{base_name}{table_suffix}"


def build_postgres_schema(
    table_prefix: str = "fastauth_",
    table_suffix: str = "",
) -> PostgresSchema:
    metadata = MetaData()
    schema_migrations_name = postgres_table_name("schema_migrations", table_prefix, table_suffix)
    users_name = postgres_table_name("users", table_prefix, table_suffix)
    sessions_name = postgres_table_name("sessions", table_prefix, table_suffix)
    refresh_tokens_name = postgres_table_name("refresh_tokens", table_prefix, table_suffix)
    accounts_name = postgres_table_name("accounts", table_prefix, table_suffix)
    verifications_name = postgres_table_name("verifications", table_prefix, table_suffix)
    api_keys_name = postgres_table_name("api_keys", table_prefix, table_suffix)
    jwks_keys_name = postgres_table_name("jwks_keys", table_prefix, table_suffix)
    audit_logs_name = postgres_table_name("audit_logs", table_prefix, table_suffix)
    rate_limits_name = postgres_table_name("rate_limits", table_prefix, table_suffix)

    schema_migrations = Table(
        schema_migrations_name,
        metadata,
        Column("version", Integer, primary_key=True),
        Column("applied_at", DateTime(timezone=True), nullable=False),
    )

    users = Table(
        users_name,
        metadata,
        id_column(),
        Column("email", String(320), nullable=False, unique=True),
        Column("username", String(255), nullable=True, unique=True),
        Column("name", String(255), nullable=True),
        Column("image", Text, nullable=True),
        Column("email_verified", Boolean, nullable=False),
        Column("pending_email_change", String(320), nullable=True),
        Column("metadata", JSONB, nullable=False),
        *timestamp_columns(),
        Index(f"{users_name}_pending_email_change_idx", "pending_email_change"),
    )

    sessions = Table(
        sessions_name,
        metadata,
        id_column(),
        Column(
            "user_id",
            String(64),
            ForeignKey(f"{users.name}.id", ondelete="CASCADE"),
            nullable=False,
        ),
        Column("token_hash", String(255), nullable=False, unique=True),
        Column("expires_at", DateTime(timezone=True), nullable=False),
        Column("ip_address", String(255), nullable=True),
        Column("user_agent", Text, nullable=True),
        *timestamp_columns(),
        Index(f"{sessions_name}_user_id_idx", "user_id"),
        Index(f"{sessions_name}_expires_at_idx", "expires_at"),
    )

    refresh_tokens = Table(
        refresh_tokens_name,
        metadata,
        id_column(),
        Column(
            "user_id",
            String(64),
            ForeignKey(f"{users.name}.id", ondelete="CASCADE"),
            nullable=False,
        ),
        Column("token_hash", String(255), nullable=False, unique=True),
        Column("family_id", String(64), nullable=False),
        Column("expires_at", DateTime(timezone=True), nullable=False),
        Column("consumed_at", DateTime(timezone=True), nullable=True),
        Column("replaced_by", String(64), nullable=True),
        Column("ip_address", String(255), nullable=True),
        Column("user_agent", Text, nullable=True),
        *timestamp_columns(),
        Index(f"{refresh_tokens_name}_user_id_idx", "user_id"),
        Index(f"{refresh_tokens_name}_family_id_idx", "family_id"),
        Index(f"{refresh_tokens_name}_expires_at_idx", "expires_at"),
    )

    accounts = Table(
        accounts_name,
        metadata,
        id_column(),
        Column(
            "user_id",
            String(64),
            ForeignKey(f"{users.name}.id", ondelete="CASCADE"),
            nullable=False,
        ),
        Column("provider_id", String(64), nullable=False),
        Column("account_id", String(255), nullable=False),
        Column("password", Text, nullable=True),
        Column("access_token", Text, nullable=True),
        Column("refresh_token", Text, nullable=True),
        Column("access_token_expires_at", DateTime(timezone=True), nullable=True),
        Column("refresh_token_expires_at", DateTime(timezone=True), nullable=True),
        Column("scope", Text, nullable=True),
        Column("id_token", Text, nullable=True),
        *timestamp_columns(),
        UniqueConstraint("user_id", "provider_id", name=f"{accounts_name}_user_provider_uq"),
        Index(f"{accounts_name}_user_id_idx", "user_id"),
    )

    verifications = Table(
        verifications_name,
        metadata,
        id_column(),
        Column("identifier", String(320), nullable=False),
        Column("value_hash", String(255), nullable=False),
        Column("purpose", String(96), nullable=False),
        Column("expires_at", DateTime(timezone=True), nullable=False),
        Column("attempt_count", Integer, nullable=False),
        *timestamp_columns(),
        UniqueConstraint(
            "identifier",
            "purpose",
            "value_hash",
            name=f"{verifications_name}_identifier_purpose_hash_uq",
        ),
        Index(f"{verifications_name}_identifier_purpose_idx", "identifier", "purpose"),
        Index(f"{verifications_name}_expires_at_idx", "expires_at"),
    )

    api_keys = Table(
        api_keys_name,
        metadata,
        id_column(),
        Column(
            "user_id",
            String(64),
            ForeignKey(f"{users.name}.id", ondelete="CASCADE"),
            nullable=False,
        ),
        Column("name", String(255), nullable=False),
        Column("key_hash", String(255), nullable=False, unique=True),
        Column("key_prefix", String(64), nullable=False),
        Column("enabled", Boolean, nullable=False),
        Column("expires_at", DateTime(timezone=True), nullable=True),
        Column("remaining", Integer, nullable=True),
        Column("refill_amount", Integer, nullable=True),
        Column("refill_interval_ms", Integer, nullable=True),
        Column("rate_limit_enabled", Boolean, nullable=False),
        Column("rate_limit_max", Integer, nullable=True),
        Column("rate_limit_window_ms", Integer, nullable=True),
        Column("last_refill_at", DateTime(timezone=True), nullable=True),
        Column("last_request_at", DateTime(timezone=True), nullable=True),
        Column("request_count", Integer, nullable=False),
        Column("metadata", JSONB, nullable=False),
        Column("permissions", JSONB, nullable=False),
        *timestamp_columns(),
        Index(f"{api_keys_name}_user_id_idx", "user_id"),
        Index(f"{api_keys_name}_expires_at_idx", "expires_at"),
    )

    jwks_keys = Table(
        jwks_keys_name,
        metadata,
        id_column(),
        Column("kid", String(255), nullable=False, unique=True),
        Column("alg", String(32), nullable=False),
        Column("public_key", Text, nullable=False),
        Column("private_key_encrypted", LargeBinary, nullable=False),
        Column("created_at", DateTime(timezone=True), nullable=False),
        Column("expires_at", DateTime(timezone=True), nullable=True),
        Column("rotated_at", DateTime(timezone=True), nullable=True),
    )

    audit_logs = Table(
        audit_logs_name,
        metadata,
        id_column(),
        Column("event_type", String(96), nullable=False),
        Column("identifier", String(320), nullable=True),
        Column("user_id", String(64), nullable=True),
        Column("ip_address", String(255), nullable=True),
        Column("user_agent", Text, nullable=True),
        Column("event_data", JSONB, nullable=False),
        Column("created_at", DateTime(timezone=True), nullable=False),
        Index(f"{audit_logs_name}_user_event_idx", "user_id", "event_type"),
        Index(f"{audit_logs_name}_created_at_idx", "created_at"),
    )

    rate_limits = Table(
        rate_limits_name,
        metadata,
        id_column(),
        Column("key", String(512), nullable=False, unique=True),
        Column("count", Integer, nullable=False),
        Column("last_request_ms", Integer, nullable=False),
    )

    return PostgresSchema(
        metadata=metadata,
        schema_migrations=schema_migrations,
        users=users,
        sessions=sessions,
        refresh_tokens=refresh_tokens,
        accounts=accounts,
        verifications=verifications,
        api_keys=api_keys,
        jwks_keys=jwks_keys,
        audit_logs=audit_logs,
        rate_limits=rate_limits,
    )
