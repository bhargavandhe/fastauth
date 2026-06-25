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


def build_postgres_schema(table_prefix: str = "authkit_") -> PostgresSchema:
    metadata = MetaData()

    users = Table(
        f"{table_prefix}users",
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
        Index(f"{table_prefix}users_pending_email_change_idx", "pending_email_change"),
    )

    sessions = Table(
        f"{table_prefix}sessions",
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
        Index(f"{table_prefix}sessions_user_id_idx", "user_id"),
        Index(f"{table_prefix}sessions_expires_at_idx", "expires_at"),
    )

    refresh_tokens = Table(
        f"{table_prefix}refresh_tokens",
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
        Index(f"{table_prefix}refresh_tokens_user_id_idx", "user_id"),
        Index(f"{table_prefix}refresh_tokens_family_id_idx", "family_id"),
        Index(f"{table_prefix}refresh_tokens_expires_at_idx", "expires_at"),
    )

    accounts = Table(
        f"{table_prefix}accounts",
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
        UniqueConstraint("user_id", "provider_id", name=f"{table_prefix}accounts_user_provider_uq"),
        Index(f"{table_prefix}accounts_user_id_idx", "user_id"),
    )

    verifications = Table(
        f"{table_prefix}verifications",
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
            name=f"{table_prefix}verifications_identifier_purpose_hash_uq",
        ),
        Index(f"{table_prefix}verifications_identifier_purpose_idx", "identifier", "purpose"),
        Index(f"{table_prefix}verifications_expires_at_idx", "expires_at"),
    )

    api_keys = Table(
        f"{table_prefix}api_keys",
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
        Index(f"{table_prefix}api_keys_user_id_idx", "user_id"),
        Index(f"{table_prefix}api_keys_expires_at_idx", "expires_at"),
    )

    jwks_keys = Table(
        f"{table_prefix}jwks_keys",
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
        f"{table_prefix}audit_logs",
        metadata,
        id_column(),
        Column("event_type", String(96), nullable=False),
        Column("identifier", String(320), nullable=True),
        Column("user_id", String(64), nullable=True),
        Column("ip_address", String(255), nullable=True),
        Column("user_agent", Text, nullable=True),
        Column("event_data", JSONB, nullable=False),
        Column("created_at", DateTime(timezone=True), nullable=False),
        Index(f"{table_prefix}audit_logs_user_event_idx", "user_id", "event_type"),
        Index(f"{table_prefix}audit_logs_created_at_idx", "created_at"),
    )

    rate_limits = Table(
        f"{table_prefix}rate_limits",
        metadata,
        id_column(),
        Column("key", String(512), nullable=False, unique=True),
        Column("count", Integer, nullable=False),
        Column("last_request_ms", Integer, nullable=False),
    )

    return PostgresSchema(
        metadata=metadata,
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
