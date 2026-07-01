"""Storage-agnostic Pydantic domain models used throughout fastauth."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, JsonValue
from pydantic.alias_generators import to_camel

from fastauth.domain.enums import (
    AuditEventType,
    EmailMessageKind,
    ProviderId,
    VerificationPurpose,
)
from fastauth.domain.value_objects import NonEmptyString

__all__ = [
    "Account",
    "ApiKey",
    "AuditLog",
    "EmailMessage",
    "FastAuthModel",
    "JwksKey",
    "RateLimit",
    "RefreshToken",
    "Session",
    "User",
    "Verification",
    "WireModel",
    "new_id",
    "utc_now",
]


def new_id() -> str:
    """Return a fresh hex UUID v4."""
    return uuid.uuid4().hex


def utc_now() -> datetime:
    """Return the current time as a timezone-aware UTC datetime."""
    return datetime.now(UTC)


class FastAuthModel(BaseModel):
    """Common base for every fastauth domain model.

    Domain models do **not** carry the HTTP alias generator. Public response
    DTOs own wire serialization so persistence and HTTP can evolve separately.
    """

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        populate_by_name=True,
    )


class WireModel(BaseModel):
    """Base for public request / response models.

    Carries ``alias_generator=to_camel`` + ``populate_by_name=True`` so
    request bodies in either ``snake_case`` or ``camelCase`` parse correctly.
    Output serialization uses Pydantic aliases directly.
    """

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        alias_generator=to_camel,
        serialize_by_alias=True,
    )


class User(FastAuthModel):
    id: NonEmptyString = Field(default_factory=new_id)
    email: EmailStr
    username: str | None = None
    name: str | None = None
    image: str | None = None
    email_verified: bool = False
    pending_email_change: EmailStr | None = None
    metadata: dict[str, JsonValue] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class Session(FastAuthModel):
    id: NonEmptyString = Field(default_factory=new_id)
    user_id: NonEmptyString
    token_hash: NonEmptyString
    expires_at: datetime
    ip_address: str | None = None
    user_agent: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class RefreshToken(FastAuthModel):
    """Long-lived credential that mints fresh access tokens on demand.

    Refresh tokens are rotated on every use (OAuth 2.1 recommendation):
    presenting one returns a brand-new refresh token and the old one is
    marked ``consumed_at``. If a previously-consumed token is presented
    again, that's evidence of theft — the entire family (every token sharing
    the same ``family_id``) is revoked and the user is forced to re-auth.

    Fields:

    * ``token_hash`` — SHA-256 of the opaque token returned to the client.
      The plain token never persists.
    * ``family_id`` — the id of the *root* token in the rotation chain.
      Created equal to the token's own id on initial issue, copied forward
      on each rotation. Reuse-detection deletes every row with the same
      family_id.
    * ``consumed_at`` — set when the token is rotated. The row is retained
      (not deleted) so a subsequent reuse can be detected. A separate
      cleanup pass (or TTL on ``expires_at``) removes consumed-and-expired
      rows.
    * ``replaced_by`` — id of the rotation successor, useful for audit
      trail reconstruction.
    """

    id: NonEmptyString = Field(default_factory=new_id)
    user_id: NonEmptyString
    token_hash: NonEmptyString
    family_id: NonEmptyString
    expires_at: datetime
    consumed_at: datetime | None = None
    replaced_by: NonEmptyString | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class Account(FastAuthModel):
    """Links a user to an authentication provider (credential, future OAuth, ...)."""

    id: NonEmptyString = Field(default_factory=new_id)
    user_id: NonEmptyString
    provider_id: ProviderId
    account_id: NonEmptyString
    password: NonEmptyString | None = None  # argon2 hash, only for credential provider
    access_token: NonEmptyString | None = None
    refresh_token: NonEmptyString | None = None
    access_token_expires_at: datetime | None = None
    refresh_token_expires_at: datetime | None = None
    scope: str | None = None
    id_token: NonEmptyString | None = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class Verification(FastAuthModel):
    id: NonEmptyString = Field(default_factory=new_id)
    identifier: NonEmptyString  # email or username
    value_hash: NonEmptyString  # sha-256 of the plain token / OTP
    purpose: VerificationPurpose
    expires_at: datetime
    # Number of failed verify attempts. Bumped by ``EmailOtpPlugin`` to enforce
    # the per-OTP attempt cap; token-based flows ignore the field. The row is
    # deleted (not just expired) once the cap is exceeded so the next request
    # has to mint a fresh OTP.
    attempt_count: int = 0
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class ApiKey(FastAuthModel):
    id: NonEmptyString = Field(default_factory=new_id)
    user_id: NonEmptyString
    name: NonEmptyString
    key_hash: NonEmptyString
    key_prefix: NonEmptyString
    enabled: bool = True
    expires_at: datetime | None = None
    remaining: int | None = None
    refill_amount: int | None = None
    refill_interval_ms: int | None = None
    rate_limit_enabled: bool = False
    rate_limit_max: int | None = None
    rate_limit_window_ms: int | None = None
    last_refill_at: datetime | None = None
    last_request_at: datetime | None = None
    request_count: int = 0
    metadata: dict[str, JsonValue] = Field(default_factory=dict)
    permissions: dict[str, list[str]] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class JwksKey(FastAuthModel):
    id: NonEmptyString = Field(default_factory=new_id)
    kid: NonEmptyString
    alg: NonEmptyString
    public_key: NonEmptyString  # PEM or JWK JSON
    private_key_encrypted: bytes
    created_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime | None = None
    rotated_at: datetime | None = None


class RateLimit(FastAuthModel):
    id: NonEmptyString = Field(default_factory=new_id)
    key: NonEmptyString
    count: int
    last_request_ms: int


class AuditLog(FastAuthModel):
    id: NonEmptyString = Field(default_factory=new_id)
    event_type: AuditEventType
    identifier: NonEmptyString | None = None
    user_id: NonEmptyString | None = None
    ip_address: NonEmptyString | None = None
    user_agent: NonEmptyString | None = None
    event_data: dict[str, JsonValue] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)


class EmailMessage(FastAuthModel):
    kind: EmailMessageKind | None = None
    to: EmailStr
    subject: NonEmptyString
    html: NonEmptyString
    text: NonEmptyString
    headers: dict[str, str] = Field(default_factory=dict)
