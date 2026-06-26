"""Pydantic configuration for fastauth.

:class:`FastAuthConfig` is a plain Pydantic v2 ``BaseModel``. All values are
passed explicitly at instantiation time, with Pydantic's validation enforced
on construction. The framework has no notion of "environment variables" —
reading from process-level configuration, files, AWS Secrets Manager,
HashiCorp Vault, or any other source is the consumer's responsibility. Pass
the values in as constructor arguments and fastauth will validate them.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr

from fastauth.domain.enums import (
    DatabaseBackendKind,
    RateLimitStorageKind,
    SessionStrategyKind,
    WireFormat,
)

__all__ = [
    "AdvancedConfig",
    "AppConfig",
    "CookieConfig",
    "CsrfConfig",
    "DatabaseConfig",
    "DeleteAccountConfig",
    "EmailChangeConfig",
    "EmailConfig",
    "EmailVerificationConfig",
    "FastAuthConfig",
    "LockoutConfig",
    "MemoryDatabaseConfig",
    "MongoDatabaseConfig",
    "PasswordConfig",
    "PasswordResetConfig",
    "PostgresDatabaseConfig",
    "RateLimitConfig",
    "RefreshTokenConfig",
    "SecurityHeadersConfig",
    "SessionConfig",
]


class ConfigSection(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class AppConfig(ConfigSection):
    name: str = "fastauth"
    base_url: str = "http://localhost:8000"
    base_path: str = "/auth"


class SessionConfig(ConfigSection):
    strategy: SessionStrategyKind = SessionStrategyKind.DATABASE
    max_age_seconds: int = 60 * 60 * 24 * 7
    idle_timeout_seconds: int | None = None
    rotate_on_refresh: bool = True


class CookieConfig(ConfigSection):
    name: str = "fastauth.session_token"
    domain: str | None = None
    path: str = "/"
    secure: bool = True
    http_only: bool = True
    same_site: Literal["lax", "strict", "none"] = "lax"


class PasswordConfig(ConfigSection):
    min_length: int = 8
    argon2_time_cost: int = 3
    argon2_memory_cost_kib: int = 64 * 1024  # 64 MiB
    argon2_parallelism: int = 4


class EmailConfig(ConfigSection):
    from_address: str = "no-reply@localhost"
    from_name: str = "fastauth"
    verification_subject: str = "Verify your email"
    password_reset_subject: str = "Reset your password"  # noqa: S105
    template_directory: str | None = None


class EmailVerificationConfig(ConfigSection):
    token_ttl_minutes: int = 15
    require_verified_for_sign_in: bool = False
    base_verify_url: str = "http://localhost:8000/auth/verify-email"


class PasswordResetConfig(ConfigSection):
    token_ttl_minutes: int = 30
    base_reset_url: str = "http://localhost:8000/auth/reset-password"


class EmailChangeConfig(ConfigSection):
    token_ttl_minutes: int = 15
    base_confirm_url: str = "http://localhost:8000/auth/change-email/confirm"
    subject: str = "Confirm your new email address"


class DeleteAccountConfig(ConfigSection):
    token_ttl_minutes: int = 15
    base_confirm_url: str = "http://localhost:8000/auth/delete-account/confirm"
    subject: str = "Confirm account deletion"


class RateLimitConfig(ConfigSection):
    enabled: bool = True
    window_seconds: int = 60
    max_requests: int = 100
    storage: RateLimitStorageKind = RateLimitStorageKind.MEMORY


class CsrfConfig(ConfigSection):
    enabled: bool = True
    trusted_origins: list[str] = Field(default_factory=list)
    allow_relative_paths: bool = True


class LockoutConfig(ConfigSection):
    """Account-lockout policy: lock an identifier after N failed sign-ins.

    ``window_seconds`` doubles as the lockout duration — failures older than
    the window are forgotten, and a triggered lockout naturally expires at the
    same horizon. ``max_failures=5`` matches NIST 800-63B's guidance for
    consumer auth (5 is the typical default in libraries like Devise and
    fastapi-users); raise it for low-risk applications or to combat false
    positives from shared NAT.
    """

    enabled: bool = True
    max_failures: int = 5
    window_seconds: int = 15 * 60


class RefreshTokenConfig(ConfigSection):
    """Long-lived refresh-token policy.

    Refresh tokens piggyback on the bearer-token transport: when ``enabled``
    is true (default) AND the sign-up / sign-in request opts into a bearer
    response via ``include_token=true``, the response carries a
    ``refresh_token`` that the client can later exchange at
    ``POST /auth/refresh`` for a fresh access session. Cookie-only clients
    (``include_token=false``) skip the refresh token entirely — their cookie
    *is* the long-lived credential, so a separate refresh token would be
    redundant.

    Tokens are rotated on every use (one-time-use; OAuth 2.1 recommendation):
    presenting a refresh token returns a *new* token and marks the old one
    consumed. Presenting a previously-consumed token revokes the entire
    rotation chain (theft-detection) — the user is forced to sign in again.

    ``max_age_seconds`` defaults to 30 days. ``absolute_max_age_seconds``
    caps the total lifetime of a single rotation chain — even with continuous
    rotation, a chain expires after this many seconds since the initial
    sign-in. Set to ``None`` to disable the absolute cap (rotation can extend
    sessions indefinitely as long as the user is active).
    """

    enabled: bool = True
    max_age_seconds: int = 30 * 24 * 60 * 60
    absolute_max_age_seconds: int | None = None


class SecurityHeadersConfig(ConfigSection):
    """Response-header hardening (HSTS, frame-ancestors, MIME-sniffing, …).

    Defaults match the OWASP Secure Headers Project's recommendations for a
    typical SaaS web application. Every header is individually toggleable —
    set ``hsts=None`` (etc.) to omit. The default ``hsts`` value
    (``"max-age=31536000; includeSubDomains"``) is conservative; production
    deployments preloaded into the HSTS preload list should add ``; preload``.

    ``content_security_policy`` defaults to ``None`` because a meaningful CSP
    is application-specific. Set it to a string and the middleware will emit
    a ``Content-Security-Policy`` header verbatim.
    """

    enabled: bool = True
    hsts: str | None = "max-age=31536000; includeSubDomains"
    x_frame_options: str | None = "DENY"
    x_content_type_options: str | None = "nosniff"
    referrer_policy: str | None = "strict-origin-when-cross-origin"
    permissions_policy: str | None = None
    content_security_policy: str | None = None


class MongoDatabaseConfig(ConfigSection):
    url: str = "mongodb://localhost:27017"
    database_name: str = "fastauth"


class PostgresDatabaseConfig(ConfigSection):
    url: str = "postgresql+asyncpg://localhost/fastauth"
    table_prefix: str = "fastauth_"


class MemoryDatabaseConfig(ConfigSection):
    pass


class DatabaseConfig(ConfigSection):
    backend: DatabaseBackendKind = DatabaseBackendKind.MEMORY
    memory: MemoryDatabaseConfig = Field(default_factory=MemoryDatabaseConfig)
    mongo: MongoDatabaseConfig = Field(default_factory=MongoDatabaseConfig)
    postgres: PostgresDatabaseConfig = Field(default_factory=PostgresDatabaseConfig)


class AdvancedConfig(ConfigSection):
    ip_address_headers: list[str] = Field(default_factory=lambda: ["x-forwarded-for"])
    ipv6_subnet: int = 64
    cookie_secure_prefix: bool = True


def empty_secret_str_list() -> list[SecretStr]:
    """Typed default factory for ``secret_key_rotation`` (keeps pyright strict happy)."""
    return []


class FastAuthConfig(BaseModel):
    """Top-level fastauth configuration.

    A plain Pydantic v2 ``BaseModel``. Construction validates the entire tree
    eagerly. **The framework never reads process-level configuration or any
    other external source** — every value comes from the constructor. Consumers
    should read their chosen configuration source in their own code and pass
    the values in explicitly.

    Example::

        from pydantic import SecretStr
        from fastauth import FastAuth, FastAuthConfig
        from fastauth.config import DatabaseConfig, MongoDatabaseConfig

        config = FastAuthConfig(
            secret_key=SecretStr("..."),
            database=DatabaseConfig(
                backend="mongo",
                mongo=MongoDatabaseConfig(url="mongodb://localhost:27017"),
            ),
        )
        auth = FastAuth(config, adapter=...)
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    secret_key: SecretStr
    secret_key_rotation: list[SecretStr] = Field(default_factory=empty_secret_str_list)
    app: AppConfig = Field(default_factory=AppConfig)
    session: SessionConfig = Field(default_factory=SessionConfig)
    cookie: CookieConfig = Field(default_factory=CookieConfig)
    password: PasswordConfig = Field(default_factory=PasswordConfig)
    email: EmailConfig = Field(default_factory=EmailConfig)
    email_verification: EmailVerificationConfig = Field(default_factory=EmailVerificationConfig)
    password_reset: PasswordResetConfig = Field(default_factory=PasswordResetConfig)
    email_change: EmailChangeConfig = Field(default_factory=EmailChangeConfig)
    delete_account: DeleteAccountConfig = Field(default_factory=DeleteAccountConfig)
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    csrf: CsrfConfig = Field(default_factory=CsrfConfig)
    lockout: LockoutConfig = Field(default_factory=LockoutConfig)
    refresh_token: RefreshTokenConfig = Field(default_factory=RefreshTokenConfig)
    security_headers: SecurityHeadersConfig = Field(default_factory=SecurityHeadersConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    advanced: AdvancedConfig = Field(default_factory=AdvancedConfig)
    wire_format: WireFormat = WireFormat.SNAKE
