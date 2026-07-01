"""Public Pydantic options for the FastAuth runtime."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from contextlib import AbstractAsyncContextManager
from datetime import timedelta
from typing import Annotated, Literal, cast

from fastapi import FastAPI
from pydantic import (
    AnyHttpUrl,
    BaseModel,
    ConfigDict,
    Field,
    PostgresDsn,
    SecretStr,
    field_validator,
    model_validator,
)

from fastauth.config import (
    AdvancedConfig,
    AppConfig,
    CookieConfig,
    CsrfConfig,
    DatabaseConfig,
    DeleteAccountConfig,
    EmailChangeConfig,
    EmailConfig,
    EmailVerificationConfig,
    FastAuthConfig,
    LockoutConfig,
    MongoDatabaseConfig,
    PasswordConfig,
    PasswordResetConfig,
    PostgresDatabaseConfig,
    RateLimitConfig,
    RefreshTokenConfig,
    SecurityHeadersConfig,
    SessionConfig,
)
from fastauth.domain.enums import (
    DatabaseBackendKind,
    RateLimitStorageKind,
    SessionStrategyKind,
)
from fastauth.plugins.base import Plugin
from fastauth.storage.base import DatabaseAdapter

__all__ = [
    "AdvancedOptions",
    "AppOptions",
    "CookieOptions",
    "CsrfOptions",
    "CustomDatabase",
    "DatabaseOptions",
    "DeleteAccountOptions",
    "EmailChangeOptions",
    "EmailOptions",
    "EmailVerificationOptions",
    "FastAuthOptions",
    "LockoutOptions",
    "MemoryDatabase",
    "MongoDatabase",
    "PasswordOptions",
    "PasswordResetOptions",
    "PostgresDatabase",
    "RateLimitOptions",
    "RefreshTokenOptions",
    "SecurityHeadersOptions",
    "SessionOptions",
]


class OptionsModel(BaseModel):
    """Common base for user-facing option sections."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
        revalidate_instances="always",
        arbitrary_types_allowed=True,
    )


class OptionsSection(OptionsModel):
    """Common base for grouped user-facing options."""


class AppOptions(OptionsSection):
    name: str = Field(default="fastauth", min_length=1, max_length=100)
    base_url: AnyHttpUrl = "http://localhost:8000"  # type: ignore[assignment]
    base_path: str = Field(default="/auth", pattern=r"^/[a-zA-Z0-9/_-]*$")


class SessionOptions(OptionsSection):
    strategy: SessionStrategyKind = SessionStrategyKind.DATABASE
    expires_in: timedelta = Field(default=timedelta(days=7), gt=timedelta(0))
    idle_timeout: timedelta | None = Field(default=None, gt=timedelta(0))
    rotate_on_refresh: bool = True

    @model_validator(mode="after")
    def validate_idle_timeout(self) -> SessionOptions:
        if self.idle_timeout is not None and self.idle_timeout > self.expires_in:
            raise ValueError("idle_timeout cannot exceed expires_in")
        return self


class CookieOptions(OptionsSection):
    name: str = Field(default="fastauth.session_token", min_length=1, max_length=256)
    domain: str | None = None
    path: str = Field(default="/", pattern=r"^/")
    secure: bool = True
    http_only: bool = True
    same_site: Literal["lax", "strict", "none"] = "lax"


class PasswordOptions(OptionsSection):
    min_length: int = Field(default=8, ge=8, le=1024)
    max_length: int = Field(default=128, ge=8, le=4096)
    argon2_time_cost: int = Field(default=3, ge=1, le=64)
    argon2_memory_cost_kib: int = Field(default=64 * 1024, ge=8 * 1024, le=2 * 1024 * 1024)
    argon2_parallelism: int = Field(default=4, ge=1, le=64)

    @model_validator(mode="after")
    def validate_password_bounds(self) -> PasswordOptions:
        if self.max_length < self.min_length:
            raise ValueError("max_length cannot be less than min_length")
        return self


class EmailOptions(OptionsSection):
    from_address: str = Field(default="no-reply@localhost", min_length=3, max_length=320)
    from_name: str = Field(default="fastauth", min_length=1, max_length=100)
    verification_subject: str = Field(default="Verify your email", min_length=1, max_length=200)
    password_reset_subject: str = Field(default="Reset your password", min_length=1, max_length=200)
    template_directory: str | None = Field(default=None, min_length=1)


class EmailVerificationOptions(OptionsSection):
    expires_in: timedelta = Field(default=timedelta(minutes=15), gt=timedelta(0))
    require_verified_for_sign_in: bool = False
    base_verify_url: AnyHttpUrl = "http://localhost:8000/auth/verify-email"  # type: ignore[assignment]


class PasswordResetOptions(OptionsSection):
    expires_in: timedelta = Field(default=timedelta(minutes=30), gt=timedelta(0))
    base_reset_url: AnyHttpUrl = "http://localhost:8000/auth/reset-password"  # type: ignore[assignment]


class EmailChangeOptions(OptionsSection):
    expires_in: timedelta = Field(default=timedelta(minutes=15), gt=timedelta(0))
    base_confirm_url: AnyHttpUrl = "http://localhost:8000/auth/change-email/confirm"  # type: ignore[assignment]
    subject: str = Field(default="Confirm your new email address", min_length=1, max_length=200)


class DeleteAccountOptions(OptionsSection):
    expires_in: timedelta = Field(default=timedelta(minutes=15), gt=timedelta(0))
    base_confirm_url: AnyHttpUrl = "http://localhost:8000/auth/delete-account/confirm"  # type: ignore[assignment]
    subject: str = Field(default="Confirm account deletion", min_length=1, max_length=200)


class RateLimitOptions(OptionsSection):
    enabled: bool = True
    window: timedelta = Field(default=timedelta(seconds=60), gt=timedelta(0))
    max_requests: int = Field(default=100, ge=1, le=1_000_000)
    storage: RateLimitStorageKind = RateLimitStorageKind.MEMORY


class CsrfOptions(OptionsSection):
    enabled: bool = True
    trusted_origins: tuple[str, ...] = Field(default_factory=tuple)
    allow_relative_paths: bool = True


class LockoutOptions(OptionsSection):
    enabled: bool = True
    max_failures: int = Field(default=5, ge=1, le=100)
    window: timedelta = Field(default=timedelta(minutes=15), gt=timedelta(0))


class RefreshTokenOptions(OptionsSection):
    enabled: bool = True
    max_age: timedelta = Field(default=timedelta(days=30), gt=timedelta(0))
    absolute_max_age: timedelta | None = Field(default=None, gt=timedelta(0))


class SecurityHeadersOptions(OptionsSection):
    enabled: bool = True
    hsts: str | None = "max-age=31536000; includeSubDomains"
    x_frame_options: str | None = "DENY"
    x_content_type_options: str | None = "nosniff"
    referrer_policy: str | None = "strict-origin-when-cross-origin"
    permissions_policy: str | None = None
    content_security_policy: str | None = None


class AdvancedOptions(OptionsSection):
    ip_address_headers: tuple[str, ...] = Field(default_factory=lambda: ("x-forwarded-for",))
    ipv6_subnet: int = Field(default=64, ge=1, le=128)
    cookie_secure_prefix: bool = True


class MemoryDatabase(OptionsSection):
    kind: Literal["memory"] = "memory"

    def build_adapter(self) -> DatabaseAdapter:
        from fastauth.storage.memory import InMemoryAdapter

        return InMemoryAdapter()

    def backend_kind(self) -> DatabaseBackendKind:
        return DatabaseBackendKind.MEMORY


class MongoDatabase(OptionsSection):
    kind: Literal["mongo"] = "mongo"
    database: object
    collection_prefix: str = ""
    collection_suffix: str = ""

    @field_validator("collection_prefix", "collection_suffix")
    @classmethod
    def validate_collection_affix(cls, value: str) -> str:
        if "\x00" in value or "$" in value or value.startswith("system."):
            raise ValueError("MongoDB collection affixes must produce valid collection names")
        return value

    def build_adapter(self) -> DatabaseAdapter:
        from fastauth.storage.beanie import BeanieAdapter

        return BeanieAdapter(
            self.database,  # type: ignore[arg-type]
            collection_prefix=self.collection_prefix,
            collection_suffix=self.collection_suffix,
        )

    def backend_kind(self) -> DatabaseBackendKind:
        return DatabaseBackendKind.MONGO


class PostgresDatabase(OptionsSection):
    kind: Literal["postgres"] = "postgres"
    url: PostgresDsn
    table_prefix: str = "fastauth_"
    table_suffix: str = ""
    migration_mode: Literal["apply", "check", "disabled"] = "apply"

    def build_adapter(self) -> DatabaseAdapter:
        from fastauth.storage.postgres import PostgresAdapter

        return PostgresAdapter.from_url(
            str(self.url),
            table_prefix=self.table_prefix,
            table_suffix=self.table_suffix,
        )

    def backend_kind(self) -> DatabaseBackendKind:
        return DatabaseBackendKind.POSTGRES


class CustomDatabase(OptionsSection):
    kind: Literal["custom"] = "custom"
    adapter: DatabaseAdapter
    backend: DatabaseBackendKind = DatabaseBackendKind.MEMORY
    lifespan: Callable[[object], Callable[[FastAPI], AbstractAsyncContextManager[None]]] | None = (
        None
    )

    def build_adapter(self) -> DatabaseAdapter:
        return self.adapter

    def backend_kind(self) -> DatabaseBackendKind:
        return self.backend


DatabaseOptions = Annotated[
    MemoryDatabase | MongoDatabase | PostgresDatabase | CustomDatabase,
    Field(discriminator="kind"),
]

class FastAuthOptions(OptionsModel):
    """Single Pydantic options object accepted by ``fastauth(...)``."""

    secret_key: SecretStr
    secret_key_rotation: tuple[SecretStr, ...] = Field(default_factory=tuple)
    database: DatabaseOptions = Field(default_factory=MemoryDatabase)
    plugins: Sequence[Plugin] = Field(default_factory=tuple)
    app: AppOptions = Field(default_factory=lambda: AppOptions())
    session: SessionOptions = Field(default_factory=lambda: SessionOptions())
    cookie: CookieOptions = Field(default_factory=lambda: CookieOptions())
    password: PasswordOptions = Field(default_factory=lambda: PasswordOptions())
    email: EmailOptions = Field(default_factory=lambda: EmailOptions())
    email_verification: EmailVerificationOptions = Field(
        default_factory=lambda: EmailVerificationOptions(),
    )
    password_reset: PasswordResetOptions = Field(default_factory=lambda: PasswordResetOptions())
    email_change: EmailChangeOptions = Field(default_factory=lambda: EmailChangeOptions())
    delete_account: DeleteAccountOptions = Field(default_factory=lambda: DeleteAccountOptions())
    rate_limit: RateLimitOptions = Field(default_factory=lambda: RateLimitOptions())
    csrf: CsrfOptions = Field(default_factory=lambda: CsrfOptions())
    lockout: LockoutOptions = Field(default_factory=lambda: LockoutOptions())
    refresh_token: RefreshTokenOptions = Field(default_factory=lambda: RefreshTokenOptions())
    security_headers: SecurityHeadersOptions = Field(
        default_factory=lambda: SecurityHeadersOptions(),
    )
    advanced: AdvancedOptions = Field(default_factory=lambda: AdvancedOptions())

    @field_validator("secret_key", mode="before")
    @classmethod
    def validate_secret_key_is_explicit_secret(cls, value: object) -> object:
        if not isinstance(value, SecretStr):
            raise ValueError("secret_key must be a pydantic SecretStr")
        return value

    @field_validator("secret_key_rotation", mode="before")
    @classmethod
    def normalize_secret_key_rotation(cls, value: object) -> object:
        if isinstance(value, list):
            return tuple(cast(list[SecretStr], value))
        return value

    @field_validator("plugins", mode="before")
    @classmethod
    def normalize_plugins(cls, value: object) -> object:
        if isinstance(value, list):
            return tuple(cast(list[Plugin], value))
        return value

    def to_runtime_config(self) -> FastAuthConfig:
        """Convert public options into the runtime config consumed by internals."""
        if isinstance(self.database, MongoDatabase):
            database = DatabaseConfig(
                backend=self.database.backend_kind(),
                mongo=MongoDatabaseConfig(
                    collection_prefix=self.database.collection_prefix,
                    collection_suffix=self.database.collection_suffix,
                ),
            )
        elif isinstance(self.database, PostgresDatabase):
            database = DatabaseConfig(
                backend=self.database.backend_kind(),
                postgres=PostgresDatabaseConfig(
                    url=str(self.database.url),
                    table_prefix=self.database.table_prefix,
                    table_suffix=self.database.table_suffix,
                ),
            )
        else:
            database = DatabaseConfig(backend=self.database.backend_kind())
        return FastAuthConfig(
            secret_key=self.secret_key,
            secret_key_rotation=self.secret_key_rotation,
            app=AppConfig(
                name=self.app.name,
                base_url=str(self.app.base_url),
                base_path=self.app.base_path,
            ),
            session=SessionConfig(
                strategy=self.session.strategy,
                max_age_seconds=int(self.session.expires_in.total_seconds()),
                idle_timeout_seconds=(
                    int(self.session.idle_timeout.total_seconds())
                    if self.session.idle_timeout is not None
                    else None
                ),
                rotate_on_refresh=self.session.rotate_on_refresh,
            ),
            cookie=CookieConfig.model_validate(self.cookie.model_dump()),
            password=PasswordConfig(
                min_length=self.password.min_length,
                max_length=self.password.max_length,
                argon2_time_cost=self.password.argon2_time_cost,
                argon2_memory_cost_kib=self.password.argon2_memory_cost_kib,
                argon2_parallelism=self.password.argon2_parallelism,
            ),
            email=EmailConfig(
                from_address=self.email.from_address,
                from_name=self.email.from_name,
                verification_subject=self.email.verification_subject,
                password_reset_subject=self.email.password_reset_subject,
                template_directory=self.email.template_directory,
            ),
            email_verification=EmailVerificationConfig(
                token_ttl_minutes=max(
                    1,
                    int(self.email_verification.expires_in.total_seconds() // 60),
                ),
                require_verified_for_sign_in=self.email_verification.require_verified_for_sign_in,
                base_verify_url=str(self.email_verification.base_verify_url),
            ),
            password_reset=PasswordResetConfig(
                token_ttl_minutes=max(1, int(self.password_reset.expires_in.total_seconds() // 60)),
                base_reset_url=str(self.password_reset.base_reset_url),
            ),
            email_change=EmailChangeConfig(
                token_ttl_minutes=max(1, int(self.email_change.expires_in.total_seconds() // 60)),
                base_confirm_url=str(self.email_change.base_confirm_url),
                subject=self.email_change.subject,
            ),
            delete_account=DeleteAccountConfig(
                token_ttl_minutes=max(1, int(self.delete_account.expires_in.total_seconds() // 60)),
                base_confirm_url=str(self.delete_account.base_confirm_url),
                subject=self.delete_account.subject,
            ),
            rate_limit=RateLimitConfig(
                enabled=self.rate_limit.enabled,
                window_seconds=int(self.rate_limit.window.total_seconds()),
                max_requests=self.rate_limit.max_requests,
                storage=self.rate_limit.storage,
            ),
            csrf=CsrfConfig(
                enabled=self.csrf.enabled,
                trusted_origins=self.csrf.trusted_origins,
                allow_relative_paths=self.csrf.allow_relative_paths,
            ),
            lockout=LockoutConfig(
                enabled=self.lockout.enabled,
                max_failures=self.lockout.max_failures,
                window_seconds=int(self.lockout.window.total_seconds()),
            ),
            refresh_token=RefreshTokenConfig(
                enabled=self.refresh_token.enabled,
                max_age_seconds=int(self.refresh_token.max_age.total_seconds()),
                absolute_max_age_seconds=(
                    int(self.refresh_token.absolute_max_age.total_seconds())
                    if self.refresh_token.absolute_max_age is not None
                    else None
                ),
            ),
            security_headers=SecurityHeadersConfig.model_validate(
                self.security_headers.model_dump(),
            ),
            database=database,
            advanced=AdvancedConfig(
                ip_address_headers=self.advanced.ip_address_headers,
                ipv6_subnet=self.advanced.ipv6_subnet,
                cookie_secure_prefix=self.advanced.cookie_secure_prefix,
            ),
        )
