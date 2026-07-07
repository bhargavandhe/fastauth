"""Public Pydantic options for the FastAuth runtime."""

from __future__ import annotations

from collections.abc import AsyncGenerator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from datetime import timedelta
from typing import Annotated, Literal, Protocol, cast

from fastapi import FastAPI
from pydantic import (
    AnyHttpUrl,
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyNetwork,
    PostgresDsn,
    SecretStr,
    field_validator,
    model_validator,
)

from fastauth.domain.enums import (
    DatabaseBackendKind,
    RateLimitStorageKind,
    SessionStrategyKind,
)
from fastauth.storage.base import DatabaseAdapter

__all__ = [
    "AdvancedOptions",
    "AppOptions",
    "CookieOptions",
    "CsrfOptions",
    "CustomDatabaseOptions",
    "CustomDatabaseRuntime",
    "DatabaseLifespanFactory",
    "DatabaseOptions",
    "DatabaseRuntime",
    "DeleteAccountOptions",
    "EmailChangeOptions",
    "EmailOptions",
    "EmailVerificationOptions",
    "FastAuthOptions",
    "LockoutOptions",
    "MemoryDatabaseOptions",
    "MemoryDatabaseRuntime",
    "MongoDatabaseOptions",
    "MongoDatabaseRuntime",
    "PasswordOptions",
    "PasswordResetOptions",
    "PostgresDatabaseOptions",
    "PostgresDatabaseRuntime",
    "ProxyOptions",
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

    @model_validator(mode="after")
    def validate_idle_timeout(self) -> SessionOptions:
        if self.idle_timeout is not None and self.idle_timeout > self.expires_in:
            raise ValueError("idle_timeout cannot exceed expires_in")
        return self

    @property
    def max_age_seconds(self) -> int:
        return int(self.expires_in.total_seconds())

    @property
    def idle_timeout_seconds(self) -> int | None:
        if self.idle_timeout is None:
            return None
        return int(self.idle_timeout.total_seconds())


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
    callback_path: str = Field(default="/auth/verify-email", pattern=r"^/")
    callback_url_override: AnyHttpUrl | None = None

    @property
    def token_ttl_minutes(self) -> int:
        return int(self.expires_in.total_seconds() // 60)


class PasswordResetOptions(OptionsSection):
    expires_in: timedelta = Field(default=timedelta(minutes=30), gt=timedelta(0))
    callback_path: str = Field(default="/auth/reset-password", pattern=r"^/")
    callback_url_override: AnyHttpUrl | None = None

    @property
    def token_ttl_minutes(self) -> int:
        return int(self.expires_in.total_seconds() // 60)


class EmailChangeOptions(OptionsSection):
    expires_in: timedelta = Field(default=timedelta(minutes=15), gt=timedelta(0))
    callback_path: str = Field(default="/auth/change-email/confirm", pattern=r"^/")
    callback_url_override: AnyHttpUrl | None = None
    subject: str = Field(default="Confirm your new email address", min_length=1, max_length=200)

    @property
    def token_ttl_minutes(self) -> int:
        return int(self.expires_in.total_seconds() // 60)


class DeleteAccountOptions(OptionsSection):
    expires_in: timedelta = Field(default=timedelta(minutes=15), gt=timedelta(0))
    callback_path: str = Field(default="/auth/delete-account/confirm", pattern=r"^/")
    callback_url_override: AnyHttpUrl | None = None
    subject: str = Field(default="Confirm account deletion", min_length=1, max_length=200)

    @property
    def token_ttl_minutes(self) -> int:
        return int(self.expires_in.total_seconds() // 60)


class RateLimitOptions(OptionsSection):
    enabled: bool = True
    window: timedelta = Field(default=timedelta(seconds=60), gt=timedelta(0))
    max_requests: int = Field(default=100, ge=1, le=1_000_000)
    storage: RateLimitStorageKind = RateLimitStorageKind.MEMORY

    @property
    def window_seconds(self) -> int:
        return int(self.window.total_seconds())


class CsrfOptions(OptionsSection):
    enabled: bool = True
    trusted_origins: tuple[str, ...] = Field(default_factory=tuple)
    require_origin: bool = True
    allow_relative_paths: bool = True


class LockoutOptions(OptionsSection):
    enabled: bool = True
    max_failures: int = Field(default=5, ge=1, le=100)
    window: timedelta = Field(default=timedelta(minutes=15), gt=timedelta(0))

    @property
    def window_seconds(self) -> int:
        return int(self.window.total_seconds())


class RefreshTokenOptions(OptionsSection):
    enabled: bool = True
    max_age: timedelta = Field(default=timedelta(days=30), gt=timedelta(0))
    absolute_max_age: timedelta | None = Field(default=None, gt=timedelta(0))

    @property
    def max_age_seconds(self) -> int:
        return int(self.max_age.total_seconds())

    @property
    def absolute_max_age_seconds(self) -> int | None:
        if self.absolute_max_age is None:
            return None
        return int(self.absolute_max_age.total_seconds())


class SecurityHeadersOptions(OptionsSection):
    enabled: bool = True
    hsts: str | None = "max-age=31536000; includeSubDomains"
    x_frame_options: str | None = "DENY"
    x_content_type_options: str | None = "nosniff"
    referrer_policy: str | None = "strict-origin-when-cross-origin"
    permissions_policy: str | None = None
    content_security_policy: str | None = None


class AdvancedOptions(OptionsSection):
    ipv6_subnet: int = Field(default=64, ge=1, le=128)
    cookie_secure_prefix: bool = True


class ProxyOptions(OptionsSection):
    trusted_proxies: tuple[IPvAnyNetwork, ...] = Field(default_factory=tuple)
    forwarded_header: str | None = Field(default=None, min_length=1, max_length=128)


DatabaseLifespanFactory = Callable[[object], Callable[[FastAPI], AbstractAsyncContextManager[None]]]


class DatabaseRuntime(Protocol):
    @property
    def adapter(self) -> DatabaseAdapter: ...

    def lifespan(self, auth: object, app: FastAPI) -> AbstractAsyncContextManager[None]: ...


class MemoryDatabaseRuntime:
    def __init__(self) -> None:
        from fastauth.storage.memory import InMemoryAdapter

        self.adapter = InMemoryAdapter()

    async def startup(self, auth: object, app: FastAPI) -> None:
        del auth, app

    async def shutdown(self) -> None:
        return None

    @asynccontextmanager
    async def lifespan(self, auth: object, app: FastAPI) -> AsyncGenerator[None, None]:
        try:
            await self.startup(auth, app)
            yield
        finally:
            await self.shutdown()


class MongoDatabaseRuntime:
    def __init__(
        self,
        database: object,
        *,
        collection_prefix: str,
        collection_suffix: str,
    ) -> None:
        from fastauth.storage.beanie import BeanieAdapter

        self.database = database
        self.collection_prefix = collection_prefix
        self.collection_suffix = collection_suffix
        self.adapter = BeanieAdapter(
            database,  # type: ignore[arg-type]
            collection_prefix=collection_prefix,
            collection_suffix=collection_suffix,
        )

    async def startup(self, auth: object, app: FastAPI) -> None:
        del auth, app
        from fastauth.storage.beanie.documents import init_beanie_documents

        await init_beanie_documents(
            self.database,  # type: ignore[arg-type]
            collection_prefix=self.collection_prefix,
            collection_suffix=self.collection_suffix,
        )

    async def shutdown(self) -> None:
        return None

    @asynccontextmanager
    async def lifespan(self, auth: object, app: FastAPI) -> AsyncGenerator[None, None]:
        try:
            await self.startup(auth, app)
            yield
        finally:
            await self.shutdown()


class PostgresDatabaseRuntime:
    def __init__(
        self,
        adapter: DatabaseAdapter,
        *,
        migration_mode: Literal["apply", "check", "disabled"],
    ) -> None:
        self.adapter = adapter
        self.migration_mode = migration_mode

    async def startup(self, auth: object, app: FastAPI) -> None:
        del auth, app
        if self.migration_mode == "apply":
            await self.adapter.apply_migrations()  # type: ignore[attr-defined]
        elif self.migration_mode == "check":
            await self.adapter.assert_schema_current()  # type: ignore[attr-defined]

    async def shutdown(self) -> None:
        engine = getattr(self.adapter, "engine", None)
        if engine is not None:
            await engine.dispose()

    @asynccontextmanager
    async def lifespan(self, auth: object, app: FastAPI) -> AsyncGenerator[None, None]:
        try:
            await self.startup(auth, app)
            yield
        finally:
            await self.shutdown()


class CustomDatabaseRuntime:
    def __init__(
        self,
        adapter: DatabaseAdapter,
        lifespan: DatabaseLifespanFactory | None,
    ) -> None:
        self.adapter = adapter
        self.lifespan_factory = lifespan
        self.context: AbstractAsyncContextManager[None] | None = None

    async def startup(self, auth: object, app: FastAPI) -> None:
        if self.lifespan_factory is None:
            return
        self.context = self.lifespan_factory(auth)(app)
        await self.context.__aenter__()

    async def shutdown(self) -> None:
        if self.context is None:
            return
        try:
            await self.context.__aexit__(None, None, None)
        finally:
            self.context = None

    @asynccontextmanager
    async def lifespan(self, auth: object, app: FastAPI) -> AsyncGenerator[None, None]:
        if self.lifespan_factory is None:
            yield
            return
        async with self.lifespan_factory(auth)(app):
            yield


class MemoryDatabaseOptions(OptionsSection):
    kind: Literal["memory"] = "memory"

    def build_adapter(self) -> DatabaseAdapter:
        return self.build_runtime().adapter

    def build_runtime(self) -> DatabaseRuntime:
        return MemoryDatabaseRuntime()

    def backend_kind(self) -> DatabaseBackendKind:
        return DatabaseBackendKind.MEMORY


class MongoDatabaseOptions(OptionsSection):
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
        return self.build_runtime().adapter

    def build_runtime(self) -> DatabaseRuntime:
        return MongoDatabaseRuntime(
            self.database,
            collection_prefix=self.collection_prefix,
            collection_suffix=self.collection_suffix,
        )

    def backend_kind(self) -> DatabaseBackendKind:
        return DatabaseBackendKind.MONGO


class PostgresDatabaseOptions(OptionsSection):
    kind: Literal["postgres"] = "postgres"
    url: PostgresDsn
    table_prefix: str = "fastauth_"
    table_suffix: str = ""
    migration_mode: Literal["apply", "check", "disabled"] = "apply"

    def build_adapter(self) -> DatabaseAdapter:
        return self.build_runtime().adapter

    def build_runtime(self) -> DatabaseRuntime:
        from fastauth.storage.postgres import PostgresAdapter

        return PostgresDatabaseRuntime(
            PostgresAdapter.from_url(
                str(self.url),
                table_prefix=self.table_prefix,
                table_suffix=self.table_suffix,
            ),
            migration_mode=self.migration_mode,
        )

    def backend_kind(self) -> DatabaseBackendKind:
        return DatabaseBackendKind.POSTGRES


class CustomDatabaseOptions(OptionsSection):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
        revalidate_instances="always",
        arbitrary_types_allowed=True,
    )

    kind: Literal["custom"] = "custom"
    adapter: DatabaseAdapter
    backend: DatabaseBackendKind = DatabaseBackendKind.MEMORY
    lifespan: DatabaseLifespanFactory | None = None

    def build_adapter(self) -> DatabaseAdapter:
        return self.adapter

    def build_runtime(self) -> DatabaseRuntime:
        return CustomDatabaseRuntime(self.adapter, self.lifespan)

    def backend_kind(self) -> DatabaseBackendKind:
        return self.backend


DatabaseOptions = Annotated[
    MemoryDatabaseOptions | MongoDatabaseOptions | PostgresDatabaseOptions | CustomDatabaseOptions,
    Field(discriminator="kind"),
]

class FastAuthOptions(OptionsModel):
    """Single Pydantic options object accepted by ``FastAuth``."""

    secret_key: SecretStr
    secret_key_rotation: tuple[SecretStr, ...] = Field(default_factory=tuple)
    deployment: Literal["development", "production"] = "development"
    database: DatabaseOptions = Field(default_factory=MemoryDatabaseOptions)
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
    proxy: ProxyOptions = Field(default_factory=lambda: ProxyOptions())

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

    @model_validator(mode="after")
    def validate_security_configuration(self) -> FastAuthOptions:
        secret_value = self.secret_key.get_secret_value()
        if len(secret_value.encode("utf-8")) < 32:
            raise ValueError("secret_key must contain at least 32 bytes")
        for index, secret in enumerate(self.secret_key_rotation):
            if len(secret.get_secret_value().encode("utf-8")) < 32:
                raise ValueError(
                    f"secret_key_rotation[{index}] must contain at least 32 bytes",
                )

        if self.cookie.same_site == "none" and not self.cookie.secure:
            raise ValueError("SameSite=None requires secure cookies")

        if self.deployment != "production":
            return self

        if self.database.backend_kind() is DatabaseBackendKind.MEMORY:
            raise ValueError("memory database is not allowed in production")

        if self.app.base_url.scheme != "https":
            raise ValueError("production base_url must use HTTPS")

        if not self.cookie.secure:
            raise ValueError("production cookies must be secure")

        callback_overrides = (
            self.email_verification.callback_url_override,
            self.password_reset.callback_url_override,
            self.email_change.callback_url_override,
            self.delete_account.callback_url_override,
        )
        if any(
            override is not None and override.scheme != "https"
            for override in callback_overrides
        ):
            raise ValueError("production callback_url_override values must use HTTPS")

        if (
            isinstance(self.database, PostgresDatabaseOptions)
            and self.database.migration_mode == "apply"
        ):
            raise ValueError("production should use migration_mode='check'")

        return self
