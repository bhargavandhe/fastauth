from __future__ import annotations

import pytest
from pydantic import SecretStr, ValidationError

from authkit.config import (
    AdvancedConfig,
    AppConfig,
    AuthKitConfig,
    CookieConfig,
    CsrfConfig,
    DatabaseConfig,
    DeleteAccountConfig,
    EmailChangeConfig,
    EmailConfig,
    EmailVerificationConfig,
    LockoutConfig,
    MemoryDatabaseConfig,
    MongoDatabaseConfig,
    PasswordConfig,
    PasswordResetConfig,
    PostgresDatabaseConfig,
    RateLimitConfig,
    RefreshTokenConfig,
    SecurityHeadersConfig,
    SessionConfig,
)
from authkit.domain.enums import DatabaseBackendKind, SessionStrategyKind


def test_authkitconfig_requires_secret_key() -> None:
    """A missing ``secret_key`` raises because config must be explicit.
    """
    with pytest.raises(ValidationError):
        AuthKitConfig()  # pyright: ignore[reportCallIssue]


def test_authkitconfig_does_not_read_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Process variables must not satisfy required config fields."""
    monkeypatch.setenv("SHOULD_BE_IGNORED_BY_AUTHKIT", "x" * 64)
    with pytest.raises(ValidationError):
        AuthKitConfig()  # pyright: ignore[reportCallIssue]


def test_authkitconfig_accepts_explicit_secret_key() -> None:
    config = AuthKitConfig(secret_key=SecretStr("a" * 64))
    assert isinstance(config.secret_key, SecretStr)
    assert "a" * 64 not in repr(config)


def test_authkitconfig_accepts_nested_overrides_via_kwargs() -> None:
    config = AuthKitConfig(
        secret_key=SecretStr("b" * 64),
        session=SessionConfig(max_age_seconds=3600),
        database=DatabaseConfig(
            backend=DatabaseBackendKind.MONGO,
            mongo=MongoDatabaseConfig(url="mongodb://example:27017"),
        ),
    )
    assert config.session.max_age_seconds == 3600
    assert config.database.backend is DatabaseBackendKind.MONGO
    assert config.database.mongo.url == "mongodb://example:27017"


def test_database_config_models_multiple_backends() -> None:
    default_config = DatabaseConfig()
    assert default_config.backend is DatabaseBackendKind.MEMORY

    config = DatabaseConfig(
        backend=DatabaseBackendKind.POSTGRES,
        postgres=PostgresDatabaseConfig(
            url="postgresql+asyncpg://user:pass@localhost/app",
            table_prefix="custom_",
        ),
    )

    assert config.backend is DatabaseBackendKind.POSTGRES
    assert config.postgres.url == "postgresql+asyncpg://user:pass@localhost/app"
    assert config.postgres.table_prefix == "custom_"


def test_authkitconfig_accepts_dict_via_model_validate() -> None:
    config = AuthKitConfig.model_validate(
        {"secret_key": "c" * 64, "session": {"max_age_seconds": 7200}}
    )
    assert config.session.max_age_seconds == 7200


def test_authkitconfig_defaults_match_documented_values() -> None:
    config = AuthKitConfig(secret_key=SecretStr("d" * 64))
    assert config.app.base_url == "http://localhost:8000"
    assert config.app.base_path == "/auth"
    assert config.session.strategy is SessionStrategyKind.DATABASE
    assert config.session.max_age_seconds == 60 * 60 * 24 * 7
    assert config.cookie.name == "authkit.session_token"
    assert config.cookie.same_site == "lax"
    assert config.cookie.secure is True
    assert config.password.argon2_time_cost == 3
    assert config.csrf.enabled is True
    assert config.rate_limit.window_seconds == 60
    assert config.rate_limit.max_requests == 100
    assert config.refresh_token.enabled is True
    assert config.refresh_token.max_age_seconds == 30 * 24 * 60 * 60
    assert config.security_headers.enabled is True


def test_sub_configs_are_pydantic_models() -> None:
    for cls in (
        AppConfig,
        SessionConfig,
        CookieConfig,
        PasswordConfig,
        EmailConfig,
        EmailVerificationConfig,
        PasswordResetConfig,
        EmailChangeConfig,
        DeleteAccountConfig,
        RateLimitConfig,
        CsrfConfig,
        LockoutConfig,
        RefreshTokenConfig,
        SecurityHeadersConfig,
        DatabaseConfig,
        MemoryDatabaseConfig,
        MongoDatabaseConfig,
        PostgresDatabaseConfig,
        AdvancedConfig,
    ):
        assert hasattr(cls, "model_dump"), f"{cls.__name__} must be a Pydantic model"


def test_no_authkitenvconfig_in_public_api() -> None:
    """Regression: the env-loader subclass was removed in a previous refactor
    that fully decoupled the framework from the process environment.
    """
    import authkit.config as config_mod

    assert not hasattr(config_mod, "AuthKitEnvConfig")
    assert "AuthKitEnvConfig" not in config_mod.__all__
