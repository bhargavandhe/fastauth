from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import SecretStr, ValidationError

from fastauth.domain.enums import DatabaseBackendKind, SessionStrategyKind
from fastauth.options import (
    AdvancedOptions,
    AppOptions,
    CookieOptions,
    CsrfOptions,
    CustomDatabaseOptions,
    DeleteAccountOptions,
    EmailChangeOptions,
    EmailOptions,
    EmailVerificationOptions,
    FastAuthOptions,
    LockoutOptions,
    MemoryDatabaseOptions,
    MongoDatabaseOptions,
    PasswordOptions,
    PasswordResetOptions,
    PostgresDatabaseOptions,
    RateLimitOptions,
    RefreshTokenOptions,
    SecurityHeadersOptions,
    SessionOptions,
)
from fastauth.storage.memory import InMemoryAdapter


def test_fastauth_options_requires_secret_key() -> None:
    with pytest.raises(ValidationError):
        FastAuthOptions()  # pyright: ignore[reportCallIssue]


def test_fastauth_options_requires_secretstr() -> None:
    with pytest.raises(ValidationError):
        FastAuthOptions(secret_key="a" * 64)  # pyright: ignore[reportArgumentType]


def test_fastauth_options_accepts_explicit_secret_key() -> None:
    options = FastAuthOptions(secret_key=SecretStr("a" * 64))
    assert isinstance(options.secret_key, SecretStr)
    assert "a" * 64 not in repr(options)


def test_fastauth_builds_reusable_credential_service_from_global_password_options() -> None:
    from fastauth import FastAuth
    from fastauth.exceptions import InvalidRequestError

    auth = FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("a" * 64),
            password=PasswordOptions(min_length=16, max_length=128),
        ),
    )

    assert auth.context.credential_service.validate_password(
        SecretStr("correct-horse-battery")
    ) == "correct-horse-battery"
    with pytest.raises(InvalidRequestError):
        auth.context.credential_service.validate_password(SecretStr("short-password"))


def test_fastauth_options_rejects_short_secret_key() -> None:
    with pytest.raises(ValidationError, match="secret_key must contain at least 32 bytes"):
        FastAuthOptions(secret_key=SecretStr("short"))


def test_cookie_samesite_none_requires_secure_cookie() -> None:
    with pytest.raises(ValidationError, match="SameSite=None requires secure cookies"):
        FastAuthOptions(
            secret_key=SecretStr("a" * 64),
            cookie=CookieOptions(secure=False, same_site="none"),
        )


def test_production_options_reject_memory_database() -> None:
    with pytest.raises(ValidationError, match="memory database is not allowed in production"):
        FastAuthOptions(
            secret_key=SecretStr("a" * 64),
            deployment="production",
            app=AppOptions.model_validate({"base_url": "https://api.example.com"}),
        )


def test_production_options_reject_http_base_url() -> None:
    with pytest.raises(ValidationError, match="production base_url must use HTTPS"):
        FastAuthOptions(
            secret_key=SecretStr("a" * 64),
            deployment="production",
            database=CustomDatabaseOptions(
                adapter=InMemoryAdapter(),
            ),
        )


def test_production_options_reject_insecure_cookies() -> None:
    with pytest.raises(ValidationError, match="production cookies must be secure"):
        FastAuthOptions(
            secret_key=SecretStr("a" * 64),
            deployment="production",
            database=CustomDatabaseOptions(
                adapter=InMemoryAdapter(),
            ),
            app=AppOptions.model_validate({"base_url": "https://api.example.com"}),
            cookie=CookieOptions(secure=False),
        )


def test_production_options_reject_automatic_postgres_migrations() -> None:
    with pytest.raises(ValidationError, match="production should use migration_mode='check'"):
        FastAuthOptions(
            secret_key=SecretStr("a" * 64),
            deployment="production",
            database=PostgresDatabaseOptions.model_validate(
                {
                    "url": "postgresql+asyncpg://user:pass@localhost:5432/app",
                    "migration_mode": "apply",
                }
            ),
            app=AppOptions.model_validate({"base_url": "https://api.example.com"}),
        )


def test_standard_options_do_not_allow_arbitrary_runtime_objects() -> None:
    assert AppOptions.model_config.get("arbitrary_types_allowed") is not True
    assert SessionOptions.model_config.get("arbitrary_types_allowed") is not True
    assert FastAuthOptions.model_config.get("arbitrary_types_allowed") is not True
    assert CustomDatabaseOptions.model_config.get("arbitrary_types_allowed") is True


def test_fastauth_options_are_immutable() -> None:
    options = FastAuthOptions(secret_key=SecretStr("b" * 64))

    with pytest.raises(ValidationError):
        options.session.expires_in = timedelta(hours=1)

    with pytest.raises(ValidationError):
        options.password.min_length = 20


def test_fastauth_options_accept_nested_overrides() -> None:
    options = FastAuthOptions(
        secret_key=SecretStr("c" * 64),
        session=SessionOptions(expires_in=timedelta(hours=1)),
        database=PostgresDatabaseOptions.model_validate(
            {
                "kind": "postgres",
                "url": "postgresql://user:pass@localhost/app",
                "table_prefix": "custom_",
                "table_suffix": "_auth",
            }
        ),
    )

    assert options.session.max_age_seconds == 3600
    assert options.database.kind == "postgres"
    assert options.database.table_prefix == "custom_"
    assert options.database.table_suffix == "_auth"


def test_database_options_are_discriminated() -> None:
    options = FastAuthOptions.model_validate(
        {
            "secret_key": SecretStr("d" * 64),
            "database": {
                "kind": "postgres",
                "url": "postgresql://user:pass@localhost/app",
            },
        }
    )

    assert isinstance(options.database, PostgresDatabaseOptions)
    assert options.database.backend_kind() is DatabaseBackendKind.POSTGRES


def test_mongo_database_options_model_collection_prefix_and_suffix() -> None:
    options = MongoDatabaseOptions(
        database=object(),
        collection_prefix="tenant_",
        collection_suffix="_auth",
    )

    assert options.collection_prefix == "tenant_"
    assert options.collection_suffix == "_auth"


def test_mongo_database_options_reject_invalid_collection_prefix() -> None:
    with pytest.raises(ValidationError):
        MongoDatabaseOptions(database=object(), collection_prefix="$tenant_")


def test_mongo_database_options_reject_invalid_collection_suffix() -> None:
    with pytest.raises(ValidationError):
        MongoDatabaseOptions(database=object(), collection_suffix="_bad\x00suffix")


def test_fastauth_options_accept_dict_via_model_validate() -> None:
    options = FastAuthOptions.model_validate(
        {
            "secret_key": SecretStr("e" * 64),
            "session": {"expires_in": timedelta(hours=2)},
        }
    )
    assert options.session.max_age_seconds == 7200


def test_fastauth_options_defaults_match_documented_values() -> None:
    options = FastAuthOptions(secret_key=SecretStr("f" * 64))

    assert str(options.app.base_url) == "http://localhost:8000/"
    assert options.app.base_path == "/auth"
    assert options.session.strategy is SessionStrategyKind.DATABASE
    assert options.session.max_age_seconds == 60 * 60 * 24 * 7
    assert options.cookie.name == "fastauth.session_token"
    assert options.cookie.same_site == "lax"
    assert options.cookie.secure is True
    assert options.password.argon2_time_cost == 3
    assert options.csrf.enabled is True
    assert options.rate_limit.window_seconds == 60
    assert options.rate_limit.max_requests == 100
    assert options.refresh_token.enabled is True
    assert options.refresh_token.max_age_seconds == 30 * 24 * 60 * 60
    assert options.security_headers.enabled is True


def test_session_options_do_not_expose_unused_rotation_toggle() -> None:
    assert "rotate_on_refresh" not in SessionOptions.model_fields


def test_option_sections_are_pydantic_models() -> None:
    for cls in (
        AppOptions,
        SessionOptions,
        CookieOptions,
        PasswordOptions,
        EmailOptions,
        EmailVerificationOptions,
        PasswordResetOptions,
        EmailChangeOptions,
        DeleteAccountOptions,
        RateLimitOptions,
        CsrfOptions,
        LockoutOptions,
        RefreshTokenOptions,
        SecurityHeadersOptions,
        MemoryDatabaseOptions,
        MongoDatabaseOptions,
        PostgresDatabaseOptions,
        AdvancedOptions,
    ):
        assert hasattr(cls, "model_dump"), f"{cls.__name__} must be a Pydantic model"
