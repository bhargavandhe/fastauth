from __future__ import annotations

import pytest
from pydantic import SecretStr

from fastauth import FastAuth, FastAuthOptions, email_password
from fastauth.database import custom, memory
from fastauth.domain.enums import DatabaseBackendKind
from fastauth.exceptions import ConfigError
from fastauth.options import AppOptions, CustomDatabaseOptions, MongoDatabaseOptions
from fastauth.storage.memory import InMemoryAdapter


def test_fastauth_defaults_to_in_memory_database_option() -> None:
    auth = FastAuth(FastAuthOptions(secret_key=SecretStr("a" * 64)))

    assert isinstance(auth.context.adapter, InMemoryAdapter)
    assert auth.options.database.kind == "memory"


def test_fastauth_accepts_memory_database_factory() -> None:
    auth = FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("a" * 64),
            database=memory(),
        ),
    )

    assert isinstance(auth.context.adapter, InMemoryAdapter)


def test_fastauth_accepts_custom_adapter_database_option() -> None:
    adapter = InMemoryAdapter()
    auth = FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("b" * 64),
            database=custom(adapter),
        ),
    )

    assert auth.context.adapter is adapter


def test_production_deployment_requires_non_console_email_sender() -> None:
    options = FastAuthOptions(
        secret_key=SecretStr("a" * 64),
        deployment="production",
        app=AppOptions.model_validate({"base_url": "https://api.example.com"}),
        database=CustomDatabaseOptions(
            adapter=InMemoryAdapter(),
            backend=DatabaseBackendKind.POSTGRES,
        ),
    )

    with pytest.raises(ConfigError):
        FastAuth(options, plugins=[email_password()])


def test_mongo_database_option_models_collection_affixes() -> None:
    database = object()
    options = FastAuthOptions(
        secret_key=SecretStr("b" * 64),
        database=MongoDatabaseOptions(
            database=database,
            collection_prefix="tenant_",
            collection_suffix="_auth",
        ),
    )

    assert options.database.kind == "mongo"
    assert options.database.collection_prefix == "tenant_"
