from __future__ import annotations

from pydantic import SecretStr

from fastauth import FastAuthOptions, fastauth
from fastauth.database import custom, memory
from fastauth.options import MongoDatabase
from fastauth.storage.memory import InMemoryAdapter


def test_fastauth_defaults_to_in_memory_database_option() -> None:
    auth = fastauth(FastAuthOptions(secret_key=SecretStr("a" * 64)))

    assert isinstance(auth.context.adapter, InMemoryAdapter)
    assert auth.options.database.kind == "memory"


def test_fastauth_accepts_memory_database_factory() -> None:
    auth = fastauth(
        FastAuthOptions(
            secret_key=SecretStr("a" * 64),
            database=memory(),
        ),
    )

    assert isinstance(auth.context.adapter, InMemoryAdapter)


def test_fastauth_accepts_custom_adapter_database_option() -> None:
    adapter = InMemoryAdapter()
    auth = fastauth(
        FastAuthOptions(
            secret_key=SecretStr("b" * 64),
            database=custom(adapter),
        ),
    )

    assert auth.context.adapter is adapter


def test_mongo_database_option_models_collection_affixes() -> None:
    database = object()
    options = FastAuthOptions(
        secret_key=SecretStr("b" * 64),
        database=MongoDatabase(
            database=database,
            collection_prefix="tenant_",
            collection_suffix="_auth",
        )
    )

    assert options.database.kind == "mongo"
    assert options.database.collection_prefix == "tenant_"
