from __future__ import annotations

import pytest
from pydantic import SecretStr

from fastauth import FastAuth, FastAuthConfig
from fastauth.config import DatabaseConfig, MongoDatabaseConfig
from fastauth.domain.enums import DatabaseBackendKind
from fastauth.exceptions import ConfigError
from fastauth.storage.memory import InMemoryAdapter


def test_fastauth_requires_explicit_adapter() -> None:
    with pytest.raises(ConfigError, match="requires an explicit adapter"):
        FastAuth(FastAuthConfig(secret_key=SecretStr("a" * 64)))


def test_fastauth_accepts_explicit_in_memory_adapter() -> None:
    auth = FastAuth(
        FastAuthConfig(secret_key=SecretStr("a" * 64)),
        adapter=InMemoryAdapter(),
    )

    assert isinstance(auth.context.adapter, InMemoryAdapter)


def test_fastauth_requires_adapter_for_persistent_backend() -> None:
    config = FastAuthConfig(
        secret_key=SecretStr("b" * 64),
        database=DatabaseConfig(
            backend=DatabaseBackendKind.MONGO,
            mongo=MongoDatabaseConfig(url="mongodb://localhost:27017"),
        ),
    )

    with pytest.raises(ConfigError, match="requires an explicit adapter"):
        FastAuth(config)
