from __future__ import annotations

import pytest
from pydantic import SecretStr

from authkit import AuthKit, AuthKitConfig
from authkit.config import DatabaseConfig, MongoDatabaseConfig
from authkit.domain.enums import DatabaseBackendKind
from authkit.exceptions import ConfigError
from authkit.storage.memory import InMemoryAdapter


def test_authkit_uses_in_memory_adapter_by_default() -> None:
    auth = AuthKit(AuthKitConfig(secret_key=SecretStr("a" * 64)))

    assert isinstance(auth.context.adapter, InMemoryAdapter)


def test_authkit_requires_adapter_for_persistent_backend() -> None:
    config = AuthKitConfig(
        secret_key=SecretStr("b" * 64),
        database=DatabaseConfig(
            backend=DatabaseBackendKind.MONGO,
            mongo=MongoDatabaseConfig(url="mongodb://localhost:27017"),
        ),
    )

    with pytest.raises(ConfigError, match="requires an explicit adapter"):
        AuthKit(config)
