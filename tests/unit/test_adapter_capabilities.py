from __future__ import annotations

import pytest
from pydantic import SecretStr

from fastauth import FastAuth, FastAuthConfig
from fastauth.config import RateLimitConfig
from fastauth.domain.enums import RateLimitStorageKind
from fastauth.exceptions import AdapterFeatureUnsupportedError, ConfigError
from fastauth.plugins.api_key import ApiKeyPlugin
from fastauth.plugins.audit_logs import AuditLogsPlugin
from fastauth.plugins.base import Plugin
from fastauth.plugins.jwt import JwtPlugin
from fastauth.storage.base import ApiKeyStore, AuditLogStore, BaseDatabaseAdapter, JwksKeyStore


def config() -> FastAuthConfig:
    return FastAuthConfig(secret_key=SecretStr("x" * 64))


def test_base_database_adapter_is_core_only() -> None:
    adapter = BaseDatabaseAdapter()

    assert not isinstance(adapter, ApiKeyStore)
    assert not isinstance(adapter, JwksKeyStore)
    assert not isinstance(adapter, AuditLogStore)
    with pytest.raises(AdapterFeatureUnsupportedError, match="users"):
        raise adapter.unsupported("users")


@pytest.mark.parametrize(
    "plugin, message",
    [
        (ApiKeyPlugin(), "ApiKeyPlugin requires an adapter implementing ApiKeyStore"),
        (JwtPlugin(), "JwtPlugin requires an adapter implementing JwksKeyStore"),
        (AuditLogsPlugin(), "AuditLogsPlugin requires an adapter implementing AuditLogStore"),
    ],
)
def test_optional_plugins_require_matching_adapter_capability(
    plugin: Plugin,
    message: str,
) -> None:
    with pytest.raises(ConfigError, match=message):
        FastAuth(config(), adapter=BaseDatabaseAdapter(), plugins=[plugin])


def test_database_rate_limit_storage_requires_matching_adapter_capability() -> None:
    cfg = config()
    cfg.rate_limit = RateLimitConfig(storage=RateLimitStorageKind.DATABASE)

    with pytest.raises(ConfigError, match="RateLimitStore"):
        FastAuth(cfg, adapter=BaseDatabaseAdapter())
