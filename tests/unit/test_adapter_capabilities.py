from __future__ import annotations

import pytest
from pydantic import SecretStr

from fastauth.database import custom
from fastauth.domain.enums import RateLimitStorageKind
from fastauth.exceptions import AdapterFeatureUnsupportedError, ConfigError
from fastauth.options import FastAuthOptions, RateLimitOptions
from fastauth.plugins.api_key import ApiKeyPlugin
from fastauth.plugins.audit_logs import AuditLogsPlugin
from fastauth.plugins.base import Plugin
from fastauth.plugins.jwt import JwtPlugin
from fastauth.runtime.auth import FastAuth
from fastauth.storage.base import ApiKeyStore, AuditLogStore, BaseDatabaseAdapter, JwksKeyStore


def options(
    adapter: BaseDatabaseAdapter,
    *,
    plugins: list[Plugin] | None = None,
    rate_limit: RateLimitOptions | None = None,
) -> FastAuthOptions:
    plugin_list: list[Plugin] = plugins or []
    return FastAuthOptions(
        secret_key=SecretStr("x" * 64),
        database=custom(adapter),
        plugins=plugin_list,
        rate_limit=rate_limit or RateLimitOptions(),
    )


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
        FastAuth(options(BaseDatabaseAdapter(), plugins=[plugin]))


def test_database_rate_limit_storage_requires_matching_adapter_capability() -> None:
    with pytest.raises(ConfigError, match="RateLimitStore"):
        FastAuth(
            options(
                BaseDatabaseAdapter(),
                rate_limit=RateLimitOptions(storage=RateLimitStorageKind.DATABASE),
            ),
        )
