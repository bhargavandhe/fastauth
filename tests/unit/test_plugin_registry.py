from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import Request
from pydantic import SecretStr

from fastauth.database import custom
from fastauth.exceptions import ConfigError, InvalidCredentialsError
from fastauth.options import FastAuthOptions
from fastauth.plugins.base import EndpointSpec, Plugin, PluginRegistry
from fastauth.runtime.auth import FastAuth
from fastauth.storage.base import AuditLogStore
from fastauth.storage.memory import InMemoryAdapter


class HelloPlugin(Plugin):
    id = "hello-plugin"

    def endpoints(self) -> list[EndpointSpec]:
        return [
            EndpointSpec(
                method="GET",
                path="/hello-plugin/ping",
                name="hello_ping",
                tags=["HelloPlugin"],
                handler=None,
            )
        ]


class HelloAgain(Plugin):
    id = "hello-plugin"  # duplicate

    def endpoints(self) -> list[EndpointSpec]:
        return []


def test_registry_records_endpoints() -> None:
    registry = PluginRegistry([HelloPlugin()])
    assert "hello-plugin" in registry.by_id
    assert registry.all_endpoints()[0].path == "/hello-plugin/ping"


def test_registry_rejects_duplicate_ids() -> None:
    with pytest.raises(ValueError, match="duplicate plugin id"):
        PluginRegistry([HelloPlugin(), HelloAgain()])


def test_endpoint_spec_convenience_constructors() -> None:
    async def handler() -> dict[str, str]:
        return {"ok": "true"}

    spec = EndpointSpec.get(
        "/hello-plugin/ping",
        name="hello_ping",
        tags=("HelloPlugin",),
        handler=handler,
    )

    assert spec.method == "GET"
    assert spec.path == "/hello-plugin/ping"
    assert spec.tags == ["HelloPlugin"]
    assert spec.handler is handler


def test_plugin_base_stores_bound_context() -> None:
    plugin = HelloPlugin()
    context = object()

    plugin.bind(context)  # type: ignore[arg-type]

    assert plugin.require_context() is context


def test_plugin_base_requires_declared_capability() -> None:
    plugin = HelloPlugin()
    plugin.bind(SimpleNamespace(adapter=object()))  # type: ignore[arg-type]

    with pytest.raises(ConfigError, match="requires AuditLogStore"):
        plugin.require_capability(AuditLogStore)


async def test_plugin_base_requires_session_from_request() -> None:
    plugin = HelloPlugin()
    adapter = InMemoryAdapter()
    auth = FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("a" * 64),
            database=custom(adapter),
        ),
    )
    plugin.bind(auth.context)
    request = Request({"type": "http", "method": "GET", "path": "/", "headers": []})

    with pytest.raises(InvalidCredentialsError):
        await plugin.require_session(request)
