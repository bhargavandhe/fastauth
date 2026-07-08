from __future__ import annotations

from types import SimpleNamespace
from typing import cast

import pytest
from fastapi import Request
from pydantic import SecretStr

from fastauth.database import custom
from fastauth.exceptions import ConfigError, FeatureNotEnabledError, InvalidCredentialsError
from fastauth.options import FastAuthOptions
from fastauth.plugins.base import Capability, EndpointInfo, EndpointSpec, Plugin, PluginRegistry
from fastauth.runtime.auth import FastAuth
from fastauth.runtime.context import AuthContext
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


class CollisionPlugin(Plugin):
    id = "collision-plugin"

    def endpoints(self) -> list[EndpointSpec]:
        return [
            EndpointSpec.get(
                "/same",
                name="same_a",
                handler=None,
            )
        ]


class CollisionAgain(Plugin):
    id = "collision-again"

    def endpoints(self) -> list[EndpointSpec]:
        return [
            EndpointSpec.get(
                "/same",
                name="same_b",
                handler=None,
            )
        ]


class CoreCollisionPlugin(Plugin):
    id = "core-collision"

    def endpoints(self) -> list[EndpointSpec]:
        async def handler() -> dict[str, bool]:
            return {"ok": True}

        return [
            EndpointSpec.post(
                "/sign-out",
                name="colliding_sign_out",
                handler=handler,
            )
        ]


class CapabilityPlugin(Plugin):
    id = "capability-plugin"

    def capabilities(self) -> list[Capability]:
        return [
            Capability(
                id="example-capability",
                description="Example capability.",
                plugin_id=self.id,
            )
        ]


class CapabilityAgain(Plugin):
    id = "capability-again"

    def capabilities(self) -> list[Capability]:
        return [
            Capability(
                id="example-capability",
                description="Duplicate capability.",
                plugin_id=self.id,
            )
        ]


class HelloPluginApi:
    async def ping(self) -> str:
        return "pong"


class ContextAwarePluginApi:
    def __init__(self, plugin: Plugin) -> None:
        self.context = plugin.require_context()


class ServerApiPlugin(Plugin):
    id = "server-api-plugin"

    def server_api_name(self) -> str:
        return "hello"

    def server_api(self) -> HelloPluginApi:
        return HelloPluginApi()


class ServerApiNameAgain(Plugin):
    id = "server-api-name-again"

    def server_api_name(self) -> str:
        return "hello"

    def server_api(self) -> HelloPluginApi:
        return HelloPluginApi()


class MissingServerApiNamePlugin(Plugin):
    id = "missing-server-api-name"

    def server_api(self) -> HelloPluginApi:
        return HelloPluginApi()


class ContextAwareServerApiPlugin(Plugin):
    id = "context-aware-server-api-plugin"

    def server_api_name(self) -> str:
        return "context_aware"

    def server_api(self) -> ContextAwarePluginApi:
        return ContextAwarePluginApi(self)


def test_registry_records_endpoints() -> None:
    registry = PluginRegistry([HelloPlugin()])
    assert "hello-plugin" in registry.by_id
    assert registry.all_endpoints()[0].path == "/hello-plugin/ping"


def test_registry_rejects_duplicate_ids() -> None:
    with pytest.raises(ValueError, match="duplicate plugin id"):
        PluginRegistry([HelloPlugin(), HelloAgain()])


def test_registry_rejects_duplicate_plugin_endpoint_routes() -> None:
    with pytest.raises(ValueError, match="duplicate plugin endpoint"):
        PluginRegistry([CollisionPlugin(), CollisionAgain()])


def test_registry_rejects_duplicate_plugin_capabilities() -> None:
    with pytest.raises(ValueError, match="duplicate plugin capability"):
        PluginRegistry([CapabilityPlugin(), CapabilityAgain()])


def test_registry_reports_plugin_info() -> None:
    registry = PluginRegistry([CapabilityPlugin()])

    info = registry.plugin_info()

    assert info[0].id == "capability-plugin"
    assert info[0].capabilities[0].id == "example-capability"
    assert all(isinstance(endpoint, EndpointInfo) for endpoint in info[0].endpoints)


def test_registry_reports_metadata_only_plugin_endpoints() -> None:
    registry = PluginRegistry([HelloPlugin()])

    info = registry.plugin_info()

    assert info[0].endpoints[0] == EndpointInfo(
        method="GET",
        path="/hello-plugin/ping",
        name="hello_ping",
        tags=("HelloPlugin",),
        request_model_name=None,
        response_model_name=None,
    )
    assert info[0].model_dump(mode="json")["endpoints"][0]["path"] == "/hello-plugin/ping"
    assert "handler" not in info[0].model_dump(mode="json")["endpoints"][0]


def test_registry_snapshots_plugin_surfaces() -> None:
    class DynamicPlugin(Plugin):
        id = "dynamic-plugin"

        def __init__(self) -> None:
            self.path = "/initial"

        def endpoints(self) -> list[EndpointSpec]:
            return [EndpointSpec.get(self.path, name="dynamic", handler=None)]

        def capabilities(self) -> list[Capability]:
            return [Capability(id=f"dynamic{self.path}", description="Dynamic")]

    plugin = DynamicPlugin()
    registry = PluginRegistry([plugin])

    plugin.path = "/changed"

    assert registry.all_endpoints()[0].path == "/initial"
    assert registry.all_capabilities()[0].id == "dynamic/initial"
    assert registry.plugin_info()[0].endpoints[0].path == "/initial"


def test_registry_reports_plugin_server_api_namespace() -> None:
    registry = PluginRegistry([ServerApiPlugin()])
    registry.bind_plugins(cast(AuthContext, SimpleNamespace()))

    namespaces = registry.all_server_api_namespaces()
    info = registry.plugin_info()

    assert namespaces[0].name == "hello"
    assert namespaces[0].plugin_id == "server-api-plugin"
    assert info[0].server_api_name == "hello"


def test_registry_rejects_missing_server_api_name() -> None:
    registry = PluginRegistry([MissingServerApiNamePlugin()])

    with pytest.raises(ValueError, match="server_api_name"):
        registry.bind_plugins(cast(AuthContext, SimpleNamespace()))


def test_registry_snapshots_plugin_server_api_after_binding() -> None:
    context = cast(AuthContext, SimpleNamespace(marker="bound"))
    registry = PluginRegistry([ContextAwareServerApiPlugin()])

    registry.bind_plugins(context)

    namespace = registry.all_server_api_namespaces()[0]
    assert isinstance(namespace.api, ContextAwarePluginApi)
    assert namespace.api.context is context


def test_auth_api_exposes_plugin_server_api_namespace() -> None:
    auth = FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("a" * 64),
            database=custom(InMemoryAdapter()),
        ),
        plugins=[ServerApiPlugin()],
    )

    assert isinstance(auth.api.plugins.by_name["hello"], HelloPluginApi)
    assert isinstance(auth.api.plugins.by_plugin_id["server-api-plugin"], HelloPluginApi)
    assert isinstance(auth.api.plugins.get(HelloPluginApi), HelloPluginApi)
    assert isinstance(auth.plugins.get(HelloPluginApi), HelloPluginApi)
    assert auth.plugins.try_get(HelloPluginApi) is not None


def test_typed_plugin_api_lookup_rejects_missing_api() -> None:
    auth = FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("a" * 64),
            database=custom(InMemoryAdapter()),
        ),
    )

    assert auth.plugins.try_get(HelloPluginApi) is None
    with pytest.raises(FeatureNotEnabledError, match="HelloPluginApi"):
        auth.plugins.get(HelloPluginApi)


def test_auth_api_rejects_duplicate_plugin_server_api_names() -> None:
    with pytest.raises(ValueError, match="duplicate plugin server API name"):
        FastAuth(
            FastAuthOptions(
                secret_key=SecretStr("a" * 64),
                database=custom(InMemoryAdapter()),
            ),
            plugins=[ServerApiPlugin(), ServerApiNameAgain()],
        )


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
    assert "request_model" not in EndpointSpec.model_fields


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


def test_fastauth_rejects_plugin_endpoint_that_collides_with_core_route() -> None:
    with pytest.raises(ValueError, match="collides with existing auth route"):
        FastAuth(
            FastAuthOptions(
                secret_key=SecretStr("a" * 64),
                database=custom(InMemoryAdapter()),
            ),
            plugins=[CoreCollisionPlugin()],
        )
