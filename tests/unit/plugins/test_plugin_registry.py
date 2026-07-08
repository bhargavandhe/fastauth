from __future__ import annotations

from types import SimpleNamespace
from typing import cast

import pytest
from fastapi import Request
from pydantic import BaseModel, SecretStr

from fastauth.database import custom
from fastauth.exceptions import ConfigError, FeatureNotEnabledError, InvalidCredentialsError
from fastauth.options import FastAuthOptions
from fastauth.plugins.base import (
    Capability,
    EndpointHookSpec,
    EndpointInfo,
    EndpointSpec,
    Plugin,
    PluginErrorCode,
    PluginMiddlewareSpec,
    PluginRegistry,
    RequestHookSpec,
    ResponseHookSpec,
)
from fastauth.plugins.schema import FieldSpec, PluginSchema, TableSpec
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


class DuplicateRoutesWithinPlugin(Plugin):
    id = "duplicate-routes-within-plugin"

    def endpoints(self) -> list[EndpointSpec]:
        return [
            EndpointSpec.get(
                "/same",
                name="same_a",
                handler=None,
            ),
            EndpointSpec.get(
                "/same",
                name="same_b",
                handler=None,
            ),
        ]


class SamePathDifferentMethodsPlugin(Plugin):
    id = "same-path-different-methods"

    def endpoints(self) -> list[EndpointSpec]:
        return [
            EndpointSpec.get(
                "/same",
                name="same_get",
                handler=None,
            ),
            EndpointSpec.post(
                "/same",
                name="same_post",
                handler=None,
            ),
        ]


class OperationIdPlugin(Plugin):
    id = "operation-id-plugin"

    def endpoints(self) -> list[EndpointSpec]:
        return [
            EndpointSpec.get(
                "/operation-id-a",
                name="operation_id_a",
                handler=None,
                operation_id="sharedOperation",
            )
        ]


class OperationIdAgain(Plugin):
    id = "operation-id-again"

    def endpoints(self) -> list[EndpointSpec]:
        return [
            EndpointSpec.post(
                "/operation-id-b",
                name="operation_id_b",
                handler=None,
                operation_id="sharedOperation",
            )
        ]


class ClientNamespacePlugin(Plugin):
    id = "client-namespace-plugin"

    def endpoints(self) -> list[EndpointSpec]:
        return [
            EndpointSpec.get(
                "/client-namespace-a",
                name="client_namespace_a",
                handler=None,
                client_namespace="sharedClient",
            )
        ]


class ClientNamespaceAgain(Plugin):
    id = "client-namespace-again"

    def endpoints(self) -> list[EndpointSpec]:
        return [
            EndpointSpec.post(
                "/client-namespace-b",
                name="client_namespace_b",
                handler=None,
                client_namespace="sharedClient",
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


async def plugin_middleware_handler() -> None:
    return None


async def plugin_hook_handler() -> None:
    return None


class ExtendedContractPlugin(Plugin):
    id = "extended-contract-plugin"

    def error_codes(self) -> list[PluginErrorCode]:
        return [
            PluginErrorCode(
                code="EXTENDED_DISABLED",
                message="Extended plugin is disabled.",
            )
        ]

    def schemas(self) -> list[PluginSchema]:
        return [
            PluginSchema(
                plugin_id=self.id,
                tables=(
                    TableSpec(
                        name="extended_records",
                        fields=(FieldSpec(name="id", python_type="str"),),
                    ),
                ),
            )
        ]

    def middlewares(self) -> list[PluginMiddlewareSpec]:
        return [
            PluginMiddlewareSpec(
                path="/extended/**",
                handler=plugin_middleware_handler,
            )
        ]

    def request_hooks(self) -> list[RequestHookSpec]:
        return [
            RequestHookSpec(name="extended_request", handler=plugin_hook_handler)
        ]

    def response_hooks(self) -> list[ResponseHookSpec]:
        return [
            ResponseHookSpec(name="extended_response", handler=plugin_hook_handler)
        ]

    def endpoint_hooks(self) -> list[EndpointHookSpec]:
        return [
            EndpointHookSpec(
                phase="before",
                matcher_name="extended_endpoint",
                handler=plugin_hook_handler,
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


def test_registry_rejects_duplicate_plugin_endpoint_routes_within_plugin() -> None:
    with pytest.raises(
        ValueError,
        match="duplicate plugin endpoint GET /same within duplicate-routes-within-plugin",
    ):
        PluginRegistry([DuplicateRoutesWithinPlugin()])


def test_registry_allows_same_path_with_different_methods() -> None:
    registry = PluginRegistry([SamePathDifferentMethodsPlugin()])

    assert [(endpoint.method, endpoint.path) for endpoint in registry.all_endpoints()] == [
        ("GET", "/same"),
        ("POST", "/same"),
    ]


def test_registry_rejects_duplicate_plugin_endpoint_operation_ids() -> None:
    with pytest.raises(
        ValueError,
        match="duplicate plugin endpoint operation_id sharedOperation",
    ):
        PluginRegistry([OperationIdPlugin(), OperationIdAgain()])


def test_registry_rejects_duplicate_plugin_endpoint_client_namespaces() -> None:
    with pytest.raises(
        ValueError,
        match="duplicate plugin endpoint client_namespace sharedClient",
    ):
        PluginRegistry([ClientNamespacePlugin(), ClientNamespaceAgain()])


def test_registry_rejects_duplicate_plugin_capabilities() -> None:
    with pytest.raises(ValueError, match="duplicate plugin capability"):
        PluginRegistry([CapabilityPlugin(), CapabilityAgain()])


def test_registry_reports_plugin_info() -> None:
    registry = PluginRegistry([CapabilityPlugin()])

    info = registry.plugin_info()

    assert info[0].id == "capability-plugin"
    assert info[0].capabilities[0].id == "example-capability"
    assert all(isinstance(endpoint, EndpointInfo) for endpoint in info[0].endpoints)


def test_registry_reports_extended_plugin_contract_surfaces() -> None:
    registry = PluginRegistry([ExtendedContractPlugin()])

    info = registry.plugin_info()[0]

    assert registry.all_error_codes()[0].code == "EXTENDED_DISABLED"
    assert registry.all_schemas()[0].tables[0].name == "extended_records"
    assert registry.all_middlewares()[0].path == "/extended/**"
    assert registry.all_request_hooks()[0].name == "extended_request"
    assert registry.all_response_hooks()[0].name == "extended_response"
    assert registry.all_endpoint_hooks()[0].matcher_name == "extended_endpoint"
    assert info.error_codes[0].message == "Extended plugin is disabled."
    assert info.schemas[0].tables[0].fields[0].name == "id"
    assert info.middleware_count == 1
    assert info.request_hook_count == 1
    assert info.response_hook_count == 1
    assert info.endpoint_hook_count == 1


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


def test_endpoint_info_serializes_richer_endpoint_metadata() -> None:
    class PingRequest(BaseModel):
        message: str

    class PingQuery(BaseModel):
        include_debug: bool = False

    class PingResponse(BaseModel):
        ok: bool

    spec = EndpointSpec.post(
        "/hello-plugin/ping",
        name="hello_ping",
        handler=None,
        tags=("HelloPlugin",),
        operation_id="helloPing",
        request_model=PingRequest,
        query_model=PingQuery,
        response_model=PingResponse,
        auth_required=True,
        server_only=True,
        csrf_policy="require",
        openapi_extra={"x-fastauth": {"capability": "hello"}},
        client_namespace="hello",
        deprecated=True,
        error_codes=("invalid_hello", "hello_disabled"),
    )

    info = EndpointInfo.from_spec(spec)

    assert info == EndpointInfo(
        method="POST",
        path="/hello-plugin/ping",
        name="hello_ping",
        tags=("HelloPlugin",),
        operation_id="helloPing",
        request_model_name="PingRequest",
        query_model_name="PingQuery",
        response_model_name="PingResponse",
        auth_required=True,
        server_only=True,
        csrf_policy="require",
        openapi_extra={"x-fastauth": {"capability": "hello"}},
        client_namespace="hello",
        deprecated=True,
        error_codes=("invalid_hello", "hello_disabled"),
    )
    assert info.model_dump(mode="json")["request_model_name"] == "PingRequest"


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
            database=custom(adapter=InMemoryAdapter()),
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
            database=custom(adapter=InMemoryAdapter()),
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
                database=custom(adapter=InMemoryAdapter()),
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
    assert spec.operation_id is None
    assert spec.request_model is None
    assert spec.query_model is None
    assert spec.auth_required is False
    assert spec.server_only is False
    assert spec.csrf_policy is None
    assert spec.openapi_extra is None
    assert spec.client_namespace is None
    assert spec.deprecated is False
    assert spec.error_codes == ()


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
            database=custom(adapter=adapter),
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
                database=custom(adapter=InMemoryAdapter()),
            ),
            plugins=[CoreCollisionPlugin()],
        )
