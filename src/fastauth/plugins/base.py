"""Plugin abstract base and the PluginRegistry."""

from __future__ import annotations

from abc import ABC
from collections.abc import Awaitable, Callable, Sequence
from datetime import timedelta
from typing import TYPE_CHECKING, Any, ClassVar, Literal, TypeVar, cast

from pydantic import BaseModel, ConfigDict, Field

from fastauth.runtime.capabilities import Capability

__all__ = [
    "Capability",
    "EndpointInfo",
    "EndpointSpec",
    "HttpMethod",
    "Plugin",
    "PluginApiNamespace",
    "PluginApiRegistry",
    "PluginInfo",
    "PluginOptions",
    "PluginRegistry",
    "RateLimitRule",
]

if TYPE_CHECKING:
    from fastapi import Request, Response

    from fastauth.domain.models import User
    from fastauth.runtime.context import AuthContext
    from fastauth.security.sessions import SessionContext


HttpMethod = Literal["GET", "POST", "PUT", "PATCH", "DELETE"]
EndpointHandler = Callable[..., Awaitable[Any]] | None
EventHandlerPair = tuple[type[BaseModel], Callable[[Any], Awaitable[None]]]
CapabilityT = TypeVar("CapabilityT")
PluginApiT = TypeVar("PluginApiT")


class EndpointSpec(BaseModel):
    """Describes a plugin-provided HTTP endpoint."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    method: HttpMethod
    path: str
    name: str
    tags: list[str] = Field(default_factory=list)
    handler: EndpointHandler = None
    response_model: type[BaseModel] | None = None

    @classmethod
    def route(
        cls,
        method: HttpMethod,
        path: str,
        *,
        name: str,
        handler: EndpointHandler,
        tags: Sequence[str] = (),
        response_model: type[BaseModel] | None = None,
    ) -> EndpointSpec:
        return cls(
            method=method,
            path=path,
            name=name,
            tags=list(tags),
            handler=handler,
            response_model=response_model,
        )

    @classmethod
    def get(
        cls,
        path: str,
        *,
        name: str,
        handler: EndpointHandler,
        tags: Sequence[str] = (),
        response_model: type[BaseModel] | None = None,
    ) -> EndpointSpec:
        return cls.route(
            "GET",
            path,
            name=name,
            tags=tags,
            handler=handler,
            response_model=response_model,
        )

    @classmethod
    def post(
        cls,
        path: str,
        *,
        name: str,
        handler: EndpointHandler,
        tags: Sequence[str] = (),
        response_model: type[BaseModel] | None = None,
    ) -> EndpointSpec:
        return cls.route(
            "POST",
            path,
            name=name,
            tags=tags,
            handler=handler,
            response_model=response_model,
        )

    @classmethod
    def delete(
        cls,
        path: str,
        *,
        name: str,
        handler: EndpointHandler,
        tags: Sequence[str] = (),
        response_model: type[BaseModel] | None = None,
    ) -> EndpointSpec:
        return cls.route(
            "DELETE",
            path,
            name=name,
            tags=tags,
            handler=handler,
            response_model=response_model,
        )


class EndpointInfo(BaseModel):
    """Serializable public metadata for a registered HTTP endpoint."""

    model_config = ConfigDict(frozen=True)

    method: HttpMethod
    path: str
    name: str
    tags: tuple[str, ...] = ()
    request_model_name: str | None = None
    response_model_name: str | None = None

    @classmethod
    def from_spec(cls, spec: EndpointSpec) -> EndpointInfo:
        response_model_name = (
            spec.response_model.__name__ if spec.response_model is not None else None
        )
        return cls(
            method=spec.method,
            path=spec.path,
            name=spec.name,
            tags=tuple(spec.tags),
            request_model_name=None,
            response_model_name=response_model_name,
        )


class RateLimitRule(BaseModel):
    """Declarative rate-limit rule for a plugin endpoint."""

    path: str
    window: timedelta
    max_requests: int


class PluginInfo(BaseModel):
    """Public metadata describing a plugin's runtime contribution."""

    model_config = ConfigDict(frozen=True)

    id: str
    endpoints: tuple[EndpointInfo, ...] = ()
    capabilities: tuple[Capability, ...] = ()
    rate_limit_rules: tuple[RateLimitRule, ...] = ()
    trusted_origins: tuple[str, ...] = ()
    event_handler_count: int = 0
    server_api_name: str | None = None


class PluginApiNamespace(BaseModel):
    """A plugin-contributed public server API namespace."""

    model_config = ConfigDict(arbitrary_types_allowed=True, frozen=True)

    plugin_id: str
    name: str
    api: Any


class PluginApiRegistry:
    """Lookup surface for plugin-contributed server API namespaces."""

    def __init__(self, namespaces: Sequence[PluginApiNamespace]) -> None:
        self.items: tuple[PluginApiNamespace, ...] = tuple(namespaces)
        self.by_name: dict[str, Any] = {}
        self.by_plugin_id: dict[str, Any] = {}
        for namespace in namespaces:
            if namespace.name in self.by_name:
                raise ValueError(f"duplicate plugin server API name: {namespace.name}")
            if namespace.plugin_id in self.by_plugin_id:
                raise ValueError(f"duplicate plugin server API plugin id: {namespace.plugin_id}")
            self.by_name[namespace.name] = namespace.api
            self.by_plugin_id[namespace.plugin_id] = namespace.api

    def try_get(self, api_type: type[PluginApiT]) -> PluginApiT | None:
        for namespace in self.items:
            if isinstance(namespace.api, api_type):
                return namespace.api
        return None

    def get(self, api_type: type[PluginApiT]) -> PluginApiT:
        from fastauth.exceptions import FeatureNotEnabledError

        api = self.try_get(api_type)
        if api is None:
            raise FeatureNotEnabledError(feature=api_type.__name__)
        return api


class PluginOptions(BaseModel):
    """Common immutable base for first-party plugin configuration."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
        revalidate_instances="always",
    )


class Plugin(ABC):  # noqa: B024 -- hooks are intentionally optional; subclasses override what they need
    """Subclass to add features. Override only the hooks you need."""

    id: ClassVar[str] = ""

    def bind(self, context: AuthContext) -> None:
        self._context = context

    def require_context(self) -> AuthContext:
        context = getattr(self, "_context", None)
        if context is None:
            raise RuntimeError(f"{self.__class__.__name__} has not been bound to AuthContext")
        return cast("AuthContext", context)

    def require_capability(self, capability: type[CapabilityT]) -> CapabilityT:
        from fastauth.exceptions import ConfigError

        context = self.require_context()
        if not isinstance(context.adapter, capability):
            capability_name = getattr(capability, "__name__", repr(capability))
            plugin_name = self.id or self.__class__.__name__
            raise ConfigError(message=f"{plugin_name} requires {capability_name}")
        return cast(CapabilityT, context.adapter)

    async def require_session(self, request: Request) -> SessionContext:
        from fastauth.exceptions import InvalidCredentialsError
        from fastauth.web.fastapi import extract_session_token

        context = self.require_context()
        token = extract_session_token(request, context)
        if token is None:
            raise InvalidCredentialsError()
        session = await context.session_strategy.read(token)
        if session is None:
            raise InvalidCredentialsError()
        return session

    def endpoints(self) -> Sequence[EndpointSpec]:
        return []

    def event_handlers(self) -> Sequence[EventHandlerPair]:
        return []

    def capabilities(self) -> Sequence[Capability]:
        return []

    def server_api_name(self) -> str | None:
        return None

    def server_api(self) -> object | None:
        return None

    def trusted_origins(self) -> Sequence[str]:
        return []

    def rate_limit_rules(self) -> Sequence[RateLimitRule]:
        return []

    async def extend_session_response(self, user: User, response: Response) -> None:
        return None

    async def lifespan_startup(self) -> None:
        return None

    async def lifespan_shutdown(self) -> None:
        return None


class PluginRegistry:
    """Validates and aggregates a list of `Plugin` instances."""

    def __init__(self, plugins: Sequence[Plugin]) -> None:
        self.plugins = list(plugins)
        self.by_id: dict[str, Plugin] = {}
        self._endpoints_by_plugin_id: dict[str, tuple[EndpointSpec, ...]] = {}
        self._capabilities_by_plugin_id: dict[str, tuple[Capability, ...]] = {}
        self._trusted_origins_by_plugin_id: dict[str, tuple[str, ...]] = {}
        self._rate_limit_rules_by_plugin_id: dict[str, tuple[RateLimitRule, ...]] = {}
        self._event_handlers_by_plugin_id: dict[str, tuple[EventHandlerPair, ...]] = {}
        self._server_api_namespaces: tuple[PluginApiNamespace, ...] = ()
        capabilities: dict[str, str] = {}
        routes: dict[tuple[str, str], str] = {}
        server_api_namespaces: list[PluginApiNamespace] = []
        for plugin in self.plugins:
            if not plugin.id:
                raise ValueError(f"plugin {plugin.__class__.__name__} must set 'id'")
            if plugin.id in self.by_id:
                raise ValueError(f"duplicate plugin id: {plugin.id}")
            self.by_id[plugin.id] = plugin

            plugin_capabilities = tuple(plugin.capabilities())
            plugin_endpoints = tuple(plugin.endpoints())
            self._capabilities_by_plugin_id[plugin.id] = plugin_capabilities
            self._endpoints_by_plugin_id[plugin.id] = plugin_endpoints
            self._trusted_origins_by_plugin_id[plugin.id] = tuple(plugin.trusted_origins())
            self._rate_limit_rules_by_plugin_id[plugin.id] = tuple(plugin.rate_limit_rules())
            self._event_handlers_by_plugin_id[plugin.id] = tuple(plugin.event_handlers())

            server_api = plugin.server_api()
            if server_api is not None:
                name = plugin.server_api_name()
                if name is None:
                    raise ValueError(
                        f"plugin {plugin.id} returned server_api without server_api_name",
                    )
                server_api_namespaces.append(
                    PluginApiNamespace(plugin_id=plugin.id, name=name, api=server_api),
                )

            for capability in plugin_capabilities:
                if capability.id in capabilities:
                    raise ValueError(
                        "duplicate plugin capability "
                        f"{capability.id} from {capabilities[capability.id]} and {plugin.id}",
                    )
                capabilities[capability.id] = plugin.id
            for endpoint in plugin_endpoints:
                route_key = (endpoint.method, endpoint.path)
                if route_key in routes:
                    raise ValueError(
                        "duplicate plugin endpoint "
                        f"{endpoint.method} {endpoint.path} "
                        f"from {routes[route_key]} and {plugin.id}",
                    )
                routes[route_key] = plugin.id
        self._server_api_namespaces = tuple(server_api_namespaces)

    def all_endpoints(self) -> list[EndpointSpec]:
        return [
            spec
            for plugin in self.plugins
            for spec in self._endpoints_by_plugin_id.get(plugin.id, ())
        ]

    def all_trusted_origins(self) -> list[str]:
        return [
            origin
            for plugin in self.plugins
            for origin in self._trusted_origins_by_plugin_id.get(plugin.id, ())
        ]

    def all_rate_limit_rules(self) -> list[RateLimitRule]:
        return [
            rule
            for plugin in self.plugins
            for rule in self._rate_limit_rules_by_plugin_id.get(plugin.id, ())
        ]

    def all_event_handlers(self) -> list[EventHandlerPair]:
        return [
            pair
            for plugin in self.plugins
            for pair in self._event_handlers_by_plugin_id.get(plugin.id, ())
        ]

    def all_capabilities(self) -> list[Capability]:
        return [
            capability
            for plugin in self.plugins
            for capability in self._capabilities_by_plugin_id.get(plugin.id, ())
        ]

    def all_server_api_namespaces(self) -> list[PluginApiNamespace]:
        return list(self._server_api_namespaces)

    def plugin_info(self) -> list[PluginInfo]:
        info: list[PluginInfo] = []
        for plugin in self.plugins:
            server_api_namespace = next(
                (
                    namespace
                    for namespace in self._server_api_namespaces
                    if namespace.plugin_id == plugin.id
                ),
                None,
            )
            info.append(
                PluginInfo(
                    id=plugin.id,
                    endpoints=tuple(
                        EndpointInfo.from_spec(spec)
                        for spec in self._endpoints_by_plugin_id.get(plugin.id, ())
                    ),
                    capabilities=self._capabilities_by_plugin_id.get(plugin.id, ()),
                    rate_limit_rules=self._rate_limit_rules_by_plugin_id.get(plugin.id, ()),
                    trusted_origins=self._trusted_origins_by_plugin_id.get(plugin.id, ()),
                    event_handler_count=len(self._event_handlers_by_plugin_id.get(plugin.id, ())),
                    server_api_name=(
                        server_api_namespace.name if server_api_namespace is not None else None
                    ),
                ),
            )
        return info
