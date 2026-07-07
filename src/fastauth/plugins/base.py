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


class EndpointSpec(BaseModel):
    """Describes a plugin-provided HTTP endpoint."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    method: HttpMethod
    path: str
    name: str
    tags: list[str] = Field(default_factory=list)
    handler: EndpointHandler = None
    request_model: type[BaseModel] | None = None
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
        request_model: type[BaseModel] | None = None,
        response_model: type[BaseModel] | None = None,
    ) -> EndpointSpec:
        return cls(
            method=method,
            path=path,
            name=name,
            tags=list(tags),
            handler=handler,
            request_model=request_model,
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
        request_model: type[BaseModel] | None = None,
        response_model: type[BaseModel] | None = None,
    ) -> EndpointSpec:
        return cls.route(
            "POST",
            path,
            name=name,
            tags=tags,
            handler=handler,
            request_model=request_model,
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
        request_model: type[BaseModel] | None = None,
        response_model: type[BaseModel] | None = None,
    ) -> EndpointSpec:
        return cls.route(
            "DELETE",
            path,
            name=name,
            tags=tags,
            handler=handler,
            request_model=request_model,
            response_model=response_model,
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
    endpoints: tuple[EndpointSpec, ...] = ()
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
        capabilities: dict[str, str] = {}
        routes: dict[tuple[str, str], str] = {}
        for plugin in self.plugins:
            if not plugin.id:
                raise ValueError(f"plugin {plugin.__class__.__name__} must set 'id'")
            if plugin.id in self.by_id:
                raise ValueError(f"duplicate plugin id: {plugin.id}")
            self.by_id[plugin.id] = plugin
            for capability in plugin.capabilities():
                if capability.id in capabilities:
                    raise ValueError(
                        "duplicate plugin capability "
                        f"{capability.id} from {capabilities[capability.id]} and {plugin.id}",
                    )
                capabilities[capability.id] = plugin.id
            for endpoint in plugin.endpoints():
                route_key = (endpoint.method, endpoint.path)
                if route_key in routes:
                    raise ValueError(
                        "duplicate plugin endpoint "
                        f"{endpoint.method} {endpoint.path} "
                        f"from {routes[route_key]} and {plugin.id}",
                    )
                routes[route_key] = plugin.id

    def all_endpoints(self) -> list[EndpointSpec]:
        return [spec for plugin in self.plugins for spec in plugin.endpoints()]

    def all_trusted_origins(self) -> list[str]:
        return [origin for plugin in self.plugins for origin in plugin.trusted_origins()]

    def all_rate_limit_rules(self) -> list[RateLimitRule]:
        return [rule for plugin in self.plugins for rule in plugin.rate_limit_rules()]

    def all_event_handlers(self) -> list[EventHandlerPair]:
        return [pair for plugin in self.plugins for pair in plugin.event_handlers()]

    def all_capabilities(self) -> list[Capability]:
        return [capability for plugin in self.plugins for capability in plugin.capabilities()]

    def all_server_api_namespaces(self) -> list[PluginApiNamespace]:
        namespaces: list[PluginApiNamespace] = []
        for plugin in self.plugins:
            api = plugin.server_api()
            if api is None:
                continue
            name = plugin.server_api_name()
            if name is None:
                raise ValueError(f"plugin {plugin.id} returned server_api without server_api_name")
            namespaces.append(PluginApiNamespace(plugin_id=plugin.id, name=name, api=api))
        return namespaces

    def plugin_info(self) -> list[PluginInfo]:
        info: list[PluginInfo] = []
        for plugin in self.plugins:
            server_api = plugin.server_api()
            info.append(
                PluginInfo(
                    id=plugin.id,
                    endpoints=tuple(plugin.endpoints()),
                    capabilities=tuple(plugin.capabilities()),
                    rate_limit_rules=tuple(plugin.rate_limit_rules()),
                    trusted_origins=tuple(plugin.trusted_origins()),
                    event_handler_count=len(plugin.event_handlers()),
                    server_api_name=plugin.server_api_name() if server_api is not None else None,
                ),
            )
        return info
