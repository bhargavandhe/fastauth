"""Plugin abstract base and the PluginRegistry."""

from __future__ import annotations

from abc import ABC
from collections.abc import Awaitable, Callable, Sequence
from typing import TYPE_CHECKING, Any, ClassVar, Literal, TypeVar, cast

from pydantic import BaseModel, ConfigDict, Field

__all__ = ["EndpointSpec", "HttpMethod", "Plugin", "PluginRegistry", "RateLimitRule"]

if TYPE_CHECKING:
    from fastapi import Request

    from authkit.runtime.context import AuthContext
    from authkit.security.sessions import SessionContext


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
    window_seconds: int
    max_requests: int


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
        from authkit.exceptions import ConfigError

        context = self.require_context()
        if not isinstance(context.adapter, capability):
            capability_name = getattr(capability, "__name__", repr(capability))
            plugin_name = self.id or self.__class__.__name__
            raise ConfigError(message=f"{plugin_name} requires {capability_name}")
        return cast(CapabilityT, context.adapter)

    async def require_session(self, request: Request) -> SessionContext:
        from authkit.exceptions import InvalidCredentialsError
        from authkit.web.fastapi import extract_session_token

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

    def trusted_origins(self) -> Sequence[str]:
        return []

    def rate_limit_rules(self) -> Sequence[RateLimitRule]:
        return []

    async def lifespan_startup(self) -> None:
        return None

    async def lifespan_shutdown(self) -> None:
        return None


class PluginRegistry:
    """Validates and aggregates a list of `Plugin` instances."""

    def __init__(self, plugins: list[Plugin]) -> None:
        self.plugins = plugins
        self.by_id: dict[str, Plugin] = {}
        for plugin in plugins:
            if not plugin.id:
                raise ValueError(f"plugin {plugin.__class__.__name__} must set 'id'")
            if plugin.id in self.by_id:
                raise ValueError(f"duplicate plugin id: {plugin.id}")
            self.by_id[plugin.id] = plugin

    def all_endpoints(self) -> list[EndpointSpec]:
        return [spec for plugin in self.plugins for spec in plugin.endpoints()]

    def all_trusted_origins(self) -> list[str]:
        return [origin for plugin in self.plugins for origin in plugin.trusted_origins()]

    def all_rate_limit_rules(self) -> list[RateLimitRule]:
        return [rule for plugin in self.plugins for rule in plugin.rate_limit_rules()]

    def all_event_handlers(self) -> list[EventHandlerPair]:
        return [pair for plugin in self.plugins for pair in plugin.event_handlers()]
