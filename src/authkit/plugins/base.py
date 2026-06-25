"""Plugin abstract base and the PluginRegistry."""

from __future__ import annotations

from abc import ABC
from collections.abc import Awaitable, Callable, Sequence
from typing import Any, ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field

__all__ = ["EndpointSpec", "HttpMethod", "Plugin", "PluginRegistry", "RateLimitRule"]


HttpMethod = Literal["GET", "POST", "PUT", "PATCH", "DELETE"]
EndpointHandler = Callable[..., Awaitable[Any]] | None
EventHandlerPair = tuple[type[BaseModel], Callable[[Any], Awaitable[None]]]


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


class RateLimitRule(BaseModel):
    """Declarative rate-limit rule for a plugin endpoint."""

    path: str
    window_seconds: int
    max_requests: int


class Plugin(ABC):  # noqa: B024 -- hooks are intentionally optional; subclasses override what they need
    """Subclass to add features. Override only the hooks you need."""

    id: ClassVar[str] = ""

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
