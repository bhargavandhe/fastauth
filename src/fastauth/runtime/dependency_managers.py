"""Public dependency and plugin manager namespaces."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING, Any

from fastauth.plugins.base import Plugin, PluginApiRegistry, PluginApiT

if TYPE_CHECKING:
    from fastauth.runtime.auth import FastAuth

__all__ = [
    "DependsManager",
    "PluginsManager",
]


class DependsManager:
    def __init__(self, auth: FastAuth) -> None:
        self._auth = auth

    def session(self) -> Callable[..., Any]:
        return self._auth.get_current_session

    def optional_session(self) -> Callable[..., Any]:
        return self._auth.get_optional_current_session

    def user(self) -> Callable[..., Any]:
        return self._auth.get_current_user

    def user_view(self) -> Callable[..., Any]:
        return self._auth.get_current_user_view

    def optional_user(self) -> Callable[..., Any]:
        return self._auth.get_optional_current_user

    def optional_user_view(self) -> Callable[..., Any]:
        return self._auth.get_optional_current_user_view


class PluginsManager:
    """Public plugin lookup surface.

    It exposes installed plugins for introspection while adding typed access
    to plugin-contributed server APIs.
    """

    def __init__(self, plugins: Sequence[Plugin], api_registry: PluginApiRegistry) -> None:
        self.items: tuple[Plugin, ...] = tuple(plugins)
        self.api_registry = api_registry

    def list(self) -> tuple[Plugin, ...]:
        return self.items

    def at(self, index: int) -> Plugin:
        return self.items[index]

    def count(self) -> int:
        return len(self.items)

    def try_get(self, api_type: type[PluginApiT]) -> PluginApiT | None:
        return self.api_registry.try_get(api_type)

    def get(self, api_type: type[PluginApiT]) -> PluginApiT:
        return self.api_registry.get(api_type)
