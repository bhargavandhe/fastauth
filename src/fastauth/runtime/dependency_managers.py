"""Public dependency and plugin manager namespaces."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING, Any

from fastapi import Request

from fastauth.api.responses import UserView, user_view
from fastauth.exceptions import FastAuthDependencyError
from fastauth.plugins.base import Plugin, PluginApiRegistry, PluginApiT
from fastauth.security.sessions import SessionContext
from fastauth.web.fastapi import extract_session_token

if TYPE_CHECKING:
    from fastauth.runtime.auth import FastAuth

__all__ = [
    "DependsManager",
    "PluginsManager",
]


class DependsManager:
    """FastAPI dependency factory namespace for a bound ``FastAuth`` instance."""

    def __init__(self, auth: FastAuth) -> None:
        self.auth = auth

    def session(self) -> Callable[..., Any]:
        return self.session_dependency

    def optional_session(self) -> Callable[..., Any]:
        return self.optional_session_dependency

    def user(self) -> Callable[..., Any]:
        return self.user_dependency

    def optional_user(self) -> Callable[..., Any]:
        return self.optional_user_dependency

    async def session_dependency(self, request: Request) -> SessionContext:
        """Return the active session or raise the canonical FastAuth 401."""
        session = await self.optional_session_dependency(request)
        if session is None:
            raise FastAuthDependencyError()
        return session

    async def optional_session_dependency(
        self,
        request: Request,
    ) -> SessionContext | None:
        """Return the active session, or ``None`` for anonymous requests."""
        token = extract_session_token(request, self.auth.context)
        if token is None:
            return None
        return await self.auth.context.session_strategy.read(token)

    async def user_dependency(self, request: Request) -> UserView:
        """Return the active user as the public ``UserView`` DTO."""
        session = await self.session_dependency(request)
        return user_view(session.user)

    async def optional_user_dependency(self, request: Request) -> UserView | None:
        """Return the active user as ``UserView``, or ``None`` for anonymous requests."""
        session = await self.optional_session_dependency(request)
        return user_view(session.user) if session is not None else None


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
