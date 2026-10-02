"""Public dependency and plugin manager namespaces."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import timedelta
from typing import TYPE_CHECKING, Any

from fastapi import Depends, Request
from fastapi.security import APIKeyHeader
from pydantic import SecretStr

from fastauth.api.responses import ApiKeyView, UserView, user_view
from fastauth.domain.value_objects import PermissionSet
from fastauth.exceptions import FastAuthDependencyError
from fastauth.plugins.api_key import ApiKeysApi
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

    def api_key(
        self, *, required_permissions: PermissionSet | None = None, header_name: str = "x-api-key"
    ) -> Callable[..., Any]:
        """Resolve an API key with required permissions; publish its actual header scheme."""
        api = self.auth.plugins.get(ApiKeysApi)
        # Hex preserves distinct header spellings using only valid OpenAPI component characters.
        scheme_name = (
            "ApiKey" if header_name == "x-api-key" else f"ApiKey_{header_name.encode().hex()}"
        )
        header = APIKeyHeader(name=header_name, scheme_name=scheme_name, auto_error=False)

        async def dependency(key: str | None = Depends(header)) -> ApiKeyView:
            if key is None:
                raise FastAuthDependencyError()
            result = await api.verify(SecretStr(key), permissions=required_permissions)
            if not result.valid or result.api_key is None:
                raise FastAuthDependencyError()
            return result.api_key

        return dependency

    def session(self) -> Callable[..., Any]:
        return self.session_dependency

    def optional_session(self) -> Callable[..., Any]:
        return self.optional_session_dependency

    def user(self) -> Callable[..., Any]:
        return self.user_dependency

    def verified_user(self) -> Callable[..., Any]:
        return self.verified_user_dependency

    def recent_session(self, *, max_age: timedelta = timedelta(minutes=5)) -> Callable[..., Any]:
        if max_age <= timedelta(0):
            raise ValueError("max_age must be positive")

        async def dependency(request: Request) -> SessionContext:
            session = await self.session_dependency(request)
            await self.auth.policy.authorize(
                session.user,
                action="session.recent",
                session=session.session,
                max_age=max_age,
            )
            return session

        return dependency

    async def verified_user_dependency(self, request: Request) -> UserView:
        session = await self.session_dependency(request)
        await self.auth.policy.authorize(
            session.user,
            action="session.verified",
            session=session.session,
            require_verified=True,
        )
        return user_view(session.user)

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
