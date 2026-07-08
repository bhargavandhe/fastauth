"""Runtime inspection DTOs and helpers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict

from fastauth.plugins.base import PluginInfo
from fastauth.runtime.capabilities import Capability

if TYPE_CHECKING:
    from fastauth.runtime.auth import FastAuth

__all__ = [
    "AuthInspection",
    "AuthInspector",
    "RouteInfo",
]


class RouteInfo(BaseModel):
    """Serializable public route metadata."""

    model_config = ConfigDict(frozen=True)

    method: str
    path: str
    name: str
    tags: tuple[str, ...] = ()
    source: str = "core"


class AuthInspection(BaseModel):
    """Serializable runtime inspection payload."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    version: str
    database_backend: str
    session_strategy: str
    plugins: tuple[PluginInfo, ...]
    capabilities: tuple[Capability, ...]
    routes: tuple[RouteInfo, ...]
    production_warnings: tuple[str, ...] = ()


class AuthInspector:
    def __init__(self, auth: FastAuth) -> None:
        self._auth = auth

    def __call__(self) -> AuthInspection:
        from fastauth import __version__

        return AuthInspection(
            version=__version__,
            database_backend=self._auth.options.database.backend_kind().value,
            session_strategy=self._auth.options.session.strategy.value,
            plugins=tuple(self.plugins()),
            capabilities=tuple(self.capabilities()),
            routes=tuple(self.routes()),
        )

    def capabilities(self) -> list[Capability]:
        return self._auth.capabilities.list()

    def plugins(self) -> list[PluginInfo]:
        return self._auth.plugin_info()

    def routes(self) -> list[RouteInfo]:
        routes: list[RouteInfo] = []
        for route in self._auth.router.routes:
            methods = getattr(route, "methods", None)
            path = getattr(route, "path", "")
            name = getattr(route, "name", "")
            tags = tuple(getattr(route, "tags", ()) or ())
            source = getattr(route, "fastauth_source", "core")
            for method in sorted(methods or ()):
                if method in {"HEAD", "OPTIONS"}:
                    continue
                routes.append(
                    RouteInfo(
                        method=method,
                        path=path,
                        name=name,
                        tags=tags,
                        source=source,
                    )
                )
        return routes
