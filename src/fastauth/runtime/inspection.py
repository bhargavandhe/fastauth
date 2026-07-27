"""Runtime inspection DTOs and helpers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, JsonValue

from fastauth.plugins.base import EndpointInfo, PluginInfo
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
    operation_id: str | None = None
    request_model_name: str | None = None
    query_model_name: str | None = None
    response_model_name: str | None = None
    auth_required: bool = False
    server_only: bool = False
    csrf_policy: str | None = None
    openapi_extra: dict[str, JsonValue] | None = None
    client_namespace: str | None = None
    deprecated: bool = False
    error_codes: tuple[str, ...] = ()


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

    def plugin_endpoint_info_by_route(self) -> dict[tuple[str, str, str], EndpointInfo]:
        endpoint_info_by_route: dict[tuple[str, str, str], EndpointInfo] = {}
        for plugin in self.plugins():
            for endpoint in plugin.endpoints:
                endpoint_info_by_route[(endpoint.method, endpoint.path, endpoint.name)] = endpoint
        return endpoint_info_by_route

    def routes(self) -> list[RouteInfo]:
        routes: list[RouteInfo] = []
        plugin_endpoint_info = self.plugin_endpoint_info_by_route()
        for route in self._auth.router.routes:
            methods = getattr(route, "methods", None)
            path = getattr(route, "path", "")
            name = getattr(route, "name", "")
            tags = tuple(getattr(route, "tags", ()) or ())
            source = getattr(route, "fastauth_source", "core")
            for method in sorted(methods or ()):
                if method in {"HEAD", "OPTIONS"}:
                    continue
                endpoint_info = plugin_endpoint_info.get((method, path, name))
                routes.append(
                    RouteInfo(
                        method=method,
                        path=path,
                        name=name,
                        tags=tags,
                        source=source,
                        operation_id=(
                            endpoint_info.operation_id if endpoint_info is not None else None
                        ),
                        request_model_name=(
                            endpoint_info.request_model_name if endpoint_info is not None else None
                        ),
                        query_model_name=(
                            endpoint_info.query_model_name if endpoint_info is not None else None
                        ),
                        response_model_name=(
                            endpoint_info.response_model_name if endpoint_info is not None else None
                        ),
                        auth_required=(
                            endpoint_info.auth_required if endpoint_info is not None else False
                        ),
                        server_only=(
                            endpoint_info.server_only if endpoint_info is not None else False
                        ),
                        csrf_policy=(
                            endpoint_info.csrf_policy if endpoint_info is not None else None
                        ),
                        openapi_extra=(
                            endpoint_info.openapi_extra if endpoint_info is not None else None
                        ),
                        client_namespace=(
                            endpoint_info.client_namespace if endpoint_info is not None else None
                        ),
                        deprecated=endpoint_info.deprecated if endpoint_info is not None else False,
                        error_codes=endpoint_info.error_codes if endpoint_info is not None else (),
                    )
                )
        return routes
