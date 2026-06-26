"""OpenApiPlugin: mounts a Scalar UI at ``/reference`` and serves OpenAPI 3.1 JSON.

Contributes two read-only HTTP endpoints to the fastauth router:

* ``GET {config.path}`` — returns an HTML page that loads the Scalar
  ``@scalar/api-reference`` web component from a CDN and points it at the
  OpenAPI JSON URL below.
* ``GET /openapi.json`` — returns the OpenAPI 3.1 schema for the calling
  FastAPI app, generated via ``fastapi.openapi.utils.get_openapi``.

The plugin also exposes ``render_schema(app)`` which is reused by
``AuthApi.generate_openapi_schema()`` to build the document offline against a
fresh ``FastAPI`` instance.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, ClassVar, cast

from fastapi import FastAPI, Request
from fastapi.openapi.utils import get_openapi
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, ConfigDict

from fastauth.plugins.base import EndpointSpec, Plugin
from fastauth.runtime.context import AuthContext

__all__ = ["SCALAR_TEMPLATE", "OpenApiConfig", "OpenApiPlugin"]


class OpenApiConfig(BaseModel):
    """Static configuration for ``OpenApiPlugin``."""

    model_config = ConfigDict(extra="forbid")
    path: str = "/reference"
    theme: str = "default"
    nonce: str | None = None
    title: str = "fastauth API"
    openapi_version: str = "3.1.0"


SCALAR_TEMPLATE = """<!doctype html>
<html>
  <head>
    <title>{title}</title>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
  </head>
  <body>
    <script id="api-reference" data-url="{openapi_url}"{nonce_attribute}></script>
    <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"{nonce_attribute}></script>
  </body>
</html>
"""


class OpenApiPlugin(Plugin):
    """Plugin contributing the Scalar UI page and the OpenAPI 3.1 JSON endpoint."""

    id: ClassVar[str] = "fastauth-openapi"

    def __init__(self, config: OpenApiConfig | None = None) -> None:
        self.config = config or OpenApiConfig()
        self.context: AuthContext | None = None
        self.cached_schema: dict[str, Any] | None = None

    def bind(self, context: AuthContext) -> None:
        """Attach the assembled ``AuthContext`` so handlers can read app config."""
        self.context = context

    def assert_bound(self) -> AuthContext:
        """Return the bound ``AuthContext`` or raise if ``bind`` was never invoked."""
        if self.context is None:
            raise RuntimeError("OpenApiPlugin is not bound to an AuthContext")
        return self.context

    def endpoints(self) -> Sequence[EndpointSpec]:
        return [
            EndpointSpec(
                method="GET",
                path=self.config.path,
                name="auth_reference",
                tags=["OpenApi"],
                handler=self.reference_handler,
            ),
            EndpointSpec(
                method="GET",
                path="/openapi.json",
                name="auth_openapi_json",
                tags=["OpenApi"],
                handler=self.schema_handler,
            ),
        ]

    def render_schema(self, app: FastAPI) -> dict[str, Any]:
        """Build (and cache) the OpenAPI 3.1 schema for ``app``'s routes.

        **Rule exception — returns a plain ``dict``:** OpenAPI 3.1 documents
        are an external specification with thousands of optional fields; no
        static Pydantic model can faithfully capture every valid document.
        ``fastapi.openapi.utils.get_openapi`` itself returns ``dict[str, Any]``
        for the same reason. One of the four documented carve-outs in
        CONTRIBUTING.md.
        """
        if self.cached_schema is not None:
            return self.cached_schema
        context = self.assert_bound()
        schema = get_openapi(
            title=self.config.title,
            version=context.config.app.name + " v1",
            openapi_version=self.config.openapi_version,
            description="fastauth endpoints",
            routes=app.routes,
        )
        self.cached_schema = schema
        return schema

    async def reference_handler(self) -> HTMLResponse:
        """``GET {config.path}`` — serve the Scalar HTML reference page."""
        context = self.assert_bound()
        nonce_attribute = f' nonce="{self.config.nonce}"' if self.config.nonce else ""
        openapi_url = context.config.app.base_path + "/openapi.json"
        html = SCALAR_TEMPLATE.format(
            title=self.config.title,
            openapi_url=openapi_url,
            nonce_attribute=nonce_attribute,
        )
        return HTMLResponse(html)

    async def schema_handler(self, request: Request) -> JSONResponse:
        """``GET /openapi.json`` — serve the OpenAPI 3.1 JSON schema."""
        # ``request.app`` is typed as ``Starlette`` upstream but is a ``FastAPI``
        # instance at runtime; cast to satisfy ``render_schema``'s signature.
        app = cast(FastAPI, request.app)
        schema = self.render_schema(app)
        return JSONResponse(schema)
