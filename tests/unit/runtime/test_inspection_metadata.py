from __future__ import annotations

from pydantic import BaseModel, SecretStr

from fastauth.database import memory
from fastauth.options import FastAuthOptions
from fastauth.plugins.base import EndpointSpec, Plugin
from fastauth.runtime.auth import FastAuth


class InspectRequest(BaseModel):
    value: str


class InspectQuery(BaseModel):
    verbose: bool = False


class InspectResponse(BaseModel):
    ok: bool


class MetadataPlugin(Plugin):
    id = "metadata-plugin"

    def endpoints(self) -> list[EndpointSpec]:
        async def ping() -> InspectResponse:
            return InspectResponse(ok=True)

        return [
            EndpointSpec.get(
                "/metadata/ping",
                name="metadata_ping",
                handler=ping,
                tags=("Metadata",),
                operation_id="metadataPing",
                request_model=InspectRequest,
                query_model=InspectQuery,
                response_model=InspectResponse,
                auth_required=True,
                server_only=True,
                csrf_policy="require",
                openapi_extra={"x-fastauth": {"feature": "metadata"}},
                client_namespace="metadata",
                deprecated=True,
                error_codes=("metadata_unavailable",),
            )
        ]


def test_auth_inspector_retains_unmounted_plugin_metadata() -> None:
    auth = FastAuth(
        FastAuthOptions(secret_key=SecretStr("m" * 64), database=memory()),
        plugins=[MetadataPlugin()],
    )

    inspection = auth.inspect()
    assert all(route.name != "metadata_ping" for route in inspection.routes)
    route = inspection.plugins[0].endpoints[0]

    assert route.path == "/metadata/ping"
    assert route.operation_id == "metadataPing"
    assert route.request_model_name == "InspectRequest"
    assert route.query_model_name == "InspectQuery"
    assert route.response_model_name == "InspectResponse"
    assert route.auth_required is True
    assert route.server_only is True
    assert route.csrf_policy == "require"
    assert route.openapi_extra == {"x-fastauth": {"feature": "metadata"}}
    assert route.client_namespace == "metadata"
    assert route.deprecated is True
    assert route.error_codes == ("metadata_unavailable",)
    assert route.model_dump(mode="json")["error_codes"] == ["metadata_unavailable"]
