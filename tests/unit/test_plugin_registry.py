from __future__ import annotations

import pytest

from authkit.plugins.base import EndpointSpec, Plugin, PluginRegistry


class HelloPlugin(Plugin):
    id = "hello-plugin"

    def endpoints(self) -> list[EndpointSpec]:
        return [
            EndpointSpec(
                method="GET",
                path="/hello-plugin/ping",
                name="hello_ping",
                tags=["HelloPlugin"],
                handler=None,
            )
        ]


class HelloAgain(Plugin):
    id = "hello-plugin"  # duplicate

    def endpoints(self) -> list[EndpointSpec]:
        return []


def test_registry_records_endpoints() -> None:
    registry = PluginRegistry([HelloPlugin()])
    assert "hello-plugin" in registry.by_id
    assert registry.all_endpoints()[0].path == "/hello-plugin/ping"


def test_registry_rejects_duplicate_ids() -> None:
    with pytest.raises(ValueError, match="duplicate plugin id"):
        PluginRegistry([HelloPlugin(), HelloAgain()])
