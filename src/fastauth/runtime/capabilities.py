"""Runtime capability registry exposed by ``FastAuth``."""

from __future__ import annotations

from collections.abc import Iterable

from pydantic import ConfigDict, Field

from fastauth.domain.models import WireModel

__all__ = ["Capability", "CapabilityRegistry"]


class Capability(WireModel):
    """A runtime feature enabled by core configuration or an installed plugin."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    plugin_id: str | None = None


class CapabilityRegistry:
    """Immutable lookup surface for installed runtime capabilities."""

    def __init__(self, capabilities: Iterable[Capability]) -> None:
        collected = list(capabilities)
        self.items: tuple[Capability, ...] = tuple(collected)
        self.by_id: dict[str, Capability] = {capability.id: capability for capability in collected}
        if len(self.by_id) != len(collected):
            raise ValueError("duplicate capability id")

    def has(self, capability_id: str) -> bool:
        return capability_id in self.by_id

    def require(self, capability_id: str) -> Capability:
        from fastauth.exceptions import FeatureNotEnabledError

        capability = self.by_id.get(capability_id)
        if capability is None:
            raise FeatureNotEnabledError(feature=capability_id)
        return capability

    def list(self) -> list[Capability]:
        return list(self.items)
