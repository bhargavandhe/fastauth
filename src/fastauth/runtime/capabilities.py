"""Runtime capability registry exposed by ``FastAuth``."""

from __future__ import annotations

from collections.abc import Iterable
from typing import NewType

from pydantic import ConfigDict, Field

from fastauth.domain.models import WireModel

CapabilityId = NewType("CapabilityId", str)

CORE_SESSIONS = CapabilityId("core.sessions")
CORE_REFRESH_TOKENS = CapabilityId("core.refresh-tokens")
EMAIL_PASSWORD = CapabilityId("email-password")
USERNAME_SIGN_IN = CapabilityId("username-sign-in")
BEARER_TOKENS = CapabilityId("bearer-tokens")
EMAIL_OTP = CapabilityId("email-otp")
API_KEYS = CapabilityId("api-keys")
JWT = CapabilityId("jwt")
AUDIT_LOGS = CapabilityId("audit-logs")
OPENAPI_REFERENCE = CapabilityId("openapi-reference")
TEST_UTILS = CapabilityId("test-utils")

__all__ = [
    "API_KEYS",
    "AUDIT_LOGS",
    "BEARER_TOKENS",
    "CORE_REFRESH_TOKENS",
    "CORE_SESSIONS",
    "EMAIL_OTP",
    "EMAIL_PASSWORD",
    "JWT",
    "OPENAPI_REFERENCE",
    "TEST_UTILS",
    "USERNAME_SIGN_IN",
    "Capability",
    "CapabilityId",
    "CapabilityRegistry",
]


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

    def has(self, capability_id: CapabilityId | str) -> bool:
        return str(capability_id) in self.by_id

    def require(self, capability_id: CapabilityId | str) -> Capability:
        from fastauth.exceptions import FeatureNotEnabledError

        capability = self.by_id.get(str(capability_id))
        if capability is None:
            raise FeatureNotEnabledError(feature=str(capability_id))
        return capability

    def list(self) -> list[Capability]:
        return list(self.items)
