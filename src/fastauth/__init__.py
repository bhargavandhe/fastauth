"""fastauth — a modular FastAPI authentication library."""

from __future__ import annotations

from fastauth.api.responses import AuthenticationResponse, SessionView, UserView
from fastauth.domain.events import AuthEvent
from fastauth.options import FastAuthOptions
from fastauth.runtime.auth import FastAuth
from fastauth.runtime.capabilities import Capability, CapabilityRegistry
from fastauth.runtime.event_bus import EventBus

__all__ = [
    "AuthEvent",
    "AuthenticationResponse",
    "Capability",
    "CapabilityRegistry",
    "EventBus",
    "FastAuth",
    "FastAuthOptions",
    "SessionView",
    "UserView",
    "__version__",
]
__version__ = "0.9.0"
