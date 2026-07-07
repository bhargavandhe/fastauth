"""fastauth — a modular FastAPI authentication library."""

from __future__ import annotations

from fastauth.api.responses import AuthenticationResponse, SessionView, UserView
from fastauth.options import FastAuthOptions
from fastauth.runtime.auth import FastAuth

__all__ = [
    "AuthenticationResponse",
    "FastAuth",
    "FastAuthOptions",
    "SessionView",
    "UserView",
    "__version__",
]
__version__ = "0.8.0"
