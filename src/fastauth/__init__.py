"""fastauth — a modular FastAPI authentication library."""

from __future__ import annotations

from fastauth.config import FastAuthConfig
from fastauth.runtime.auth import FastAuth

__all__ = ["FastAuth", "FastAuthConfig", "__version__"]
__version__ = "0.1.0"
