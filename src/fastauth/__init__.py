"""fastauth — a modular FastAPI authentication library."""

from __future__ import annotations

from fastauth.options import FastAuthOptions
from fastauth.runtime.auth import FastAuth

__all__ = ["FastAuth", "FastAuthOptions", "__version__"]
__version__ = "0.3.2"
