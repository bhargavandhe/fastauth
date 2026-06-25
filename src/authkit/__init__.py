"""authkit — a modular FastAPI authentication library."""

from __future__ import annotations

from authkit.config import AuthKitConfig
from authkit.runtime.auth import AuthKit

__all__ = ["AuthKit", "AuthKitConfig", "__version__"]
__version__ = "0.1.0"
