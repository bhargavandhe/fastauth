"""Consistent warnings for public API deprecations after the 0.14 boundary."""

from __future__ import annotations

import warnings

__all__ = ["FastAuthDeprecationWarning", "warn_deprecated"]


class FastAuthDeprecationWarning(DeprecationWarning):
    """Warning category for supported FastAuth deprecation windows."""


def warn_deprecated(
    name: str,
    *,
    replacement: str,
    removal: str,
    stacklevel: int = 2,
) -> None:
    """Emit one consistently formatted public API deprecation warning."""
    warnings.warn(
        f"{name} is deprecated; use {replacement}. Removal is planned for {removal}.",
        FastAuthDeprecationWarning,
        stacklevel=stacklevel,
    )
