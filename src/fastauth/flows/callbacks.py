"""Callback URL helpers for email-driven auth flows."""

from __future__ import annotations

from pydantic import AnyHttpUrl

__all__ = ["resolve_callback_url"]


def resolve_callback_url(
    *,
    app_base_url: AnyHttpUrl,
    callback_path: str,
    override: AnyHttpUrl | None,
) -> str:
    if override is not None:
        return str(override).rstrip("/")
    return f"{str(app_base_url).rstrip('/')}/{callback_path.lstrip('/')}"
