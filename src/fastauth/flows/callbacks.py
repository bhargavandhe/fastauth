"""Callback URL helpers for email-driven auth flows."""

from __future__ import annotations

from pydantic import AnyHttpUrl

from fastauth.options import DynamicBaseUrlOptions
from fastauth.web.callbacks import build_callback_url

__all__ = ["resolve_callback_url"]


def resolve_callback_url(
    *,
    app_base_url: AnyHttpUrl | DynamicBaseUrlOptions | str,
    callback_path: str,
    override: AnyHttpUrl | str | None,
) -> str:
    return build_callback_url(
        app_base_url=app_base_url,
        callback_path=callback_path,
        override=override,
    )
