"""Email/password first-party auth provider plugin."""

from __future__ import annotations

from typing import ClassVar

from pydantic import BaseModel, ConfigDict

from fastauth.plugins.base import Plugin

__all__ = ["EmailPasswordOptions", "EmailPasswordPlugin"]


class EmailPasswordOptions(BaseModel):
    """Static options for the email/password provider."""

    model_config = ConfigDict(extra="forbid")
    allow_username_sign_in: bool = True
    allow_bearer_tokens: bool = True


class EmailPasswordPlugin(Plugin):
    """Enable built-in email/password routes."""

    id: ClassVar[str] = "fastauth-email-password"

    def __init__(self, options: EmailPasswordOptions | None = None) -> None:
        self.options = options or EmailPasswordOptions()
        self.config = self.options
