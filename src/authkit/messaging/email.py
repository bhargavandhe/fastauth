"""EmailSender protocol, default Jinja2 renderer, and console sender for tests."""

from __future__ import annotations

import pathlib
from typing import Any, Protocol, runtime_checkable

from jinja2 import (
    BaseLoader,
    ChoiceLoader,
    Environment,
    FileSystemLoader,
    PackageLoader,
    TemplateNotFound,
    select_autoescape,
)

from authkit.domain.models import EmailMessage

__all__ = ["ConsoleEmailSender", "EmailSender", "TemplateRenderer"]


@runtime_checkable
class EmailSender(Protocol):
    """Protocol for asynchronous email senders."""

    async def send(self, message: EmailMessage) -> None: ...


class ConsoleEmailSender:
    """In-memory `EmailSender` for tests and local development."""

    def __init__(self) -> None:
        self.outbox: list[EmailMessage] = []

    async def send(self, message: EmailMessage) -> None:
        self.outbox.append(message)


class TemplateRenderer:
    """Renders email templates from a user-supplied directory or packaged defaults."""

    def __init__(self, template_directory: str | None) -> None:
        loaders: list[BaseLoader] = []
        if template_directory is not None and pathlib.Path(template_directory).is_dir():
            loaders.append(FileSystemLoader(template_directory))
        loaders.append(PackageLoader("authkit", "messaging/templates"))
        self.environment = Environment(
            loader=ChoiceLoader(loaders),
            autoescape=select_autoescape(["html"]),
            keep_trailing_newline=True,
        )

    def render(self, name: str, variables: dict[str, Any]) -> tuple[str, str]:
        try:
            html = self.environment.get_template(f"{name}.html").render(**variables)
        except TemplateNotFound:
            html = ""
        text = self.environment.get_template(f"{name}.txt").render(**variables)
        return html, text
