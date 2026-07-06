from __future__ import annotations

import pathlib

from fastauth.domain.models import EmailMessage
from fastauth.messaging.email import ConsoleEmailSender, TemplateRenderer


async def test_console_sender_captures_messages() -> None:
    sender = ConsoleEmailSender()
    message = EmailMessage(to="x@example.com", subject="s", html="<p>h</p>", text="h")
    await sender.send(message)
    assert sender.outbox == [message]


def test_template_renderer_uses_packaged_templates() -> None:
    renderer = TemplateRenderer(None)
    html, text = renderer.render(
        "verification",
        {"verify_url": "http://x/verify?token=abc", "name": "Alice"},
    )
    assert "http://x/verify?token=abc" in html
    assert "http://x/verify?token=abc" in text
    assert "Alice" in html


def test_template_renderer_falls_back_to_packaged_when_directory_missing(
    tmp_path: pathlib.Path,
) -> None:
    renderer = TemplateRenderer(str(tmp_path))
    html, text = renderer.render(
        "verification",
        {"verify_url": "http://x", "name": "X"},
    )
    assert "http://x" in html and "http://x" in text
