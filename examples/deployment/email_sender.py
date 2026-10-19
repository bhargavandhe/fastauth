"""Async Resend recipe: bounded retries, one idempotency key per send operation."""

from __future__ import annotations

import asyncio
from uuid import uuid4

import httpx
from pydantic import BaseModel, Field, SecretStr

from fastauth.domain.models import EmailMessage


class ResendSettings(BaseModel):
    api_key: SecretStr
    from_address: str = Field(min_length=3)
    max_attempts: int = Field(default=3, ge=1, le=5)
    retry_delay: float = Field(default=0.5, ge=0, le=10)


class ResendPayload(BaseModel):
    sender: str = Field(serialization_alias="from")
    to: list[str]
    subject: str
    html: str
    text: str
    headers: dict[str, str]


class ResendEmailSender:
    """Provider acceptance is awaited; this is not a durable email queue.

    The application owns and closes the AsyncClient. A stable idempotency key
    covers retries within one call only. Persist delivery IDs in an application
    outbox if retries must survive process failure.
    """

    def __init__(self, client: httpx.AsyncClient, settings: ResendSettings) -> None:
        self.client = client
        self.settings = settings

    async def send(self, message: EmailMessage) -> None:
        payload = ResendPayload(
            sender=self.settings.from_address,
            to=[str(message.to)],
            subject=message.subject,
            html=message.html,
            text=message.text,
            headers=message.headers,
        )
        headers = {
            "Authorization": f"Bearer {self.settings.api_key.get_secret_value()}",
            "Idempotency-Key": str(uuid4()),
        }
        for attempt in range(self.settings.max_attempts):
            try:
                response = await self.client.post(
                    "https://api.resend.com/emails",
                    headers=headers,
                    json=payload.model_dump(by_alias=True),
                    timeout=10.0,
                    follow_redirects=False,
                )
                response.raise_for_status()
                return
            except httpx.HTTPStatusError as error:
                if error.response.status_code != 429 and error.response.status_code < 500:
                    raise
                if attempt + 1 == self.settings.max_attempts:
                    raise
            except httpx.TransportError:
                if attempt + 1 == self.settings.max_attempts:
                    raise
            await asyncio.sleep(self.settings.retry_delay * 2**attempt)
