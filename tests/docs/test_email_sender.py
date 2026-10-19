"""The production sender recipe uses async I/O and bounded, idempotent retries."""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest
from examples.deployment.email_sender import ResendEmailSender, ResendSettings
from pydantic import SecretStr, ValidationError

from fastauth.domain.models import EmailMessage


def message() -> EmailMessage:
    return EmailMessage(
        to="reader@example.com",
        subject="Verify your email",
        html="<p>Verify</p>",
        text="Verify",
    )


def settings() -> ResendSettings:
    return ResendSettings(api_key=SecretStr("test-key"), from_address="Auth <auth@example.com>")


async def test_sender_maps_message_and_reuses_idempotency_key_on_retry() -> None:
    requests: list[httpx.Request] = []

    async def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        await asyncio.sleep(0)
        return httpx.Response(503 if len(requests) == 1 else 200, json={"id": "accepted"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
        sender = ResendEmailSender(client, settings().model_copy(update={"retry_delay": 0.0}))
        await sender.send(message())
    assert len(requests) == 2
    assert requests[0].url == "https://api.resend.com/emails"
    assert requests[0].headers["Authorization"] == "Bearer test-key"
    assert requests[0].headers["Idempotency-Key"] == requests[1].headers["Idempotency-Key"]
    payload = json.loads(requests[0].content)
    assert payload == {
        "from": "Auth <auth@example.com>",
        "to": ["reader@example.com"],
        "subject": "Verify your email",
        "html": "<p>Verify</p>",
        "text": "Verify",
        "headers": {},
    }


@pytest.mark.parametrize("status", [400, 401, 403, 422])
async def test_sender_does_not_retry_permanent_rejections(status: int) -> None:
    attempts = 0

    async def handle(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(status)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
        with pytest.raises(httpx.HTTPStatusError):
            await ResendEmailSender(client, settings()).send(message())
    assert attempts == 1


@pytest.mark.parametrize("failure", [429, 503, "timeout"])
async def test_sender_surfaces_failure_after_bounded_attempts(failure: int | str) -> None:
    attempts = 0

    async def handle(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if failure == "timeout":
            raise httpx.ReadTimeout("timed out", request=request)
        assert isinstance(failure, int)
        return httpx.Response(failure)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
        config = settings().model_copy(update={"retry_delay": 0.0})
        with pytest.raises(httpx.HTTPError):
            await ResendEmailSender(client, config).send(message())
    assert attempts == 3


async def test_sender_does_not_swallow_cancellation() -> None:
    async def handle(request: httpx.Request) -> httpx.Response:
        raise asyncio.CancelledError

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
        with pytest.raises(asyncio.CancelledError):
            await ResendEmailSender(client, settings()).send(message())


def test_sender_rejects_unbounded_retry_configuration() -> None:
    with pytest.raises(ValidationError):
        ResendSettings(api_key=SecretStr("test"), from_address="auth@example.com", max_attempts=0)
