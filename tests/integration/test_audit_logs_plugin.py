"""Integration tests for the AuditLogsPlugin (Task 21)."""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from fastauth.plugins.audit_logs import AuditLogsConfig, AuditLogsPlugin
from fastauth.runtime.auth import FastAuth


@pytest.fixture
def auth(auth_factory: Callable[..., FastAuth]) -> FastAuth:
    return auth_factory(plugins=[AuditLogsPlugin(AuditLogsConfig())])


async def test_sign_up_writes_audit_event(client: httpx.AsyncClient) -> None:
    await client.post(
        "/auth/sign-up/email",
        json={"email": "alice@example.com", "password": "correct-horse-staple"},
    )
    listed = await client.get("/auth/audit-logs", params={"limit": 50})
    assert listed.status_code == 200
    events = listed.json()["events"]
    types = {event["event_type"] for event in events}
    assert "user_signed_up" in types
    assert "session_created" in types


async def test_filter_by_event_type(client: httpx.AsyncClient) -> None:
    await client.post(
        "/auth/sign-up/email",
        json={"email": "bob@example.com", "password": "correct-horse-staple"},
    )
    response = await client.get(
        "/auth/audit-logs",
        params={"event_type": "user_signed_up"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["events"][0]["event_type"] == "user_signed_up"


async def test_admin_endpoint_requires_admin(client: httpx.AsyncClient) -> None:
    await client.post(
        "/auth/sign-up/email",
        json={"email": "carol@example.com", "password": "correct-horse-staple"},
    )
    response = await client.get("/auth/audit-logs/all")
    assert response.status_code == 403
