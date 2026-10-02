"""Exercise the exact app factories linked from the deployment documentation."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from examples.deployment.common import ProductionSettings, mount_auth
from examples.deployment.memory import build_auth, create_app
from fastapi import FastAPI
from pydantic import SecretStr

from fastauth.messaging.email import ConsoleEmailSender


async def test_memory_recipe_signup_recovery_refresh_and_logout() -> None:
    outbox = ConsoleEmailSender()
    auth = build_auth(outbox)
    app = mount_auth(auth)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://localhost:8000",
            headers={"Origin": "http://localhost:8000"},
        ) as client:
            assert (await client.get("/auth/health/ready")).status_code == 200
            signup = await client.post(
                "/auth/sign-up/email",
                json={
                    "email": "docs@example.com",
                    "password": "first-password-123",
                },
            )
            assert signup.status_code == 200, signup.text
            assert (await client.get("/me")).status_code == 200
            verification_email = await client.post(
                "/auth/send-verification-email",
                json={"email": "docs@example.com"},
            )
            assert verification_email.status_code == 200, verification_email.text
            verification_link = re.search(r"https?://[^\s<>]+", outbox.outbox[-1].text)
            assert verification_link is not None
            verification_token = parse_qs(urlparse(verification_link.group(0)).query)["token"][0]
            verified = await client.post(
                "/auth/verify-email",
                json={"email": "docs@example.com", "token": verification_token},
            )
            assert verified.status_code == 200, verified.text
            assert (await client.get("/me")).json()["emailVerified"] is True
            reset_request = await client.post(
                "/auth/forgot-password",
                json={
                    "email": "docs@example.com",
                },
            )
            assert reset_request.status_code == 200, reset_request.text
            assert outbox.outbox
            link = re.search(r"https?://[^\s<>]+", outbox.outbox[-1].text)
            assert link is not None
            token = parse_qs(urlparse(link.group(0)).query)["token"][0]
            reset = await client.post(
                "/auth/reset-password",
                json={
                    "email": "docs@example.com",
                    "token": token,
                    "newPassword": "replacement-password-123",
                },
            )
            assert reset.status_code == 200, reset.text
            assert (await client.get("/me")).status_code == 401
            login = await client.post(
                "/auth/sign-in/email",
                json={
                    "email": "docs@example.com",
                    "password": "replacement-password-123",
                    "delivery": {"kind": "bearer"},
                },
            )
            assert login.status_code == 200, login.text
            client.cookies.clear()
            refresh = await client.post(
                "/auth/refresh",
                json={
                    "refreshToken": login.json()["credentials"]["refreshToken"],
                    "delivery": {"kind": "bearer"},
                },
            )
            assert refresh.status_code == 200, refresh.text
            client.headers["Authorization"] = f"Bearer {refresh.json()['credentials']['token']}"
            assert (await client.get("/me")).status_code == 200
            assert (await client.post("/auth/sign-out")).status_code == 200
            assert (await client.get("/me")).status_code == 401


def test_memory_factory_is_a_runnable_fastapi_app() -> None:
    assert isinstance(create_app(), FastAPI)


def production_settings() -> ProductionSettings:
    return ProductionSettings(
        secret_key=SecretStr("production-secret-for-doc-tests-at-least-32-bytes"),
        base_url="https://app.example.com",
        email_api_key=SecretStr("test-api-key"),
        email_from="Auth <auth@example.com>",
    )


def test_persistent_recipe_options_keep_production_guards() -> None:
    from fastauth.database import postgres
    from fastauth.domain.enums import RateLimitStorageKind

    options = production_settings().options(
        postgres(
            url="postgresql+asyncpg://app:pass@localhost/auth",
            migration_mode="check",
            plugin_migration_mode="check",
        )
    )
    assert options.deployment == "production"
    assert options.cookie.secure
    assert options.rate_limit.storage is RateLimitStorageKind.DATABASE
    assert options.production_safety.forbid_memory_database
    assert options.production_safety.forbid_console_email_sender


def test_mongo_and_postgres_factories_construct_without_opening_connections(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from examples.deployment.mongo import MongoSettings
    from examples.deployment.mongo import create_app as create_mongo
    from examples.deployment.postgres import PostgresSettings
    from examples.deployment.postgres import create_app as create_postgres

    for proxy in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ):
        monkeypatch.delenv(proxy, raising=False)
    common = production_settings().model_dump()
    assert isinstance(
        create_mongo(
            MongoSettings.model_validate(
                {
                    **common,
                    "mongo_url": "mongodb://localhost:27017",
                    "mongo_database": "auth",
                }
            )
        ),
        FastAPI,
    )
    assert isinstance(
        create_postgres(
            PostgresSettings.model_validate(
                {
                    **common,
                    "postgres_url": "postgresql+asyncpg://app:pass@localhost/auth",
                }
            )
        ),
        FastAPI,
    )


def test_production_settings_load_application_owned_config_file(tmp_path: Path) -> None:
    from examples.deployment.postgres import PostgresSettings

    config = tmp_path / "deployment.json"
    config.write_text(
        '{"secret_key":"application-owned-secret-at-least-32-bytes",'
        '"base_url":"https://app.example.com","email_api_key":"test-key",'
        '"email_from":"auth@example.com",'
        '"postgres_url":"postgresql+asyncpg://app:pass@localhost/auth"}'
    )
    loaded = PostgresSettings.from_file(config)
    assert loaded.email_api_key.get_secret_value() == "test-key"
    assert loaded.postgres_url.get_secret_value().startswith("postgresql+asyncpg://")
