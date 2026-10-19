"""Postgres: uvicorn examples.deployment.postgres:create_app --factory."""

from __future__ import annotations

import httpx
from fastapi import FastAPI
from pydantic import SecretStr

from fastauth import FastAuth, email_password
from fastauth.database import postgres

from .common import ProductionSettings, mount_auth
from .email_sender import ResendEmailSender


class PostgresSettings(ProductionSettings):
    postgres_url: SecretStr


def create_app(settings: PostgresSettings | None = None) -> FastAPI:
    settings = settings or PostgresSettings.from_file()
    http = httpx.AsyncClient(limits=httpx.Limits(max_connections=10))
    options = settings.options(
        postgres(
            url=settings.postgres_url.get_secret_value(),
            migration_mode="check",
            plugin_migration_mode="check",
        )
    )
    auth = FastAuth(
        options,
        plugins=[email_password()],
        email_sender=ResendEmailSender(http, settings.sender_settings()),
    )
    return mount_auth(auth, (http.aclose,))
