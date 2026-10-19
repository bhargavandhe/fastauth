"""MongoDB: uvicorn examples.deployment.mongo:create_app --factory."""

from __future__ import annotations

from typing import Any

import httpx
from fastapi import FastAPI
from pydantic import SecretStr
from pymongo import AsyncMongoClient

from fastauth import FastAuth, email_password
from fastauth.database import mongo

from .common import ProductionSettings, mount_auth
from .email_sender import ResendEmailSender


class MongoSettings(ProductionSettings):
    mongo_url: SecretStr
    mongo_database: str


def create_app(settings: MongoSettings | None = None) -> FastAPI:
    settings = settings or MongoSettings.from_file()
    client: AsyncMongoClient[Any] = AsyncMongoClient(
        settings.mongo_url.get_secret_value(),
        tz_aware=True,
        uuidRepresentation="standard",
    )
    http = httpx.AsyncClient(limits=httpx.Limits(max_connections=10))
    options = settings.options(
        mongo(
            database=client[settings.mongo_database],
            plugin_migration_mode="check",
        )
    )
    auth = FastAuth(
        options,
        plugins=[email_password()],
        email_sender=ResendEmailSender(http, settings.sender_settings()),
    )
    return mount_auth(auth, (client.close, http.aclose))
