"""Example FastAPI app exercising every authkit v1 feature end-to-end.

The example keeps configuration explicit: callers construct an
``AuthKitConfig`` and pass it into the app factory. No process environment is
read by the example or by authkit.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from pydantic import SecretStr

from authkit import AuthKit, AuthKitConfig
from authkit.config import (
    CookieConfig,
    CsrfConfig,
    DatabaseConfig,
    RateLimitConfig,
)
from authkit.plugins.api_key import ApiKeyPlugin
from authkit.plugins.audit_logs import AuditLogsPlugin
from authkit.plugins.jwt import JwtPlugin
from authkit.plugins.openapi import OpenApiPlugin
from authkit.storage.beanie import BeanieAdapter

__all__ = [
    "app",
    "auth",
    "build_config",
    "config",
    "create_app",
    "create_auth",
    "lifespan",
    "mongo_client",
    "mongo_database",
]


def build_config(
    *,
    secret_key: SecretStr,
    mongo_url: str = "mongodb://localhost:27017",
    database_name: str = "authkit",
    cookie_secure: bool = True,
    csrf_enabled: bool = True,
    rate_limit_enabled: bool = True,
) -> AuthKitConfig:
    return AuthKitConfig(
        secret_key=secret_key,
        database=DatabaseConfig(
            mongo_url=mongo_url,
            database_name=database_name,
        ),
        cookie=CookieConfig(secure=cookie_secure),
        csrf=CsrfConfig(enabled=csrf_enabled),
        rate_limit=RateLimitConfig(enabled=rate_limit_enabled),
    )


def create_auth(config: AuthKitConfig, database: AsyncIOMotorDatabase[Any]) -> AuthKit:
    adapter = BeanieAdapter(database)
    return AuthKit(
        config,
        adapter=adapter,
        plugins=[
            ApiKeyPlugin(),
            JwtPlugin(),
            AuditLogsPlugin(),
            OpenApiPlugin(),
        ],
    )


def create_app(auth: AuthKit, database: AsyncIOMotorDatabase[Any]) -> FastAPI:
    del database  # The BeanieAdapter is already bound into the AuthKit instance.
    adapter = auth.context.adapter
    if not isinstance(adapter, BeanieAdapter):
        raise TypeError("quickstart create_app requires a BeanieAdapter-backed AuthKit")
    app_instance = FastAPI(title="authkit quickstart", lifespan=adapter.lifespan(auth))
    auth.install(app_instance)

    @app_instance.get("/")
    async def root() -> dict[str, str]:
        """Friendly landing page pointing visitors at the Scalar API reference."""
        return {"message": "authkit quickstart - visit /auth/reference for the API docs"}

    return app_instance


config = build_config(
    secret_key=SecretStr("replace-me-with-a-secret-from-your-application-config"),
)

mongo_client: AsyncIOMotorClient[Any] = AsyncIOMotorClient(
    config.database.mongo_url,
    uuidRepresentation="standard",
    tz_aware=True,
)
mongo_database: AsyncIOMotorDatabase[Any] = mongo_client[config.database.database_name]
auth = create_auth(config, mongo_database)
app = create_app(auth, mongo_database)
lifespan = app.router.lifespan_context
