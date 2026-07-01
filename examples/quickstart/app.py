"""Example FastAPI app exercising every fastauth feature end-to-end.

The example keeps configuration explicit: callers construct ``FastAuthOptions``
and pass it to ``FastAuth``. No process environment is read by the
example or by fastauth.
"""

from __future__ import annotations

from contextlib import AbstractAsyncContextManager
from typing import Any, Protocol

from fastapi import FastAPI
from pydantic import SecretStr
from pymongo import AsyncMongoClient
from pymongo.asynchronous.database import AsyncDatabase

from fastauth import FastAuth, FastAuthOptions
from fastauth.database import mongo
from fastauth.options import CookieOptions, CsrfOptions, RateLimitOptions
from fastauth.providers import api_key, audit_logs, email_password, jwt, openapi

__all__ = [
    "DATABASE_NAME",
    "MONGO_URL",
    "app",
    "auth",
    "build_options",
    "create_app",
    "create_auth",
    "lifespan",
    "mongo_client",
    "mongo_database",
    "options",
]


class AuthRuntime(Protocol):
    def lifespan(self, app: FastAPI) -> AbstractAsyncContextManager[None]: ...

    def mount(self, app: FastAPI) -> None: ...


MONGO_URL = "mongodb://localhost:27017"
DATABASE_NAME = "fastauth"


def build_options(
    *,
    secret_key: SecretStr,
    database: AsyncDatabase[Any],
    cookie_secure: bool = True,
    csrf_enabled: bool = True,
    rate_limit_enabled: bool = True,
) -> FastAuthOptions:
    return FastAuthOptions(
        secret_key=secret_key,
        database=mongo(database),
        cookie=CookieOptions(secure=cookie_secure),
        csrf=CsrfOptions(enabled=csrf_enabled),
        rate_limit=RateLimitOptions(enabled=rate_limit_enabled),
    )


def create_auth(options: FastAuthOptions) -> AuthRuntime:
    return FastAuth(
        options,
        plugins=[
            email_password(),
            api_key(),
            jwt(),
            audit_logs(),
            openapi(),
        ],
    )


def create_app(auth: AuthRuntime) -> FastAPI:
    app_instance = FastAPI(title="fastauth quickstart", lifespan=auth.lifespan)
    auth.mount(app_instance)

    @app_instance.get("/")
    async def root() -> dict[str, str]:
        """Friendly landing page pointing visitors at the Scalar API reference."""
        return {"message": "fastauth quickstart - visit /auth/reference for the API docs"}

    return app_instance


mongo_client: AsyncMongoClient[Any] = AsyncMongoClient(
    MONGO_URL,
    uuidRepresentation="standard",
    tz_aware=True,
)
mongo_database: AsyncDatabase[Any] = mongo_client[DATABASE_NAME]
options = build_options(
    secret_key=SecretStr("replace-me-with-a-secret-from-your-application-config"),
    database=mongo_database,
)
auth = create_auth(options)
app = create_app(auth)
lifespan = app.router.lifespan_context
