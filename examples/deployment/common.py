"""Application-owned settings and typed FastAPI wiring shared by the recipes."""

from __future__ import annotations

from collections.abc import AsyncGenerator, Awaitable, Callable, Sequence
from contextlib import AsyncExitStack, asynccontextmanager
from pathlib import Path
from typing import Self
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI
from pydantic import BaseModel, SecretStr

from fastauth import FastAuth, FastAuthOptions, UserView
from fastauth.domain.enums import RateLimitStorageKind
from fastauth.options import (
    AppOptions,
    CookieOptions,
    CsrfOptions,
    DatabaseOptions,
    RateLimitOptions,
)

from .email_sender import ResendSettings


class ProductionSettings(BaseModel):
    secret_key: SecretStr
    base_url: str
    email_api_key: SecretStr
    email_from: str

    @classmethod
    def from_file(cls, path: Path = Path("deployment.json")) -> Self:
        """Load an application-owned mounted config file, outside library settings."""
        return cls.model_validate_json(path.read_text(encoding="utf-8"))

    def options(self, database: DatabaseOptions) -> FastAuthOptions:
        origin = urlsplit(self.base_url)
        return FastAuthOptions(
            secret_key=self.secret_key,
            deployment="production",
            database=database,
            app=AppOptions.model_validate({"base_url": self.base_url}),
            csrf=CsrfOptions(trusted_origins=(f"{origin.scheme}://{origin.netloc}",)),
            cookie=CookieOptions(secure=True),
            rate_limit=RateLimitOptions(storage=RateLimitStorageKind.DATABASE),
        )

    def sender_settings(self) -> ResendSettings:
        return ResendSettings(api_key=self.email_api_key, from_address=self.email_from)


def mount_auth(
    auth: FastAuth,
    close_resources: Sequence[Callable[[], Awaitable[None]]] = (),
) -> FastAPI:
    """A synchronous FastAPI application factory; authentication handlers are async."""

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
        async with AsyncExitStack() as stack:
            for close in close_resources:
                stack.push_async_callback(close)
            await stack.enter_async_context(auth.lifespan(app))
            yield

    app = FastAPI(title="FastAuth deployment recipe", lifespan=lifespan)
    app.include_router(auth.router, prefix=auth.options.app.base_path)
    auth.add_middleware(app)

    user_dependency = Depends(auth.depends.user())

    @app.get("/me", response_model=UserView)
    async def me(user: UserView = user_dependency) -> UserView:
        return user

    return app
