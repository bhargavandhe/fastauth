"""Development only: uvicorn examples.deployment.memory:create_app --factory."""

from __future__ import annotations

from fastapi import FastAPI
from pydantic import SecretStr

from fastauth import FastAuth, FastAuthOptions, email_password
from fastauth.database import memory
from fastauth.messaging.email import ConsoleEmailSender
from fastauth.options import CookieOptions, CsrfOptions

from .common import mount_auth


def build_auth(email_sender: ConsoleEmailSender | None = None) -> FastAuth:
    return FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("local-development-only-never-use-this-secret-in-production"),
            database=memory(),
            cookie=CookieOptions(secure=False),
            csrf=CsrfOptions(trusted_origins=("http://localhost:8000",)),
        ),
        plugins=[email_password()],
        email_sender=email_sender or ConsoleEmailSender(),
    )


def create_app() -> FastAPI:
    return mount_auth(build_auth())
