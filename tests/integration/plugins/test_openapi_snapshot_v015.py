"""Snapshot the actual mounted schema, including custom API-key protection."""

import json
from pathlib import Path

from fastapi import Depends, FastAPI
from pydantic import SecretStr

from fastauth import FastAuth, api_key, audit_logs, email_otp, email_password, jwt, openapi
from fastauth.api.responses import ApiKeyView
from fastauth.database import memory
from fastauth.options import CookieOptions, FastAuthOptions


def snapshot_app() -> FastAPI:
    auth = FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("x" * 64),
            database=memory(),
            cookie=CookieOptions(name="example.session"),
        ),
        plugins=[email_password(), email_otp(), jwt(), api_key(), audit_logs(), openapi()],
    )
    app = FastAPI()
    app.include_router(auth.router, prefix="/v1/auth")
    dependency = Depends(auth.depends.api_key())

    async def protected(key: ApiKeyView = dependency) -> ApiKeyView:
        return key

    app.get("/files", operation_id="read_files")(protected)
    return app


def test_mounted_openapi_snapshot() -> None:
    schema = snapshot_app().openapi()
    expected = json.loads(
        (Path(__file__).parents[2] / "snapshots" / "openapi-v015.json").read_text()
    )
    assert schema == expected
