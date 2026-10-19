"""Generated app code must execute, not merely contain expected strings."""

from __future__ import annotations

import runpy
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from pydantic import SecretStr
from pymongo import AsyncMongoClient
from typer.testing import CliRunner

from fastauth import FastAuth
from fastauth.cli.main import app


@pytest.mark.parametrize("backend", ["memory", "mongo", "postgres"])
async def test_generated_scaffold_constructs_options_and_auth(tmp_path: Path, backend: str) -> None:
    result = CliRunner().invoke(app, ["init", "--backend", backend, "--path", str(tmp_path)])
    assert result.exit_code == 0, result.output
    generated = runpy.run_path(str(tmp_path / "auth.py"))
    secret = "application-owned-secret-at-least-thirty-two-bytes"
    if backend == "memory":
        options = generated["create_options"](secret)
        auth = generated["build_auth"](secret)
        assert isinstance(auth, FastAuth)
    elif backend == "mongo":
        client: AsyncMongoClient[Any] = AsyncMongoClient("mongodb://localhost:27017")
        try:
            options = generated["create_options"](secret_key=secret, database=client["example"])
            assert isinstance(generated["build_auth"](options), FastAuth)
        finally:
            await client.close()
    else:
        options = generated["create_options"](
            secret_key=secret,
            postgres_url="postgresql+asyncpg://app:pass@localhost/auth",
        )
        assert isinstance(generated["create_app"](options), FastAPI)
    assert isinstance(options.secret_key, SecretStr)
    assert options.secret_key.get_secret_value() == secret
