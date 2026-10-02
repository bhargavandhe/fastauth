"""Execute from outside the checkout using only a freshly installed wheel."""

from __future__ import annotations

import asyncio
import importlib
import importlib.metadata
import importlib.resources
import importlib.util
import runpy
import sys
import tempfile
from pathlib import Path

from pydantic import EmailStr, SecretStr, TypeAdapter

import fastauth
from fastauth import FastAuth, FastAuthOptions, email_password
from fastauth.api.commands import BearerCredentialDelivery
from fastauth.messaging.email import TemplateRenderer


async def main() -> None:
    assert fastauth.__version__ == importlib.metadata.version("fastauth-py") == "0.15.0"
    python_requirement = importlib.metadata.metadata("fastauth-py")["Requires-Python"]
    assert {bound.strip() for bound in python_requirement.split(",")} == {">=3.11", "<3.14"}
    location = Path(fastauth.__file__).resolve()
    assert "site-packages" in location.parts, f"Expected installed wheel, got {location}"
    assert importlib.resources.files("fastauth").joinpath("py.typed").is_file()
    renderer = TemplateRenderer(None)
    html, message = renderer.render(
        "verification",
        {
            "verify_url": "https://example.com/verify",
            "name": "Reader",
            "expires_in_minutes": 15,
        },
    )
    assert "https://example.com/verify" in html and "https://example.com/verify" in message
    auth = FastAuth(
        FastAuthOptions(secret_key=SecretStr("wheel-smoke-application-secret-at-least-32-bytes")),
        plugins=[email_password()],
    )
    app = auth.as_asgi()
    async with auth.lifespan(app):
        result = await auth.sign_up.email(
            TypeAdapter(EmailStr).validate_python("wheel@example.com"),
            SecretStr("wheel-password-12345"),
            delivery=BearerCredentialDelivery(),
        )
        body = result.model_dump()
        assert "emailVerified" in body["user"] and "createdAt" in body["user"]
        assert "email_verified" not in body["user"]
        assert result.credentials is not None
        assert await auth.sessions.get(SecretStr(result.credentials.token.root)) is not None
    extra = sys.argv[1]
    modules = {
        "beanie": ("fastauth.storage.beanie.adapter", "pymongo"),
        "postgres": ("fastauth.storage.postgres.adapter", "asyncpg"),
        "jwt": ("fastauth.plugins.jwt", "fastauth.security.jwt"),
        "cli": ("fastauth.cli.main",),
        "testing": ("fastauth.testing.adapter_contract",),
        "docs": ("mkdocs", "mkdocstrings"),
        "dev": ("pytest", "httpx", "testcontainers", "ruff"),
        "core": (),
    }
    for module in modules[extra]:
        importlib.import_module(module)
    if extra == "core":
        for dependency in ("beanie", "sqlalchemy", "joserfc", "typer", "pytest"):
            assert importlib.util.find_spec(dependency) is None, dependency
    if extra == "jwt":
        from fastauth import jwt
        from fastauth.domain.enums import SessionStrategyKind
        from fastauth.options import SessionOptions

        jwt_auth = FastAuth(
            FastAuthOptions(
                secret_key=SecretStr("wheel-smoke-jwt-secret-at-least-thirty-two-bytes"),
                session=SessionOptions(strategy=SessionStrategyKind.JWT),
            ),
            plugins=[email_password(), jwt()],
        )
        async with jwt_auth.lifespan(jwt_auth.as_asgi()):
            signed = await jwt_auth.sign_up.email(
                TypeAdapter(EmailStr).validate_python("jwt@example.com"),
                SecretStr("wheel-password-12345"),
                delivery=BearerCredentialDelivery(),
            )
            assert signed.credentials is not None
            assert await jwt_auth.sessions.get(SecretStr(signed.credentials.token.root)) is not None
    if extra == "cli":
        from typer.testing import CliRunner

        from fastauth.cli.main import app as cli

        result_cli = CliRunner().invoke(cli, ["--help"])
        assert result_cli.exit_code == 0, result_cli.output
        with tempfile.TemporaryDirectory() as target:
            generated = CliRunner().invoke(cli, ["init", "--backend", "memory", "--path", target])
            assert generated.exit_code == 0, generated.output
            module = runpy.run_path(str(Path(target) / "auth.py"))
            assert isinstance(
                module["build_auth"]("application-owned-secret-at-least-32-bytes"), FastAuth
            )
    print(f"Installed wheel {fastauth.__version__}: {extra} passed ({location})")


asyncio.run(main())
