from __future__ import annotations

import pathlib

from typer.testing import CliRunner

from authkit.cli.main import app


def test_generate_secret_prints_64_chars() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["generate-secret"])
    assert result.exit_code == 0
    assert len(result.stdout.strip()) >= 64


def test_init_writes_auth_scaffold(tmp_path: pathlib.Path) -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["init", "--path", str(tmp_path)])
    assert result.exit_code == 0
    auth_py = tmp_path / "auth.py"
    assert auth_py.exists()
    # The scaffold demonstrates explicit AuthKitConfig construction and does
    # NOT pull from any env-only loader.
    body = auth_py.read_text(encoding="utf-8")
    assert "AuthKitConfig" in body
    assert "AuthKitEnvConfig" not in body


def test_init_no_longer_writes_dotenv_example(tmp_path: pathlib.Path) -> None:
    """The CLI no longer ships an ``.env.example`` template — consumers
    decide their own config-loading strategy (env vars, vault, file, etc.).
    """
    runner = CliRunner()
    result = runner.invoke(app, ["init", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert not (tmp_path / ".env.example").exists()


def test_migrate_requires_explicit_mongo_url() -> None:
    """``migrate`` requires an explicit connection flag."""
    runner = CliRunner()
    result = runner.invoke(app, ["migrate"])
    assert result.exit_code == 1
    assert "Pass exactly one" in result.stdout


def test_migrate_requires_exactly_one_backend_url() -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "migrate",
            "--mongo-url",
            "mongodb://localhost:27017",
            "--postgres-url",
            "postgresql+asyncpg://localhost/authkit",
        ],
    )
    assert result.exit_code == 1
    assert "Pass exactly one" in result.stdout
