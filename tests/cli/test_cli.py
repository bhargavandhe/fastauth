from __future__ import annotations

import pathlib
from typing import Any

from typer.testing import CliRunner

from fastauth.cli.main import app


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
    # The scaffold demonstrates explicit FastAuthOptions construction and does
    # NOT pull from any env-only loader.
    body = auth_py.read_text(encoding="utf-8")
    assert "FastAuthOptions" in body
    assert "FastAuth(create_options(secret_key), plugins=[email_password()])" in body
    assert "FastAuthEnvConfig" not in body
    assert "memory()" in body
    assert "email_password()" in body
    assert "motor" not in body


def test_init_can_write_postgres_scaffold(tmp_path: pathlib.Path) -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["init", "--backend", "postgres", "--path", str(tmp_path)])
    assert result.exit_code == 0

    body = (tmp_path / "auth.py").read_text(encoding="utf-8")
    assert "postgres(" in body
    assert "postgres_url" in body
    assert "table_prefix=table_prefix" in body
    assert "table_suffix=table_suffix" in body
    assert "auth.mount(app)" in body


def test_init_can_write_mongo_scaffold(tmp_path: pathlib.Path) -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["init", "--backend", "mongo", "--path", str(tmp_path)])
    assert result.exit_code == 0

    body = (tmp_path / "auth.py").read_text(encoding="utf-8")
    assert "mongo(" in body
    assert "create_mongo_database(mongo_url: str, database_name: str)" in body
    assert "collection_prefix=collection_prefix" in body
    assert "collection_suffix=collection_suffix" in body


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
            "postgresql+asyncpg://localhost/fastauth",
        ],
    )
    assert result.exit_code == 1
    assert "Pass exactly one" in result.stdout


def test_migrate_passes_mongo_collection_affixes(monkeypatch: Any) -> None:
    calls: list[tuple[str, object]] = []

    class FakeClient:
        def __init__(self, url: str, **kwargs: object) -> None:
            calls.append(("client", (url, kwargs)))

        def __getitem__(self, database_name: str) -> str:
            return f"database:{database_name}"

        async def close(self) -> None:
            calls.append(("close", None))

    async def fake_init_beanie_documents(
        database: object,
        *,
        collection_prefix: str = "",
        collection_suffix: str = "",
    ) -> None:
        calls.append(
            (
                "init",
                (database, collection_prefix, collection_suffix),
            )
        )

    monkeypatch.setattr("pymongo.AsyncMongoClient", FakeClient)
    monkeypatch.setattr("fastauth.storage.beanie.init_beanie_documents", fake_init_beanie_documents)

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "migrate",
            "--mongo-url",
            "mongodb://localhost:27017",
            "--database",
            "app",
            "--mongo-collection-prefix",
            "tenant_",
            "--mongo-collection-suffix",
            "_auth",
        ],
    )

    assert result.exit_code == 0
    assert ("init", ("database:app", "tenant_", "_auth")) in calls
    assert ("close", None) in calls


def test_migrate_passes_postgres_table_suffix(monkeypatch: Any) -> None:
    calls: list[tuple[str, object]] = []

    class FakeEngine:
        async def dispose(self) -> None:
            calls.append(("dispose", None))

    class FakePostgresAdapter:
        engine = FakeEngine()

        @classmethod
        def from_url(
            cls,
            url: str,
            *,
            table_prefix: str = "fastauth_",
            table_suffix: str = "",
        ) -> FakePostgresAdapter:
            calls.append(("from_url", (url, table_prefix, table_suffix)))
            return cls()

        async def apply_migrations(self) -> list[int]:
            calls.append(("apply_migrations", None))
            return []

        async def schema_version(self) -> int:
            calls.append(("schema_version", None))
            return 1

    monkeypatch.setattr("fastauth.storage.postgres.PostgresAdapter", FakePostgresAdapter)

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "migrate",
            "--postgres-url",
            "postgresql+asyncpg://localhost/fastauth",
            "--postgres-table-prefix",
            "tenant_",
            "--postgres-table-suffix",
            "_auth",
        ],
    )

    assert result.exit_code == 0
    assert (
        "from_url",
        ("postgresql+asyncpg://localhost/fastauth", "tenant_", "_auth"),
    ) in calls
    assert ("dispose", None) in calls
