from __future__ import annotations

import json
import pathlib
from typing import Any

from typer.testing import CliRunner

from fastauth.cli.main import app


def test_generate_secret_prints_64_chars() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["generate-secret"])
    assert result.exit_code == 0
    assert len(result.stdout.strip()) >= 64


def test_info_prints_versions_and_optional_dependency_status() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["info"])

    assert result.exit_code == 0
    assert "fastauth:" in result.stdout
    assert "python:" in result.stdout
    assert "pydantic:" in result.stdout
    assert "optional dependencies:" in result.stdout
    assert "sqlalchemy:" in result.stdout


def test_maintenance_runs_bounded_cleanup_and_prints_json() -> None:
    runner = CliRunner()

    result = runner.invoke(
        app,
        ["maintenance", "--backend", "memory", "--batch-size", "25", "--max-batches", "2"],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload == {
        "deletedApiKeys": 0,
        "deletedAuditLogs": 0,
        "deletedRefreshTokens": 0,
        "deletedSessions": 0,
        "deletedVerifications": 0,
        "failures": [],
        "ok": True,
    }


def test_inspect_prints_default_options_summary() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["inspect"])

    assert result.exit_code == 0
    assert "FastAuthOptions" in result.stdout
    assert "deployment: development" in result.stdout
    assert "database: memory" in result.stdout
    assert "session: database" in result.stdout


def test_inspect_can_render_valid_config_as_json(tmp_path: pathlib.Path) -> None:
    config = tmp_path / "fastauth.json"
    config.write_text(
        json.dumps(
            {
                "secret_key": "a" * 64,
                "session": {"expires_in": "2h"},
                "cookie": {"same_site": "strict"},
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(app, ["inspect", str(config), "--output", "json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["deployment"] == "development"
    assert payload["database"]["kind"] == "memory"
    assert payload["session"]["max_age_seconds"] == 7200
    assert payload["cookie"]["same_site"] == "strict"


def test_config_check_validates_json_config(tmp_path: pathlib.Path) -> None:
    config = tmp_path / "fastauth.json"
    config.write_text(
        json.dumps(
            {
                "secret_key": "b" * 64,
                "session": {"expires_in": 1800},
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(app, ["config-check", str(config)])

    assert result.exit_code == 0
    assert "config valid" in result.stdout
    assert "database: memory" in result.stdout


def test_config_check_validates_toml_fastauth_table(tmp_path: pathlib.Path) -> None:
    config = tmp_path / "fastauth.toml"
    config.write_text(
        """
[fastauth]
secret_key = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

[fastauth.session]
expires_in = "45m"
""".strip(),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(app, ["config-check", str(config)])

    assert result.exit_code == 0
    assert "config valid" in result.stdout


def test_config_check_reports_validation_errors(tmp_path: pathlib.Path) -> None:
    config = tmp_path / "fastauth.json"
    config.write_text(
        json.dumps(
            {
                "secret_key": "short",
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(app, ["config-check", str(config)])

    assert result.exit_code == 1
    assert "config invalid" in result.stdout
    assert "secret_key must contain at least 32 bytes" in result.stdout


def test_schema_plan_prints_postgres_tables_and_migrations() -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "schema-plan",
            "--backend",
            "postgres",
            "--postgres-table-prefix",
            "tenant_",
            "--postgres-table-suffix",
            "_auth",
        ],
    )

    assert result.exit_code == 0
    assert "Backend: postgres" in result.stdout
    assert "tenant_users_auth" in result.stdout
    assert "Current schema version:" in result.stdout
    assert "initial fastauth schema" in result.stdout


def test_schema_plan_prints_mongo_collections() -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "schema-plan",
            "--backend",
            "mongo",
            "--mongo-collection-prefix",
            "tenant_",
            "--mongo-collection-suffix",
            "_auth",
        ],
    )

    assert result.exit_code == 0
    assert "Backend: mongo" in result.stdout
    assert "tenant_users_auth" in result.stdout
    assert "Startup action: ensure Beanie documents and indexes" in result.stdout


def test_migrate_dry_run_prints_pending_postgres_migrations() -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["migrate-dry-run", "--backend", "postgres", "--current-version", "1"],
    )

    assert result.exit_code == 0
    assert "Pending migrations:" in result.stdout
    assert "2: link refresh tokens to sessions" in result.stdout
    assert "3: preserve refresh token evidence" in result.stdout
    assert "fastauth_users" in result.stdout


def test_migrate_dry_run_rejects_newer_postgres_schema() -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["migrate-dry-run", "--backend", "postgres", "--current-version", "99"],
    )

    assert result.exit_code == 1
    assert "schema is newer than this fastauth version" in result.stdout


def test_migrate_dry_run_prints_mongo_plan() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["migrate-dry-run", "--backend", "mongo"])

    assert result.exit_code == 0
    assert "Backend: mongo" in result.stdout
    assert "Tracked migrations: none" in result.stdout
    assert "users" in result.stdout


def test_migrate_dry_run_prints_executable_plugin_plan(
    tmp_path: pathlib.Path,
    monkeypatch: Any,
) -> None:
    module = tmp_path / "plugin_auth.py"
    module.write_text(
        """
from pydantic import SecretStr
from fastauth import FastAuth, FastAuthOptions
from fastauth.plugins import FieldSpec, MigrationSpec, Plugin, PluginSchema, TableSpec

class RecordsPlugin(Plugin):
    id = "records"
    def schemas(self):
        return [PluginSchema(
            plugin_id=self.id,
            tables=(TableSpec(
                name="records",
                fields=(FieldSpec(name="id", python_type="str"),),
            ),),
            migrations=(MigrationSpec(name="create_records", version=1),),
        )]

auth = FastAuth(
    FastAuthOptions(secret_key=SecretStr("x" * 64)),
    plugins=[RecordsPlugin()],
)
""",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))

    result = CliRunner().invoke(
        app,
        [
            "migrate-dry-run",
            "--backend",
            "postgres",
            "--auth",
            "plugin_auth:auth",
            "--plugin-migrations",
            "check",
        ],
    )

    assert result.exit_code == 0
    assert "Plugin migrations: check" in result.stdout
    assert "create_table: records records" in result.stdout
    assert "record_migration: records create_records" in result.stdout


def test_migrate_rejects_unknown_plugin_migration_mode() -> None:
    result = CliRunner().invoke(
        app,
        [
            "migrate-dry-run",
            "--plugin-migrations",
            "sometimes",
        ],
    )

    assert result.exit_code == 2
    assert "must be apply, check, or disabled" in result.stderr


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
    assert "FastAuth(" in body
    assert "plugins=[email_password()]" in body
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
    assert "url=postgres_url" in body
    assert "postgres_url" in body
    assert "table_prefix=table_prefix" in body
    assert "table_suffix=table_suffix" in body
    assert 'app.include_router(auth.router, prefix="/auth")' in body
    assert "auth.add_middleware(app)" in body


def test_init_can_write_mongo_scaffold(tmp_path: pathlib.Path) -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["init", "--backend", "mongo", "--path", str(tmp_path)])
    assert result.exit_code == 0

    body = (tmp_path / "auth.py").read_text(encoding="utf-8")
    assert "mongo(" in body
    assert "database=database" in body
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
