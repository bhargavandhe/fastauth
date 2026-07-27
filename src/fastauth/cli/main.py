"""Typer-based CLI for fastauth."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import pathlib
import secrets
import sys
import tomllib
from collections.abc import Mapping
from copy import deepcopy
from typing import Any, cast

import pydantic
import typer
from pydantic import SecretStr, ValidationError
from rich import print as rich_print

from fastauth.options import FastAuthOptions

__all__ = ["AUTH_SCAFFOLD", "AUTH_SCAFFOLDS", "app", "cli"]


app = typer.Typer(no_args_is_help=True, help="fastauth CLI")


MEMORY_AUTH_SCAFFOLD = '''\
"""Authkit instance for this application.

This scaffold demonstrates explicit dependency injection. Build your
``FastAuthOptions`` in your application code, then pass it to
``FastAuth``. fastauth never reads process-level configuration.
"""
from __future__ import annotations

from fastauth import FastAuth, FastAuthOptions
from fastauth.database import memory
from fastauth import email_password


def create_options(secret_key: str) -> FastAuthOptions:
    return FastAuthOptions(
        secret_key=secret_key,
        database=memory(),
    )


def build_auth(secret_key: str):
    return FastAuth(create_options(secret_key), plugins=[email_password()])
'''


MONGO_AUTH_SCAFFOLD = '''\
"""Mongo-backed fastauth instance for this application.

Build ``FastAuthOptions`` in your application code. The Mongo URL and database
name come from your own settings object; fastauth never reads process-level
configuration.
"""
from __future__ import annotations

from typing import Any

from pymongo import AsyncMongoClient
from pymongo.asynchronous.database import AsyncDatabase

from fastauth import FastAuth, FastAuthOptions
from fastauth.database import mongo
from fastauth import email_password
from fastauth.storage.beanie import init_beanie_documents


def create_mongo_database(mongo_url: str, database_name: str) -> AsyncDatabase[Any]:
    client: AsyncMongoClient[Any] = AsyncMongoClient(
        mongo_url,
        uuidRepresentation="standard",
    )
    return client[database_name]


def create_options(
    *,
    secret_key: str,
    database: AsyncDatabase[Any],
    collection_prefix: str = "",
    collection_suffix: str = "",
) -> FastAuthOptions:
    return FastAuthOptions(
        secret_key=secret_key,
        database=mongo(
            database=database,
            collection_prefix=collection_prefix,
            collection_suffix=collection_suffix,
        ),
    )


def build_auth(options: FastAuthOptions):
    return FastAuth(options, plugins=[email_password()])


async def init_auth_database(
    database: AsyncDatabase[Any],
    *,
    collection_prefix: str = "",
    collection_suffix: str = "",
) -> None:
    await init_beanie_documents(
        database,
        collection_prefix=collection_prefix,
        collection_suffix=collection_suffix,
    )
'''


POSTGRES_AUTH_SCAFFOLD = '''\
"""Postgres-backed fastauth instance for this application.

Build ``FastAuthOptions`` in your application code. The Postgres URL and table
prefix/suffix come from your own settings object; fastauth never reads
process-level configuration.
"""
from __future__ import annotations

from fastapi import FastAPI

from fastauth import FastAuth, FastAuthOptions
from fastauth.database import postgres
from fastauth import email_password


def create_options(
    *,
    secret_key: str,
    postgres_url: str,
    table_prefix: str = "fastauth_",
    table_suffix: str = "",
) -> FastAuthOptions:
    return FastAuthOptions(
        secret_key=secret_key,
        database=postgres(
            url=postgres_url,
            table_prefix=table_prefix,
            table_suffix=table_suffix,
        ),
    )


def create_app(options: FastAuthOptions) -> FastAPI:
    auth = FastAuth(options, plugins=[email_password()])
    app = FastAPI(lifespan=auth.lifespan)
    app.include_router(auth.router, prefix="/auth")
    auth.add_middleware(app)
    return app
'''


AUTH_SCAFFOLD = MEMORY_AUTH_SCAFFOLD
AUTH_SCAFFOLDS = {
    "memory": MEMORY_AUTH_SCAFFOLD,
    "mongo": MONGO_AUTH_SCAFFOLD,
    "postgres": POSTGRES_AUTH_SCAFFOLD,
}

CORE_STORAGE_NAMES = (
    "schema_migrations",
    "users",
    "sessions",
    "refresh_tokens",
    "accounts",
    "verifications",
    "api_keys",
    "jwks_keys",
    "audit_logs",
    "rate_limits",
)

MONGO_COLLECTION_NAMES = tuple(name for name in CORE_STORAGE_NAMES if name != "schema_migrations")

POSTGRES_DEFAULT_PREFIX = "fastauth_"


def prepare_options_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    prepared: dict[str, Any] = deepcopy(dict(payload))
    secret_key = prepared.get("secret_key")
    if isinstance(secret_key, str):
        prepared["secret_key"] = SecretStr(secret_key)

    rotation = prepared.get("secret_key_rotation")
    if isinstance(rotation, list):
        rotation_values = cast(list[Any], rotation)
        prepared["secret_key_rotation"] = [
            SecretStr(secret) if isinstance(secret, str) else secret for secret in rotation_values
        ]

    return prepared


def load_options_payload(path: pathlib.Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise typer.BadParameter(f"could not read config file: {exc}") from exc

    suffix = path.suffix.lower()
    try:
        if suffix == ".json":
            raw: object = json.loads(text)
        elif suffix == ".toml":
            raw = tomllib.loads(text)
        else:
            raise typer.BadParameter("config file must be JSON or TOML")
    except json.JSONDecodeError as exc:
        raise typer.BadParameter(f"invalid JSON: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise typer.BadParameter(f"invalid TOML: {exc}") from exc

    if not isinstance(raw, dict):
        raise typer.BadParameter("config root must be an object/table")

    loaded = cast(dict[str, Any], raw)
    candidate = loaded.get("fastauth")
    if isinstance(candidate, dict):
        loaded = cast(dict[str, Any], candidate)

    return prepare_options_payload(loaded)


def load_options(path: pathlib.Path) -> FastAuthOptions:
    return FastAuthOptions.model_validate(load_options_payload(path))


def default_options() -> FastAuthOptions:
    return FastAuthOptions(secret_key=SecretStr("x" * 64))


def options_summary(options: FastAuthOptions) -> dict[str, Any]:
    database = options.database
    summary: dict[str, Any] = {
        "deployment": options.deployment,
        "database": {
            "kind": database.kind,
        },
        "app": {
            "name": options.app.name,
            "base_url": str(options.app.base_url),
            "base_path": options.app.base_path,
        },
        "session": {
            "strategy": options.session.strategy.value,
            "max_age_seconds": options.session.max_age_seconds,
            "idle_timeout_seconds": options.session.idle_timeout_seconds,
        },
        "cookie": {
            "name": options.cookie.name,
            "secure": options.cookie.secure,
            "same_site": options.cookie.same_site,
        },
        "security": {
            "csrf_enabled": options.csrf.enabled,
            "rate_limit_enabled": options.rate_limit.enabled,
            "lockout_enabled": options.lockout.enabled,
            "refresh_tokens_enabled": options.refresh_token.enabled,
        },
    }
    if database.kind == "postgres":
        summary["database"].update(
            {
                "table_prefix": database.table_prefix,
                "table_suffix": database.table_suffix,
                "migration_mode": database.migration_mode,
            }
        )
    elif database.kind == "mongo":
        summary["database"].update(
            {
                "collection_prefix": database.collection_prefix,
                "collection_suffix": database.collection_suffix,
            }
        )
    return summary


def print_options_summary(summary: Mapping[str, Any]) -> None:
    rich_print("FastAuthOptions")
    rich_print(f"deployment: {summary['deployment']}")
    database = summary["database"]
    rich_print(f"database: {database['kind']}")
    for key in ("table_prefix", "table_suffix", "migration_mode"):
        if key in database:
            rich_print(f"database.{key}: {database[key]}")
    for key in ("collection_prefix", "collection_suffix"):
        if key in database:
            rich_print(f"database.{key}: {database[key]}")
    app_summary = summary["app"]
    rich_print(f"app: {app_summary['name']} {app_summary['base_url']}{app_summary['base_path']}")
    session = summary["session"]
    rich_print(
        "session: "
        f"{session['strategy']} max_age={session['max_age_seconds']}s "
        f"idle_timeout={session['idle_timeout_seconds']}"
    )
    cookie = summary["cookie"]
    rich_print(
        f"cookie: {cookie['name']} secure={cookie['secure']} same_site={cookie['same_site']}"
    )
    security = summary["security"]
    rich_print(
        "security: "
        f"csrf={security['csrf_enabled']} rate_limit={security['rate_limit_enabled']} "
        f"lockout={security['lockout_enabled']} refresh_tokens={security['refresh_tokens_enabled']}"
    )


def package_status(package: str) -> str:
    return "installed" if importlib.util.find_spec(package) is not None else "not installed"


def postgres_table_plan(table_prefix: str, table_suffix: str) -> list[tuple[str, int, int]]:
    from fastauth.storage.postgres.schema import build_postgres_schema

    schema = build_postgres_schema(table_prefix=table_prefix, table_suffix=table_suffix)
    return [
        (table.name, len(table.columns), len(table.indexes))
        for table in schema.metadata.sorted_tables
    ]


def mongo_collection_name(base_name: str, collection_prefix: str, collection_suffix: str) -> str:
    name = f"{collection_prefix}{base_name}{collection_suffix}"
    if not name or "\x00" in name or "$" in name or name.startswith("system."):
        raise typer.BadParameter(f"invalid MongoDB collection name: {name!r}")
    return name


def print_postgres_schema_plan(table_prefix: str, table_suffix: str) -> None:
    from fastauth.storage.postgres.migrations import CURRENT_SCHEMA_VERSION, POSTGRES_MIGRATIONS

    rich_print("Backend: postgres")
    rich_print(f"Current schema version: {CURRENT_SCHEMA_VERSION}")
    rich_print("Tables:")
    for table_name, column_count, index_count in postgres_table_plan(table_prefix, table_suffix):
        rich_print(f"  - {table_name} ({column_count} columns, {index_count} indexes)")
    rich_print("Migrations:")
    for migration in POSTGRES_MIGRATIONS:
        rich_print(f"  - {migration.version}: {migration.description}")


def print_mongo_schema_plan(collection_prefix: str, collection_suffix: str) -> None:
    rich_print("Backend: mongo")
    rich_print("Tracked migrations: none")
    rich_print("Collections:")
    for base_name in MONGO_COLLECTION_NAMES:
        rich_print(f"  - {mongo_collection_name(base_name, collection_prefix, collection_suffix)}")
    rich_print("Startup action: ensure Beanie documents and indexes")


@app.command("info")
def info_command() -> None:
    """Print local fastauth package and optional dependency information."""
    from fastauth import __version__

    rich_print(f"fastauth: {__version__}")
    rich_print(f"python: {sys.version.split()[0]}")
    rich_print(f"pydantic: {pydantic.__version__}")
    rich_print(f"typer: {typer.__version__}")
    rich_print("optional dependencies:")
    rich_print(f"  beanie: {package_status('beanie')}")
    rich_print(f"  pymongo: {package_status('pymongo')}")
    rich_print(f"  sqlalchemy: {package_status('sqlalchemy')}")
    rich_print(f"  asyncpg: {package_status('asyncpg')}")


@app.command("inspect")
def inspect_command(
    config: pathlib.Path | None = typer.Argument(  # noqa: B008
        None,
        help="Optional JSON/TOML config file",
    ),
    output: str = typer.Option("text", "--output", "-o", help="Output format: text or json"),
) -> None:
    """Inspect default options or a validated JSON/TOML FastAuthOptions config."""
    output_key = output.lower()
    if output_key not in {"text", "json"}:
        rich_print("[red]--output must be text or json[/red]")
        raise typer.Exit(code=1)

    try:
        options = default_options() if config is None else load_options(config)
    except (typer.BadParameter, ValidationError) as exc:
        rich_print(f"[red]config invalid: {exc}[/red]")
        raise typer.Exit(code=1) from exc

    summary = options_summary(options)
    if output_key == "json":
        typer.echo(json.dumps(summary, indent=2, sort_keys=True))
        return
    print_options_summary(summary)


@app.command("config-check")
def config_check_command(
    config: pathlib.Path = typer.Argument(  # noqa: B008
        ...,
        help="JSON/TOML config file to validate",
    ),
) -> None:
    """Validate a JSON/TOML file against FastAuthOptions."""
    try:
        options = load_options(config)
    except typer.BadParameter as exc:
        rich_print(f"[red]config invalid: {exc}[/red]")
        raise typer.Exit(code=1) from exc
    except ValidationError as exc:
        rich_print("[red]config invalid[/red]")
        for error in exc.errors(include_input=False):
            location = ".".join(str(part) for part in error["loc"])
            rich_print(f"  - {location}: {error['msg']}")
        raise typer.Exit(code=1) from exc

    rich_print("[green]config valid[/green]")
    rich_print(f"deployment: {options.deployment}")
    rich_print(f"database: {options.database.kind}")


@app.command("schema-plan")
def schema_plan_command(
    backend: str = typer.Option("postgres", "--backend", "-b", help="Backend: postgres or mongo"),
    table_prefix: str = typer.Option(
        POSTGRES_DEFAULT_PREFIX,
        "--postgres-table-prefix",
        help="Table prefix for Postgres schema names",
    ),
    table_suffix: str = typer.Option(
        "",
        "--postgres-table-suffix",
        help="Table suffix for Postgres schema names",
    ),
    collection_prefix: str = typer.Option(
        "",
        "--mongo-collection-prefix",
        help="Prefix for MongoDB collection names",
    ),
    collection_suffix: str = typer.Option(
        "",
        "--mongo-collection-suffix",
        help="Suffix for MongoDB collection names",
    ),
) -> None:
    """Print the database objects fastauth expects for a backend."""
    backend_key = backend.lower()
    if backend_key == "postgres":
        print_postgres_schema_plan(table_prefix, table_suffix)
        return
    if backend_key == "mongo":
        print_mongo_schema_plan(collection_prefix, collection_suffix)
        return

    rich_print("[red]--backend must be postgres or mongo[/red]")
    raise typer.Exit(code=1)


@app.command("migrate-dry-run")
def migrate_dry_run_command(
    backend: str = typer.Option("postgres", "--backend", "-b", help="Backend: postgres or mongo"),
    current_version: int = typer.Option(
        0,
        "--current-version",
        min=0,
        help="Current tracked Postgres schema version",
    ),
    table_prefix: str = typer.Option(
        POSTGRES_DEFAULT_PREFIX,
        "--postgres-table-prefix",
        help="Table prefix for Postgres schema names",
    ),
    table_suffix: str = typer.Option(
        "",
        "--postgres-table-suffix",
        help="Table suffix for Postgres schema names",
    ),
    collection_prefix: str = typer.Option(
        "",
        "--mongo-collection-prefix",
        help="Prefix for MongoDB collection names",
    ),
    collection_suffix: str = typer.Option(
        "",
        "--mongo-collection-suffix",
        help="Suffix for MongoDB collection names",
    ),
) -> None:
    """Show migration work that would run, without opening a database connection."""
    backend_key = backend.lower()
    if backend_key == "postgres":
        from fastauth.storage.postgres.migrations import pending_postgres_migrations

        try:
            pending = pending_postgres_migrations(current_version)
        except RuntimeError as exc:
            rich_print(f"[red]{exc}[/red]")
            raise typer.Exit(code=1) from exc

        rich_print("Backend: postgres")
        rich_print(f"Current database version: {current_version}")
        if not pending:
            rich_print("[green]No pending migrations[/green]")
        else:
            rich_print("Pending migrations:")
            for migration in pending:
                rich_print(f"  - {migration.version}: {migration.description}")
        rich_print("Tables that migrations target:")
        for table_name, _, _ in postgres_table_plan(table_prefix, table_suffix):
            rich_print(f"  - {table_name}")
        return

    if backend_key == "mongo":
        rich_print("Backend: mongo")
        rich_print("Tracked migrations: none")
        rich_print("Would ensure collections and indexes:")
        for base_name in MONGO_COLLECTION_NAMES:
            collection_name = mongo_collection_name(base_name, collection_prefix, collection_suffix)
            rich_print(f"  - {collection_name}")
        return

    rich_print("[red]--backend must be postgres or mongo[/red]")
    raise typer.Exit(code=1)


@app.command("init")
def init_command(
    path: pathlib.Path = typer.Option(pathlib.Path("."), "--path", "-p"),  # noqa: B008
    backend: str = typer.Option(
        "memory",
        "--backend",
        "-b",
        help="Scaffold backend: memory, mongo, or postgres",
    ),
) -> None:
    """Scaffold an ``auth.py`` showing explicit FastAuthOptions construction."""
    backend_key = backend.lower()
    if backend_key not in AUTH_SCAFFOLDS:
        rich_print("[red]--backend must be one of: memory, mongo, postgres[/red]")
        raise typer.Exit(code=1)
    path.mkdir(parents=True, exist_ok=True)
    (path / "auth.py").write_text(AUTH_SCAFFOLDS[backend_key], encoding="utf-8")
    rich_print(f"[green]wrote auth.py to {path}[/green]")


@app.command("migrate")
def migrate_command(
    mongo_url: str | None = typer.Option(None, "--mongo-url", "-m", help="MongoDB connection URL"),
    postgres_url: str | None = typer.Option(
        None,
        "--postgres-url",
        help="Postgres connection URL, for example postgresql+asyncpg://...",
    ),
    database: str = typer.Option(
        "fastauth",
        "--database",
        "-d",
        help="MongoDB database name",
    ),
    mongo_collection_prefix: str = typer.Option(
        "",
        "--mongo-collection-prefix",
        help="Prefix for MongoDB collection names",
    ),
    mongo_collection_suffix: str = typer.Option(
        "",
        "--mongo-collection-suffix",
        help="Suffix for MongoDB collection names",
    ),
    postgres_table_prefix: str = typer.Option(
        "fastauth_",
        "--postgres-table-prefix",
        help="Table prefix for Postgres schema creation",
    ),
    postgres_table_suffix: str = typer.Option(
        "",
        "--postgres-table-suffix",
        help="Table suffix for Postgres schema creation",
    ),
) -> None:
    """Initialise database schema/indexes for fastauth storage adapters.

    Connection details are passed via CLI flags. fastauth does not read
    them from the environment.
    """
    selected_backends = [mongo_url is not None, postgres_url is not None]
    if sum(selected_backends) != 1:
        rich_print("[red]Pass exactly one of --mongo-url or --postgres-url[/red]")
        raise typer.Exit(code=1)

    async def run() -> None:
        if mongo_url is not None:
            from pymongo import AsyncMongoClient

            from fastauth.storage.beanie import init_beanie_documents

            client: AsyncMongoClient[Any] = AsyncMongoClient(
                mongo_url, uuidRepresentation="standard"
            )
            try:
                await init_beanie_documents(
                    client[database],
                    collection_prefix=mongo_collection_prefix,
                    collection_suffix=mongo_collection_suffix,
                )
                rich_print("[green]indexes ensured on every fastauth collection[/green]")
            finally:
                await client.close()
            return

        from fastauth.storage.postgres import PostgresAdapter

        assert postgres_url is not None
        adapter = PostgresAdapter.from_url(
            postgres_url,
            table_prefix=postgres_table_prefix,
            table_suffix=postgres_table_suffix,
        )
        try:
            applied = await adapter.apply_migrations()
            version = await adapter.schema_version()
            if applied:
                rich_print(f"[green]Postgres migrations applied: {applied}[/green]")
            else:
                rich_print("[green]Postgres schema already current[/green]")
            rich_print(f"[green]Postgres fastauth schema version: {version}[/green]")
        finally:
            await adapter.engine.dispose()

    asyncio.run(run())


@app.command("generate-secret")
def generate_secret_command() -> None:
    """Print a fresh 64-char URL-safe secret."""
    rich_print(secrets.token_urlsafe(48))


def cli() -> None:
    app()
