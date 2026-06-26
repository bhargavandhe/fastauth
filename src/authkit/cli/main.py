"""Typer-based CLI for authkit."""

from __future__ import annotations

import asyncio
import pathlib
import secrets
from typing import Any

import typer
from rich import print as rich_print

__all__ = ["AUTH_SCAFFOLD", "AUTH_SCAFFOLDS", "app", "cli"]


app = typer.Typer(no_args_is_help=True, help="authkit CLI")


MEMORY_AUTH_SCAFFOLD = '''\
"""Authkit instance for this application.

This scaffold demonstrates explicit dependency injection. Build your
``AuthKitConfig`` in your application code, then pass it to ``create_auth``.
authkit never reads process-level configuration.
"""
from __future__ import annotations

from authkit import AuthKit, AuthKitConfig
from authkit.storage.memory import InMemoryAdapter


def create_auth(config: AuthKitConfig) -> AuthKit:
    return AuthKit(config, adapter=InMemoryAdapter())
'''


MONGO_AUTH_SCAFFOLD = '''\
"""Mongo-backed authkit instance for this application.

Build ``AuthKitConfig`` in your application code. The Mongo URL and database
name come from ``config.database.mongo``; authkit never reads process-level
configuration.
"""
from __future__ import annotations

from typing import Any

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase

from authkit import AuthKit, AuthKitConfig
from authkit.storage.beanie import BeanieAdapter, init_beanie_documents


def create_mongo_database(config: AuthKitConfig) -> AsyncIOMotorDatabase[Any]:
    client: AsyncIOMotorClient[Any] = AsyncIOMotorClient(
        config.database.mongo.url,
        uuidRepresentation="standard",
    )
    return client[config.database.mongo.database_name]


def create_auth(
    config: AuthKitConfig,
    database: AsyncIOMotorDatabase[Any],
) -> AuthKit:
    return AuthKit(config, adapter=BeanieAdapter(database))


async def init_auth_database(database: AsyncIOMotorDatabase[Any]) -> None:
    await init_beanie_documents(database)
'''


POSTGRES_AUTH_SCAFFOLD = '''\
"""Postgres-backed authkit instance for this application.

Build ``AuthKitConfig`` in your application code. The Postgres URL and table
prefix come from ``config.database.postgres``; authkit never reads
process-level configuration.
"""
from __future__ import annotations

from fastapi import FastAPI

from authkit import AuthKit, AuthKitConfig
from authkit.storage.postgres import PostgresAdapter


def create_auth(config: AuthKitConfig) -> AuthKit:
    adapter = PostgresAdapter.from_url(
        config.database.postgres.url,
        table_prefix=config.database.postgres.table_prefix,
    )
    return AuthKit(config, adapter=adapter)


def create_app(config: AuthKitConfig) -> FastAPI:
    auth = create_auth(config)
    adapter = auth.context.adapter
    if not isinstance(adapter, PostgresAdapter):
        raise RuntimeError("expected PostgresAdapter")
    app = FastAPI(lifespan=adapter.checked_lifespan(auth))
    auth.install(app)
    return app
'''


AUTH_SCAFFOLD = MEMORY_AUTH_SCAFFOLD
AUTH_SCAFFOLDS = {
    "memory": MEMORY_AUTH_SCAFFOLD,
    "mongo": MONGO_AUTH_SCAFFOLD,
    "postgres": POSTGRES_AUTH_SCAFFOLD,
}


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
    """Scaffold an ``auth.py`` showing explicit AuthKitConfig construction."""
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
        "authkit",
        "--database",
        "-d",
        help="MongoDB database name",
    ),
    postgres_table_prefix: str = typer.Option(
        "authkit_",
        "--postgres-table-prefix",
        help="Table prefix for Postgres schema creation",
    ),
) -> None:
    """Initialise database schema/indexes for authkit storage adapters.

    Connection details are passed via CLI flags. authkit does not read
    them from the environment.
    """
    selected_backends = [mongo_url is not None, postgres_url is not None]
    if sum(selected_backends) != 1:
        rich_print("[red]Pass exactly one of --mongo-url or --postgres-url[/red]")
        raise typer.Exit(code=1)

    async def run() -> None:
        if mongo_url is not None:
            from motor.motor_asyncio import AsyncIOMotorClient

            from authkit.storage.beanie import init_beanie_documents

            client: AsyncIOMotorClient[Any] = AsyncIOMotorClient(
                mongo_url, uuidRepresentation="standard"
            )
            try:
                await init_beanie_documents(client[database])
                rich_print("[green]indexes ensured on every authkit collection[/green]")
            finally:
                client.close()
            return

        from authkit.storage.postgres import PostgresAdapter

        assert postgres_url is not None
        adapter = PostgresAdapter.from_url(postgres_url, table_prefix=postgres_table_prefix)
        try:
            applied = await adapter.apply_migrations()
            version = await adapter.schema_version()
            if applied:
                rich_print(f"[green]Postgres migrations applied: {applied}[/green]")
            else:
                rich_print("[green]Postgres schema already current[/green]")
            rich_print(f"[green]Postgres authkit schema version: {version}[/green]")
        finally:
            await adapter.engine.dispose()

    asyncio.run(run())


@app.command("generate-secret")
def generate_secret_command() -> None:
    """Print a fresh 64-char URL-safe secret."""
    rich_print(secrets.token_urlsafe(48))


def cli() -> None:
    app()
