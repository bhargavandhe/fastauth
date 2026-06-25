"""Typer-based CLI for authkit."""

from __future__ import annotations

import asyncio
import pathlib
import secrets
from typing import Any

import typer
from rich import print as rich_print

__all__ = ["AUTH_SCAFFOLD", "app", "cli"]


app = typer.Typer(no_args_is_help=True, help="authkit CLI")


AUTH_SCAFFOLD = '''\
"""Authkit instance for this application.

This scaffold demonstrates explicit dependency injection. Build your
``AuthKitConfig`` and database connection in your application code, then pass
them to ``create_auth``. authkit never reads process-level configuration.
"""
from __future__ import annotations

from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from authkit import AuthKit, AuthKitConfig
from authkit.storage.beanie import BeanieAdapter, init_beanie_documents


def create_auth(
    config: AuthKitConfig,
    database: AsyncIOMotorDatabase[Any],
) -> AuthKit:
    return AuthKit(config, adapter=BeanieAdapter(database))


async def init_auth_database(database: AsyncIOMotorDatabase[Any]) -> None:
    await init_beanie_documents(database)
'''


@app.command("init")
def init_command(
    path: pathlib.Path = typer.Option(pathlib.Path("."), "--path", "-p"),  # noqa: B008
) -> None:
    """Scaffold an ``auth.py`` showing explicit AuthKitConfig construction."""
    path.mkdir(parents=True, exist_ok=True)
    (path / "auth.py").write_text(AUTH_SCAFFOLD, encoding="utf-8")
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
            await adapter.create_schema()
            rich_print("[green]Postgres schema ensured for authkit tables[/green]")
        finally:
            await adapter.engine.dispose()

    asyncio.run(run())


@app.command("generate-secret")
def generate_secret_command() -> None:
    """Print a fresh 64-char URL-safe secret."""
    rich_print(secrets.token_urlsafe(48))


def cli() -> None:
    app()
