"""Typer-based CLI for fastauth."""

from __future__ import annotations

import asyncio
import pathlib
import secrets
from typing import Any

import typer
from rich import print as rich_print

__all__ = ["AUTH_SCAFFOLD", "AUTH_SCAFFOLDS", "app", "cli"]


app = typer.Typer(no_args_is_help=True, help="fastauth CLI")


MEMORY_AUTH_SCAFFOLD = '''\
"""Authkit instance for this application.

This scaffold demonstrates explicit dependency injection. Build your
``FastAuthConfig`` in your application code, then pass it to ``create_auth``.
fastauth never reads process-level configuration.
"""
from __future__ import annotations

from fastauth import FastAuth, FastAuthConfig
from fastauth.storage.memory import InMemoryAdapter


def create_auth(config: FastAuthConfig) -> FastAuth:
    return FastAuth(config, adapter=InMemoryAdapter())
'''


MONGO_AUTH_SCAFFOLD = '''\
"""Mongo-backed fastauth instance for this application.

Build ``FastAuthConfig`` in your application code. The Mongo URL and database
name come from ``config.database.mongo``; fastauth never reads process-level
configuration.
"""
from __future__ import annotations

from typing import Any

from pymongo import AsyncMongoClient
from pymongo.asynchronous.database import AsyncDatabase

from fastauth import FastAuth, FastAuthConfig
from fastauth.storage.beanie import BeanieAdapter, init_beanie_documents


def create_mongo_database(config: FastAuthConfig) -> AsyncDatabase[Any]:
    client: AsyncMongoClient[Any] = AsyncMongoClient(
        config.database.mongo.url,
        uuidRepresentation="standard",
    )
    return client[config.database.mongo.database_name]


def create_auth(
    config: FastAuthConfig,
    database: AsyncDatabase[Any],
) -> FastAuth:
    return FastAuth(
        config,
        adapter=BeanieAdapter(
            database,
            collection_prefix=config.database.mongo.collection_prefix,
            collection_suffix=config.database.mongo.collection_suffix,
        ),
    )


async def init_auth_database(config: FastAuthConfig, database: AsyncDatabase[Any]) -> None:
    await init_beanie_documents(
        database,
        collection_prefix=config.database.mongo.collection_prefix,
        collection_suffix=config.database.mongo.collection_suffix,
    )
'''


POSTGRES_AUTH_SCAFFOLD = '''\
"""Postgres-backed fastauth instance for this application.

Build ``FastAuthConfig`` in your application code. The Postgres URL and table
prefix/suffix come from ``config.database.postgres``; fastauth never reads
process-level configuration.
"""
from __future__ import annotations

from fastapi import FastAPI

from fastauth import FastAuth, FastAuthConfig
from fastauth.storage.postgres import PostgresAdapter


def create_auth(config: FastAuthConfig) -> FastAuth:
    adapter = PostgresAdapter.from_url(
        config.database.postgres.url,
        table_prefix=config.database.postgres.table_prefix,
        table_suffix=config.database.postgres.table_suffix,
    )
    return FastAuth(config, adapter=adapter)


def create_app(config: FastAuthConfig) -> FastAPI:
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
    """Scaffold an ``auth.py`` showing explicit FastAuthConfig construction."""
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
