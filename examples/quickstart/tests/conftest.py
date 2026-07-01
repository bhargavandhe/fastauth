"""Fixtures for the quickstart example app's end-to-end test.

The example app is configured by passing ``FastAuthOptions`` into its factory.
This conftest starts a session-scoped Mongo container, then creates a fresh
PyMongo async client inside each async test fixture so the client binds to the
same event loop as FastAPI and httpx.

The conftest also drives the FastAPI lifespan manually around each request,
because ``httpx.ASGITransport`` does not emit lifespan events on its own and
the JwtPlugin relies on ``lifespan_startup`` to provision its JWKS key.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator, Iterator

import httpx
import pytest
from pydantic import SecretStr
from pymongo import AsyncMongoClient
from testcontainers.mongodb import MongoDbContainer  # pyright: ignore[reportMissingTypeStubs]

from examples.quickstart.app import build_options, create_app, create_auth


@pytest.fixture(scope="session")
def mongo_url() -> Iterator[str]:
    try:
        container = MongoDbContainer("mongo:7")
        container.start()
    except Exception as exc:
        pytest.skip(f"Docker is required for quickstart tests: {exc}")

    yield container.get_connection_url()

    container.stop()


@pytest.fixture
async def client(mongo_url: str) -> AsyncIterator[httpx.AsyncClient]:
    """Yield a fresh ``httpx.AsyncClient`` bound to the example FastAPI app.

    The PyMongo async client is created inside this async fixture so it binds to
    the same event loop used by ``httpx.AsyncClient`` and FastAPI lifespan.
    """
    database_name = f"fastauth_quickstart_{os.getpid()}"
    mongo_client: AsyncMongoClient[object] = AsyncMongoClient(
        mongo_url,
        uuidRepresentation="standard",
        tz_aware=True,
    )
    mongo_database = mongo_client[database_name]
    options = build_options(
        secret_key=SecretStr("x" * 64),
        database=mongo_database,
        cookie_secure=False,
        csrf_enabled=False,
        rate_limit_enabled=False,
    )
    auth = create_auth(options)
    app = create_app(auth)
    try:
        await mongo_client.drop_database(database_name)
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://testserver",
            ) as http:
                yield http
    finally:
        await mongo_client.drop_database(database_name)
        await mongo_client.close()
