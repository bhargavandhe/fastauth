"""Fixtures for the quickstart example app's end-to-end test.

The example app is configured by passing an ``AuthKitConfig`` directly into
its factory. This conftest creates a per-process Mongo database and passes the
test config object explicitly.

The conftest also drives the FastAPI lifespan manually around each request,
because ``httpx.ASGITransport`` does not emit lifespan events on its own and
the JwtPlugin relies on ``lifespan_startup`` to provision its JWKS key.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator, Iterator

import httpx
import pytest
from fastapi import FastAPI
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from pydantic import SecretStr
from testcontainers.mongodb import MongoDbContainer  # pyright: ignore[reportMissingTypeStubs]

from examples.quickstart.app import build_config, create_app, create_auth


@pytest.fixture(scope="session")
def quickstart_runtime() -> Iterator[tuple[FastAPI, AsyncIOMotorDatabase[object]]]:
    try:
        container = MongoDbContainer("mongo:7")
        container.start()
    except Exception as exc:
        pytest.skip(f"Docker is required for quickstart tests: {exc}")

    mongo_url = container.get_connection_url()
    database_name = f"authkit_quickstart_{os.getpid()}"
    config = build_config(
        secret_key=SecretStr("x" * 64),
        mongo_url=mongo_url,
        database_name=database_name,
        cookie_secure=False,
        csrf_enabled=False,
        rate_limit_enabled=False,
    )
    mongo_client: AsyncIOMotorClient[object] = AsyncIOMotorClient(
        config.database.mongo_url,
        uuidRepresentation="standard",
        tz_aware=True,
    )
    mongo_database: AsyncIOMotorDatabase[object] = mongo_client[config.database.database_name]
    auth = create_auth(config, mongo_database)
    app = create_app(auth, mongo_database)
    try:
        yield app, mongo_database
    finally:
        mongo_client.close()
        container.stop()


@pytest.fixture
async def client(
    quickstart_runtime: tuple[FastAPI, AsyncIOMotorDatabase[object]],
) -> AsyncIterator[httpx.AsyncClient]:
    """Yield a fresh ``httpx.AsyncClient`` bound to the example FastAPI app.

    Wipes every collection before the test runs so each call to this fixture
    sees an empty database. The AuthKit lifespan (and therefore the JWKS
    key-provisioning hook) is driven manually because ``ASGITransport`` does
    not emit lifespan events.
    """
    app, mongo_database = quickstart_runtime
    for name in await mongo_database.list_collection_names():
        await mongo_database[name].delete_many({})
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as http:
            yield http
