"""Shared fixtures: Mongo testcontainer + ready-to-use Beanie database."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from typing import Any

import pytest
from pymongo import AsyncMongoClient
from pymongo.asynchronous.database import AsyncDatabase
from testcontainers.mongodb import MongoDbContainer  # pyright: ignore[reportMissingTypeStubs]

from fastauth.storage.beanie import init_beanie_documents


@pytest.fixture(scope="session")
def mongo_url() -> str:
    external_url = os.environ.get("FASTAUTH_TEST_MONGO_URL")
    if external_url:
        return external_url
    try:
        container = MongoDbContainer("mongo:7")
        container.start()
    except Exception as exc:
        if os.environ.get("FASTAUTH_REQUIRE_DATABASES") == "1":
            pytest.fail(f"Required real database unavailable: {exc}")
        pytest.skip(f"Docker is required for Beanie adapter tests: {exc}")
    url = container.get_connection_url()

    def stop_container() -> None:
        container.stop()

    import atexit

    atexit.register(stop_container)
    return url


@pytest.fixture
async def beanie_database(mongo_url: str) -> AsyncIterator[AsyncDatabase[Any]]:
    client: AsyncMongoClient[Any] = AsyncMongoClient(
        mongo_url,
        uuidRepresentation="standard",
        tz_aware=True,
    )
    database_name = "fastauth_test"
    database = client[database_name]
    await init_beanie_documents(database)
    yield database
    await client.drop_database(database_name)
    await client.close()
