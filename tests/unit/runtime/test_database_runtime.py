from __future__ import annotations

from fastapi import FastAPI
from pydantic import SecretStr
from pytest import MonkeyPatch

from fastauth import FastAuth, FastAuthOptions
from fastauth.options import MemoryDatabaseOptions
from fastauth.storage.memory import InMemoryAdapter


class FakeDatabaseRuntime:
    def __init__(self, events: list[str]) -> None:
        self.adapter = InMemoryAdapter()
        self.events = events

    async def startup(self, auth: object, app: FastAPI) -> None:
        del auth, app
        self.events.append("database-start")

    async def shutdown(self) -> None:
        self.events.append("database-stop")


async def test_fastauth_lifespan_delegates_database_startup_and_shutdown(
    monkeypatch: MonkeyPatch,
) -> None:
    events: list[str] = []

    def build_runtime(self: MemoryDatabaseOptions) -> FakeDatabaseRuntime:
        del self
        return FakeDatabaseRuntime(events)

    monkeypatch.setattr(MemoryDatabaseOptions, "build_runtime", build_runtime, raising=False)
    auth = FastAuth(FastAuthOptions(secret_key=SecretStr("a" * 64)))

    async with auth.lifespan(FastAPI()):
        assert events == ["database-start"]

    assert events == ["database-start", "database-stop"]
