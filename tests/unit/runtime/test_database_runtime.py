from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import pytest
from fastapi import FastAPI
from pydantic import SecretStr
from pytest import MonkeyPatch

from fastauth import FastAuth, FastAuthOptions
from fastauth.options import CustomDatabaseOptions, MemoryDatabaseOptions
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

    @asynccontextmanager
    async def lifespan(self, auth: object, app: FastAPI) -> AsyncGenerator[None, None]:
        try:
            await self.startup(auth, app)
            yield
        finally:
            await self.shutdown()


class LifespanOnlyRuntime:
    def __init__(self, events: list[str]) -> None:
        self.adapter = InMemoryAdapter()
        self.events = events

    @asynccontextmanager
    async def lifespan(self, auth: object, app: FastAPI) -> AsyncGenerator[None, None]:
        del auth, app
        self.events.append("database-start")
        try:
            yield
        finally:
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


async def test_fastauth_lifespan_shuts_down_database_after_startup_failure(
    monkeypatch: MonkeyPatch,
) -> None:
    events: list[str] = []

    class FailingStartupRuntime(FakeDatabaseRuntime):
        async def startup(self, auth: object, app: FastAPI) -> None:
            await super().startup(auth, app)
            raise RuntimeError("database startup failed")

    def build_runtime(self: MemoryDatabaseOptions) -> FailingStartupRuntime:
        del self
        return FailingStartupRuntime(events)

    monkeypatch.setattr(MemoryDatabaseOptions, "build_runtime", build_runtime, raising=False)
    auth = FastAuth(FastAuthOptions(secret_key=SecretStr("a" * 64)))

    with pytest.raises(RuntimeError, match="database startup failed"):
        async with auth.lifespan(FastAPI()):
            pass

    assert events == ["database-start", "database-stop"]


async def test_custom_database_lifespan_receives_body_exception() -> None:
    seen: list[type[BaseException] | None] = []

    def database_lifespan(auth: object):
        del auth

        def app_lifespan(app: FastAPI):
            del app

            @asynccontextmanager
            async def context() -> AsyncGenerator[None, None]:
                try:
                    yield
                except BaseException as exc:
                    seen.append(type(exc))
                    raise
                else:
                    seen.append(None)

            return context()

        return app_lifespan

    auth = FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("a" * 64),
            database=CustomDatabaseOptions(
                adapter=InMemoryAdapter(),
                lifespan=database_lifespan,
            ),
        )
    )

    with pytest.raises(ValueError, match="body failed"):
        async with auth.lifespan(FastAPI()):
            raise ValueError("body failed")

    assert seen == [ValueError]


async def test_database_runtime_only_needs_lifespan(monkeypatch: MonkeyPatch) -> None:
    events: list[str] = []

    def build_runtime(self: MemoryDatabaseOptions) -> LifespanOnlyRuntime:
        del self
        return LifespanOnlyRuntime(events)

    monkeypatch.setattr(MemoryDatabaseOptions, "build_runtime", build_runtime, raising=False)
    auth = FastAuth(FastAuthOptions(secret_key=SecretStr("a" * 64)))

    async with auth.lifespan(FastAPI()):
        assert events == ["database-start"]

    assert events == ["database-start", "database-stop"]


async def test_body_and_database_shutdown_failures_are_grouped(
    monkeypatch: MonkeyPatch,
) -> None:
    class FailingShutdownRuntime:
        adapter = InMemoryAdapter()

        @asynccontextmanager
        async def lifespan(self, auth: object, app: FastAPI) -> AsyncGenerator[None, None]:
            del auth, app
            try:
                yield
            finally:
                raise RuntimeError("database shutdown failed")

    def build_runtime(self: MemoryDatabaseOptions) -> FailingShutdownRuntime:
        del self
        return FailingShutdownRuntime()

    monkeypatch.setattr(MemoryDatabaseOptions, "build_runtime", build_runtime, raising=False)
    auth = FastAuth(FastAuthOptions(secret_key=SecretStr("a" * 64)))

    with pytest.raises(ExceptionGroup) as captured:
        async with auth.lifespan(FastAPI()):
            raise ValueError("body failed")

    messages = {str(exc) for exc in captured.value.exceptions}
    assert messages == {"body failed", "database shutdown failed"}
