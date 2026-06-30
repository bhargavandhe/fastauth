from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any, cast

import pytest
from fastapi import FastAPI

from fastauth.runtime.auth import FastAuth
from fastauth.storage.beanie import BeanieAdapter


class FakeAuth:
    def __init__(self) -> None:
        self.started = False
        self.stopped = False

    @asynccontextmanager
    async def lifespan(self, app: FastAPI | None = None) -> AsyncGenerator[None, None]:
        del app
        self.started = True
        try:
            yield
        finally:
            self.stopped = True


@pytest.mark.anyio
async def test_beanie_adapter_lifespan_initializes_beanie_before_auth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    async def fake_init(
        database: object,
        *,
        collection_prefix: str = "",
        collection_suffix: str = "",
    ) -> None:
        assert database == "db"
        assert collection_prefix == ""
        assert collection_suffix == ""
        calls.append("beanie")

    fake_auth = FakeAuth()

    @asynccontextmanager
    async def fake_auth_lifespan(app: FastAPI | None = None) -> AsyncGenerator[None, None]:
        del app
        calls.append("auth-start")
        try:
            yield
        finally:
            calls.append("auth-stop")

    fake_auth.lifespan = fake_auth_lifespan  # type: ignore[method-assign]
    monkeypatch.setattr("fastauth.storage.beanie.adapter.init_beanie_documents", fake_init)

    adapter = BeanieAdapter(cast(Any, "db"))
    app = FastAPI(lifespan=adapter.lifespan(cast(FastAuth, fake_auth)))

    async with app.router.lifespan_context(app):
        assert calls == ["beanie", "auth-start"]

    assert calls == ["beanie", "auth-start", "auth-stop"]


@pytest.mark.anyio
async def test_beanie_adapter_lifespan_passes_custom_collection_affixes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, str]] = []

    async def fake_init(
        database: object,
        *,
        collection_prefix: str = "",
        collection_suffix: str = "",
    ) -> None:
        assert database == "db"
        calls.append((collection_prefix, collection_suffix))

    fake_auth = FakeAuth()
    monkeypatch.setattr("fastauth.storage.beanie.adapter.init_beanie_documents", fake_init)

    adapter = BeanieAdapter(
        cast(Any, "db"),
        collection_prefix="tenant_",
        collection_suffix="_auth",
    )
    app = FastAPI(lifespan=adapter.lifespan(cast(FastAuth, fake_auth)))

    async with app.router.lifespan_context(app):
        assert calls == [("tenant_", "_auth")]

    assert fake_auth.stopped is True
