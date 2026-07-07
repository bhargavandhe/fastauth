from __future__ import annotations

import pytest
from pydantic import SecretStr

from fastauth import FastAuth, FastAuthOptions
from fastauth.database import memory
from fastauth.plugins.base import Plugin


class LifecyclePlugin(Plugin):
    id = "lifecycle-plugin"

    def __init__(
        self,
        events: list[str],
        name: str,
        *,
        fail_startup: bool = False,
        fail_shutdown: bool = False,
    ) -> None:
        self.events = events
        self.name = name
        self.fail_startup = fail_startup
        self.fail_shutdown = fail_shutdown

    async def lifespan_startup(self) -> None:
        self.events.append(f"{self.name}:startup")
        if self.fail_startup:
            raise RuntimeError(f"{self.name} startup failed")

    async def lifespan_shutdown(self) -> None:
        self.events.append(f"{self.name}:shutdown")
        if self.fail_shutdown:
            raise RuntimeError(f"{self.name} shutdown failed")


class FirstLifecyclePlugin(LifecyclePlugin):
    id = "lifecycle-first"


class SecondLifecyclePlugin(LifecyclePlugin):
    id = "lifecycle-second"


class ThirdLifecyclePlugin(LifecyclePlugin):
    id = "lifecycle-third"


def build_auth(*plugins: Plugin) -> FastAuth:
    return FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("a" * 64),
            database=memory(),
        ),
        plugins=plugins,
    )


async def test_plugin_lifespan_shuts_down_started_plugins_after_startup_failure() -> None:
    events: list[str] = []
    started = FirstLifecyclePlugin(events, "started")
    failing = SecondLifecyclePlugin(events, "failing", fail_startup=True)
    unstarted = ThirdLifecyclePlugin(events, "unstarted")
    auth = build_auth(started, failing, unstarted)

    with pytest.raises(RuntimeError, match="failing startup failed"):
        async with auth.plugin_lifespan():
            pass

    assert events == [
        "started:startup",
        "failing:startup",
        "started:shutdown",
    ]


async def test_plugin_lifespan_shutdowns_in_reverse_order_and_collects_errors() -> None:
    events: list[str] = []
    first = FirstLifecyclePlugin(events, "first")
    second = SecondLifecyclePlugin(events, "second", fail_shutdown=True)
    third = ThirdLifecyclePlugin(events, "third")
    auth = build_auth(first, second, third)

    with pytest.raises(ExceptionGroup) as exc_info:
        async with auth.plugin_lifespan():
            events.append("inside")

    assert [str(error) for error in exc_info.value.exceptions] == [
        "second shutdown failed",
    ]
    assert events == [
        "first:startup",
        "second:startup",
        "third:startup",
        "inside",
        "third:shutdown",
        "second:shutdown",
        "first:shutdown",
    ]
