from __future__ import annotations

from pydantic import SecretStr

from fastauth.database import custom
from fastauth.domain.events import UserSignedIn
from fastauth.options import FastAuthOptions
from fastauth.runtime.auth import FastAuth
from fastauth.runtime.event_bus import EventBus
from fastauth.storage.memory import InMemoryAdapter


async def test_subscribe_and_publish() -> None:
    bus = EventBus()
    received: list[UserSignedIn] = []

    async def handler(event: UserSignedIn) -> None:
        received.append(event)

    bus.subscribe(UserSignedIn, handler)
    event = UserSignedIn(user_id="user-1", identifier="alice@example.com")
    await bus.publish(event)
    assert received == [event]


async def test_handler_exception_does_not_block_others() -> None:
    bus = EventBus()
    received: list[str] = []

    async def boom(event: UserSignedIn) -> None:
        raise RuntimeError("kaboom")

    async def ok(event: UserSignedIn) -> None:
        received.append(event.user_id)

    bus.subscribe(UserSignedIn, boom)
    bus.subscribe(UserSignedIn, ok)
    await bus.publish(UserSignedIn(user_id="user-2", identifier="bob@example.com"))
    assert received == ["user-2"]


async def test_fastauth_exposes_public_event_decorator() -> None:
    auth = FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("a" * 64),
            database=custom(adapter=InMemoryAdapter()),
        )
    )
    received: list[str] = []

    @auth.on(UserSignedIn)
    async def handler(  # pyright: ignore[reportUnusedFunction]
        event: UserSignedIn,
    ) -> None:
        received.append(event.user_id)

    await auth.events.publish(UserSignedIn(user_id="user-3", identifier="cara@example.com"))

    assert received == ["user-3"]
