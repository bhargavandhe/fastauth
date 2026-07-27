from typing import cast

from pydantic import SecretStr

from fastauth.database import memory
from fastauth.domain.enums import HookPhase
from fastauth.domain.events import UserCreated
from fastauth.domain.models import User
from fastauth.options import FastAuthOptions
from fastauth.runtime.auth import FastAuth
from fastauth.runtime.hooks import HookContext


def make_auth() -> FastAuth:
    return FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("d" * 64),
            database=memory(),
        )
    )


async def test_on_registers_handler_and_preserves_identity() -> None:
    auth = make_auth()
    received: list[str] = []

    async def handler(event: UserCreated) -> None:
        received.append(event.user_id)

    decorated = auth.on(UserCreated)(handler)
    await auth.events.publish(
        UserCreated(user_id="user-1", identifier="a@app.com"),
    )

    assert decorated is handler
    assert received == ["user-1"]


async def test_on_preserves_event_exception_isolation_and_order() -> None:
    auth = make_auth()
    received: list[str] = []

    @auth.on(UserCreated)
    async def failing_handler(  # pyright: ignore[reportUnusedFunction]
        event: UserCreated,
    ) -> None:
        del event
        raise RuntimeError("subscriber failed")

    @auth.on(UserCreated)
    async def successful_handler(  # pyright: ignore[reportUnusedFunction]
        event: UserCreated,
    ) -> None:
        received.append(event.user_id)

    await auth.events.publish(
        UserCreated(user_id="user-2", identifier="b@app.com"),
    )

    assert received == ["user-2"]


async def test_hook_registers_handler_and_preserves_identity() -> None:
    auth = make_auth()

    async def add_name(context: HookContext) -> User:
        user = cast(User, context.payload)
        return user.model_copy(update={"name": "Decorated"})

    decorated = auth.hook(HookPhase.BEFORE_CREATE, target="user")(add_name)
    result = await auth.context.hooks.run(
        HookPhase.BEFORE_CREATE,
        "user",
        User(email="a@app.com"),
        actor_user_id=None,
    )

    assert decorated is add_name
    assert isinstance(result, User)
    assert result.name == "Decorated"


async def test_hook_chains_before_payloads_in_registration_order() -> None:
    auth = make_auth()
    seen_names: list[str | None] = []

    @auth.hook(HookPhase.BEFORE_CREATE, target="user")
    async def add_name(  # pyright: ignore[reportUnusedFunction]
        context: HookContext,
    ) -> User:
        user = cast(User, context.payload)
        seen_names.append(user.name)
        return user.model_copy(update={"name": "First"})

    @auth.hook(HookPhase.BEFORE_CREATE, target="user")
    async def add_metadata(  # pyright: ignore[reportUnusedFunction]
        context: HookContext,
    ) -> User:
        user = cast(User, context.payload)
        seen_names.append(user.name)
        return user.model_copy(update={"metadata": {"order": "second"}})

    result = await auth.context.hooks.run(
        HookPhase.BEFORE_CREATE,
        "user",
        User(email="b@app.com"),
        actor_user_id=None,
    )

    assert isinstance(result, User)
    assert seen_names == [None, "First"]
    assert result.name == "First"
    assert result.metadata == {"order": "second"}
