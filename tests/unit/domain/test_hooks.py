from __future__ import annotations

import pytest

from fastauth.domain.enums import HookPhase
from fastauth.domain.models import User
from fastauth.exceptions import HookAbortError
from fastauth.runtime.hooks import DatabaseHooks, HookContext


async def test_run_returns_payload_when_no_hooks_registered() -> None:
    hooks = DatabaseHooks()
    user = User(email="x@example.com")
    result = await hooks.run(HookPhase.BEFORE_CREATE, "user", user, actor_user_id=None)
    assert result == user


async def test_before_hook_can_mutate() -> None:
    hooks = DatabaseHooks()

    async def cap_email(ctx: HookContext) -> User:
        assert isinstance(ctx.payload, User)
        new = ctx.payload.model_copy(update={"name": (ctx.payload.name or "").upper()})
        return new

    hooks.register(HookPhase.BEFORE_CREATE, "user", cap_email)
    user = User(email="x@example.com", name="alice")
    result = await hooks.run(HookPhase.BEFORE_CREATE, "user", user, actor_user_id=None)
    assert isinstance(result, User)
    assert result.name == "ALICE"


async def test_before_hook_can_abort() -> None:
    hooks = DatabaseHooks()

    async def deny(ctx: HookContext) -> User:
        raise HookAbortError(message="banned")

    hooks.register(HookPhase.BEFORE_CREATE, "user", deny)
    with pytest.raises(HookAbortError):
        await hooks.run(
            HookPhase.BEFORE_CREATE,
            "user",
            User(email="x@example.com"),
            actor_user_id=None,
        )


async def test_after_hooks_run_in_registration_order() -> None:
    hooks = DatabaseHooks()
    log: list[str] = []

    async def first(ctx: HookContext) -> None:
        log.append("first")
        return None

    async def second(ctx: HookContext) -> None:
        log.append("second")
        return None

    hooks.register(HookPhase.AFTER_CREATE, "user", first)
    hooks.register(HookPhase.AFTER_CREATE, "user", second)
    await hooks.run(HookPhase.AFTER_CREATE, "user", User(email="x@example.com"), actor_user_id=None)
    assert log == ["first", "second"]
