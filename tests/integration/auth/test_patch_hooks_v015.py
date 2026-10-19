"""Python/HTTP profile patch parity and complete user mutation hooks."""

from typing import Any

import httpx
import pytest
from pydantic import SecretStr, ValidationError

from fastauth import FastAuth
from fastauth.api.commands import UpdateUserCommand, UserPrincipal
from fastauth.domain.enums import HookPhase
from fastauth.domain.models import User
from fastauth.exceptions import HookAbortError
from fastauth.runtime.hooks import HookContext


@pytest.mark.asyncio
async def test_sdk_profile_omission_preserves_and_null_clears(auth: FastAuth) -> None:
    user = await auth.api.create_user(
        email="patch@example.com", password="Password123!", name="Old"
    )
    first = await auth.users.update(user.id, image="https://example.com/avatar")
    assert first.name == "Old"
    second = await auth.users.update(user.id, name=None)
    assert second.name is None
    assert second.image == "https://example.com/avatar"
    third = await auth.api.user.update(
        UpdateUserCommand(principal=UserPrincipal(user_id=user.id), image=None)
    )
    assert third.image is None
    with pytest.raises(ValidationError, match="metadata must be an object"):
        await auth.users.update(user.id, metadata=None)
    with pytest.raises(ValidationError, match="username must not be null"):
        await auth.users.update(user.id, username=None)


@pytest.mark.asyncio
async def test_before_after_update_delete_hooks_and_abort(
    auth: FastAuth, client: httpx.AsyncClient
) -> None:
    result = await client.post(
        "/auth/sign-up/email", json={"email": "hooks@example.com", "password": "Password123!"}
    )
    uid = result.json()["user"]["id"]
    seen: list[tuple[HookPhase, str, bool]] = []

    async def observe(hook: HookContext) -> Any:
        assert isinstance(hook.payload, User)
        persisted = await auth.context.adapter.get_user_by_id(uid)
        seen.append((hook.phase, hook.actor_user_id or "", persisted is not None))
        if hook.phase is HookPhase.BEFORE_UPDATE:
            return hook.payload.model_copy(update={"name": "Hook transformed"})
        return None

    for phase in (
        HookPhase.BEFORE_UPDATE,
        HookPhase.AFTER_UPDATE,
        HookPhase.BEFORE_DELETE,
        HookPhase.AFTER_DELETE,
    ):
        auth.hook(phase, target="user")(observe)
    patched = await client.patch("/auth/user", json={"name": "Client"})
    assert patched.json()["name"] == "Hook transformed"
    deleted = await client.post("/auth/delete-account", json={"password": "Password123!"})
    assert deleted.status_code == 200
    assert seen == [
        (HookPhase.BEFORE_UPDATE, uid, True),
        (HookPhase.AFTER_UPDATE, uid, True),
        (HookPhase.BEFORE_DELETE, uid, True),
        (HookPhase.AFTER_DELETE, uid, False),
    ]

    user = await auth.api.create_user(email="abort@example.com", password="Password123!")

    async def abort(hook: HookContext) -> None:
        raise HookAbortError(message="blocked")

    auth.hook(HookPhase.BEFORE_DELETE, target="user")(abort)
    with pytest.raises(HookAbortError):
        await auth.users.delete(user.id, SecretStr("Password123!"))
    assert await auth.api.get_user(by_id=user.id) is not None


@pytest.mark.parametrize("mutation", ["in_place", "replacement"])
async def test_delete_hooks_cannot_redirect_target_or_audit(auth: FastAuth, mutation: str) -> None:
    from fastauth.domain.events import UserDeleted

    requested = await auth.api.create_user(
        email="requested-delete@example.com", password="Password123!"
    )
    other = await auth.api.create_user(email="keep@example.com", password="Password123!")
    observed: list[tuple[HookPhase, str | None, str, str]] = []
    events: list[UserDeleted] = []

    async def before(hook: HookContext) -> User | None:
        assert isinstance(hook.payload, User)
        observed.append((hook.phase, hook.actor_user_id, hook.payload.id, hook.payload.email))
        if mutation == "in_place":
            hook.payload.id = other.id.root
            hook.payload.email = other.email
            return None
        return hook.payload.model_copy(update={"id": other.id.root, "email": other.email})

    async def after(hook: HookContext) -> None:
        assert isinstance(hook.payload, User)
        observed.append((hook.phase, hook.actor_user_id, hook.payload.id, hook.payload.email))
        # After-hook mutation must not change the event's already-authorized target either.
        hook.payload.id = other.id.root

    async def observe_event(event: UserDeleted) -> None:
        events.append(event)

    auth.hook(HookPhase.BEFORE_DELETE, target="user")(before)
    auth.hook(HookPhase.AFTER_DELETE, target="user")(after)
    auth.context.event_bus.subscribe(UserDeleted, observe_event)

    await auth.users.delete(requested.id, SecretStr("Password123!"))

    assert await auth.api.get_user(by_id=requested.id) is None
    assert await auth.api.get_user(by_id=other.id) is not None
    assert observed == [
        (HookPhase.BEFORE_DELETE, requested.id.root, requested.id.root, requested.email),
        (HookPhase.AFTER_DELETE, requested.id.root, requested.id.root, requested.email),
    ]
    assert [event.user_id for event in events] == [requested.id.root]
