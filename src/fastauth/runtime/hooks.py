"""DatabaseHooks: before/after callbacks for create/update/delete on each model."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field

from fastauth.domain.enums import HookPhase
from fastauth.domain.models import User

if TYPE_CHECKING:
    from fastauth.runtime.context import AuthContext

__all__ = ["DatabaseHooks", "HookContext", "HookHandler", "update_user_with_hooks"]


HookHandler = Callable[["HookContext"], Awaitable[Any | None]]


class HookContext(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    phase: HookPhase
    model_name: str
    payload: Any
    actor_user_id: str | None = None


class DatabaseHooks(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    handlers: dict[tuple[HookPhase, str], list[HookHandler]] = Field(
        default_factory=lambda: {},
    )

    def register(self, phase: HookPhase, model_name: str, handler: HookHandler) -> None:
        self.handlers.setdefault((phase, model_name), []).append(handler)

    async def run(
        self,
        phase: HookPhase,
        model_name: str,
        payload: Any,  # noqa: ANN401
        actor_user_id: str | None,
    ) -> Any:  # noqa: ANN401
        context = HookContext(
            phase=phase,
            model_name=model_name,
            payload=payload,
            actor_user_id=actor_user_id,
        )
        is_before = phase in (
            HookPhase.BEFORE_CREATE,
            HookPhase.BEFORE_UPDATE,
            HookPhase.BEFORE_DELETE,
        )
        current = payload
        for handler in self.handlers.get((phase, model_name), []):
            result = await handler(context)
            if is_before and result is not None:
                current = result
                context = context.model_copy(update={"payload": current})
        return current


async def update_user_with_hooks(
    context: AuthContext, user: User, *, actor_user_id: str | None
) -> User:
    """Persist a user update between before/after hooks; after runs only on success."""
    transformed = await context.hooks.run(
        HookPhase.BEFORE_UPDATE, "user", user, actor_user_id=actor_user_id
    )
    if not isinstance(transformed, User):
        raise TypeError("before-update user hook must return User or None")
    updated = await context.adapter.update_user(transformed)
    await context.hooks.run(HookPhase.AFTER_UPDATE, "user", updated, actor_user_id=actor_user_id)
    return updated
