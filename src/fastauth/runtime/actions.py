"""An explicit shared abuse-control boundary for application-owned entry points."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TypeVar

from pydantic import BaseModel

from fastauth.api.commands import RequestContext
from fastauth.exceptions import InvalidRequestError
from fastauth.runtime.context import AuthContext

__all__ = ["ActionBoundary"]

ActionResultT = TypeVar("ActionResultT", bound=BaseModel)


class ActionBoundary:
    """Apply the same IP/path limiter as mounted HTTP before running an action.

    Paths are canonical FastAuth-relative paths, e.g. ``/sign-in/email``.
    Supply an IP from a trusted proxy-aware request boundary, never an
    unvalidated forwarding header. This is abuse control, not authorization.
    Trusted SDK calls deliberately do not consume network rate limits by default.
    """

    def __init__(self, context: AuthContext) -> None:
        self.context = context

    async def check(self, path: str, *, context: RequestContext) -> None:
        if not path.startswith("/"):
            raise InvalidRequestError(message="action path must start with /")
        if self.context.config.rate_limit.enabled and context.ip_address is None:
            raise InvalidRequestError(message="ip_address is required for a rate-limited action")
        await self.context.rate_limiter.check(path, context.ip_address)

    async def run(
        self,
        path: str,
        operation: Callable[[], Awaitable[ActionResultT]],
        *,
        context: RequestContext,
    ) -> ActionResultT:
        await self.check(path, context=context)
        return await operation()
