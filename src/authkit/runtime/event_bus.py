"""In-process pub/sub bus for :class:`authkit.domain.events.AuthEvent`.

The bus is the **runtime** half of authkit's event system; the event data
classes themselves live in :mod:`authkit.domain.events` since they're pure
data with no orchestration. Plugins subscribe handlers at construction
time via :meth:`AuthKit.__init__`; flows publish events as side effects.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

from authkit.domain.events import AuthEvent

__all__ = ["EventBus"]

LOGGER = logging.getLogger("authkit.events")

EventT = TypeVar("EventT", bound=AuthEvent)
HandlerType = Callable[[Any], Awaitable[None]]


class EventBus:
    def __init__(self) -> None:
        self.subscribers: dict[type[AuthEvent], list[HandlerType]] = {}

    def subscribe(
        self,
        event_type: type[EventT],
        handler: Callable[[EventT], Awaitable[None]],
    ) -> None:
        self.subscribers.setdefault(event_type, []).append(handler)  # type: ignore[arg-type]

    async def publish(self, event: AuthEvent) -> None:
        for event_type, handlers in self.subscribers.items():
            if isinstance(event, event_type):
                for handler in handlers:
                    try:
                        await handler(event)
                    except Exception:
                        LOGGER.exception("event handler raised for %s", event_type.__name__)
