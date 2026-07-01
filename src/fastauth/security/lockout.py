"""Per-identifier failed-sign-in tracking + lockout enforcement.

Reuses the existing :class:`RateLimitStorage` machinery — both memory- and
DB-backed implementations work without changes. Lockout state is encoded as a
:class:`RateLimit` row keyed by ``"lockout:<identifier>"``: ``count`` is the
number of failures within the rolling window, ``last_request_ms`` is the
timestamp of the most recent failure. The window doubles as the lockout
duration — once ``count`` exceeds ``max_failures``, the identifier stays
locked until ``last_request_ms + window_seconds * 1000``, after which the
counter naturally rolls off and a new sign-in attempt is permitted.

This keeps the implementation single-storage (no new collection) and inherits
the IPv6 / Redis future-compatibility work from the rate-limiter design.
"""

from __future__ import annotations

import time

from fastauth.exceptions import AccountLockedError
from fastauth.options import LockoutOptions
from fastauth.security.rate_limit import RateLimitStorage

__all__ = ["AccountLockoutTracker"]


def lockout_key(identifier: str) -> str:
    return f"lockout:{identifier}"


class AccountLockoutTracker:
    """Track per-identifier sign-in failures and enforce lockout windows.

    The flow integrates this in three places:

    * Before password verification: :meth:`check_locked` raises
      :class:`AccountLockedError` (HTTP 423) if the identifier is currently
      locked, before any password material is examined.
    * On successful sign-in: :meth:`reset` clears the failure counter.
    * On failed sign-in: :meth:`record_failure` increments the counter and
      returns ``None`` (still attempting) or an int (lockout just triggered).

    A no-op pathway when ``LockoutConfig.enabled == False`` keeps the cost
    near zero for applications that intentionally don't want lockout
    enforcement (e.g. internal apps behind SSO that handle this elsewhere).
    """

    def __init__(self, *, config: LockoutOptions, storage: RateLimitStorage) -> None:
        self.config = config
        self.storage = storage

    def now_ms(self) -> int:
        return int(time.time() * 1000)

    async def check_locked(self, identifier: str) -> None:
        """Raise ``AccountLockedError`` if ``identifier`` is currently locked."""
        if not self.config.enabled:
            return
        window_ms = self.config.window_seconds * 1000
        existing = await self.storage.get(lockout_key(identifier))
        if existing is None:
            return
        now = self.now_ms()
        if existing.count <= self.config.max_failures:
            return
        unlock_at_ms = existing.last_request_ms + window_ms
        if unlock_at_ms <= now:
            # Window rolled off naturally; the next attempt resets it.
            return
        retry_after = max(1, (unlock_at_ms - now) // 1000)
        raise AccountLockedError(retry_after_seconds=int(retry_after))

    async def record_failure(self, identifier: str) -> int | None:
        """Increment the failure counter. Returns retry_after_seconds iff this
        attempt was the one that crossed the threshold; ``None`` otherwise.
        """
        if not self.config.enabled:
            return None
        window_ms = self.config.window_seconds * 1000
        now = self.now_ms()
        count, _start = await self.storage.increment(
            lockout_key(identifier),
            window_ms=window_ms,
            now_ms=now,
        )
        if count <= self.config.max_failures:
            return None
        return self.config.window_seconds

    async def reset(self, identifier: str) -> None:
        """Clear the failure counter for ``identifier`` (successful sign-in)."""
        if not self.config.enabled:
            return
        await self.storage.delete(lockout_key(identifier))
