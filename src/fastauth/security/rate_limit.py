"""Rate limiting: storage backends, IPv6 normalisation, per-path rules."""

from __future__ import annotations

import asyncio
import ipaddress
import time
from typing import Protocol, runtime_checkable

from fastauth.config import AdvancedConfig, RateLimitConfig
from fastauth.domain.models import RateLimit
from fastauth.exceptions import RateLimitError
from fastauth.plugins.base import RateLimitRule
from fastauth.storage.base import RateLimitStore

__all__ = [
    "DEFAULT_STRICT_RULES",
    "DatabaseRateLimitStorage",
    "MemoryRateLimitStorage",
    "RateLimitStorage",
    "RateLimiter",
    "normalise_ip",
]


DEFAULT_STRICT_RULES: dict[str, tuple[int, int]] = {
    "/sign-in/email": (10, 3),
    "/sign-in/username": (10, 3),
    "/send-verification-email": (60, 5),
    "/forgot-password": (60, 5),
    "/reset-password": (10, 3),
}


def normalise_ip(ip_address: str, ipv6_subnet: int) -> str:
    """Normalise an IP for bucketing.

    - IPv4-mapped IPv6 addresses (``::ffff:a.b.c.d``) are returned as the IPv4.
    - IPv6 addresses are collapsed to the network address of their ``/ipv6_subnet``.
    - IPv4 addresses are returned in their canonical form.
    - On parse failure the input string is returned untouched.
    """
    try:
        parsed = ipaddress.ip_address(ip_address)
    except ValueError:
        return ip_address
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        return str(parsed.ipv4_mapped)
    if isinstance(parsed, ipaddress.IPv6Address):
        network = ipaddress.ip_network(f"{parsed.exploded}/{ipv6_subnet}", strict=False)
        return str(network.network_address)
    return str(parsed)


@runtime_checkable
class RateLimitStorage(Protocol):
    """Storage backend Protocol for rate-limit buckets.

    Three operations are required:

    * :meth:`increment` records a hit and returns the current window counter.
    * :meth:`get` reads the current bucket state without mutating, used by
      consumers (e.g. ``AccountLockoutTracker``) that need to know "is this
      key currently over the threshold?" without incrementing.
    * :meth:`delete` clears a bucket — used to reset the counter on a
      successful sign-in so subsequent failures don't accumulate from
      previous unrelated attempts.
    """

    async def increment(
        self,
        key: str,
        *,
        window_ms: int,
        now_ms: int,
    ) -> tuple[int, int]:
        """Return ``(count in window, window start ms)``."""
        ...

    async def get(self, key: str) -> RateLimit | None:
        """Return the current bucket state for ``key``, or ``None`` if absent.

        Unlike :meth:`increment`, this does not record a hit. The returned
        ``count`` reflects the absolute number of hits in the most-recent
        window; ``last_request_ms`` is the timestamp of the most recent hit.
        """
        ...

    async def delete(self, key: str) -> None:
        """Remove the bucket for ``key``. Idempotent on absent keys."""
        ...


class MemoryRateLimitStorage:
    """Dict-backed, asyncio-Lock-guarded rate-limit storage."""

    def __init__(self) -> None:
        self.state: dict[str, list[int]] = {}
        self.lock = asyncio.Lock()

    async def increment(
        self,
        key: str,
        *,
        window_ms: int,
        now_ms: int,
    ) -> tuple[int, int]:
        async with self.lock:
            timestamps = [ts for ts in self.state.get(key, []) if ts > now_ms - window_ms]
            timestamps.append(now_ms)
            self.state[key] = timestamps
            return len(timestamps), timestamps[0]

    async def get(self, key: str) -> RateLimit | None:
        timestamps = self.state.get(key)
        if not timestamps:
            return None
        return RateLimit(key=key, count=len(timestamps), last_request_ms=timestamps[-1])

    async def delete(self, key: str) -> None:
        async with self.lock:
            self.state.pop(key, None)


class DatabaseRateLimitStorage:
    """Adapter-backed rate-limit storage using the ``RateLimit`` row model."""

    def __init__(self, adapter: RateLimitStore) -> None:
        self.adapter = adapter

    async def increment(
        self,
        key: str,
        *,
        window_ms: int,
        now_ms: int,
    ) -> tuple[int, int]:
        existing = await self.adapter.get_rate_limit(key)
        if existing is None or existing.last_request_ms <= now_ms - window_ms:
            updated = RateLimit(key=key, count=1, last_request_ms=now_ms)
        else:
            updated = RateLimit(
                key=key,
                count=existing.count + 1,
                last_request_ms=now_ms,
            )
        await self.adapter.upsert_rate_limit(updated)
        return updated.count, updated.last_request_ms - window_ms

    async def get(self, key: str) -> RateLimit | None:
        return await self.adapter.get_rate_limit(key)

    async def delete(self, key: str) -> None:
        await self.adapter.delete_rate_limit(key)


class RateLimiter:
    """Per-(IP bucket, path) rate limiter with plugin + strict-default precedence."""

    def __init__(
        self,
        *,
        config: RateLimitConfig,
        advanced: AdvancedConfig,
        storage: RateLimitStorage,
        plugin_rules: list[RateLimitRule],
    ) -> None:
        self.config = config
        self.advanced = advanced
        self.storage = storage
        self.plugin_rules: dict[str, tuple[int, int]] = {
            rule.path: (int(rule.window.total_seconds()), rule.max_requests)
            for rule in plugin_rules
        }

    def rule_for(self, path: str) -> tuple[int, int]:
        if path in self.plugin_rules:
            return self.plugin_rules[path]
        if path in DEFAULT_STRICT_RULES:
            return DEFAULT_STRICT_RULES[path]
        return (self.config.window_seconds, self.config.max_requests)

    async def check(self, path: str, ip_address: str | None) -> None:
        if not self.config.enabled or ip_address is None:
            return
        window_seconds, max_requests = self.rule_for(path)
        bucket = normalise_ip(ip_address, self.advanced.ipv6_subnet)
        key = f"ip:{bucket}:{path}"
        now_ms = int(time.time() * 1000)
        count, window_start_ms = await self.storage.increment(
            key,
            window_ms=window_seconds * 1000,
            now_ms=now_ms,
        )
        if count > max_requests:
            retry_after = max(
                1,
                (window_start_ms + window_seconds * 1000 - now_ms) // 1000,
            )
            raise RateLimitError(retry_after_seconds=int(retry_after))
