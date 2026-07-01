"""Unit tests for the rate limiter."""

from __future__ import annotations

import time
from datetime import timedelta

import pytest

from fastauth.exceptions import RateLimitError
from fastauth.options import AdvancedOptions, RateLimitOptions
from fastauth.security.rate_limit import (
    DatabaseRateLimitStorage,
    MemoryRateLimitStorage,
    RateLimiter,
    normalise_ip,
)
from fastauth.storage.memory import InMemoryAdapter


def test_normalise_ipv6_subnet_collapses() -> None:
    one = normalise_ip("2001:0db8:0000:0000:0000:0000:0000:0001", 64)
    two = normalise_ip("2001:db8::abc", 64)
    assert one == two


def test_normalise_ipv4_mapped_ipv6_becomes_ipv4() -> None:
    assert normalise_ip("::ffff:192.0.2.1", 64) == "192.0.2.1"


async def test_memory_storage_increments() -> None:
    storage = MemoryRateLimitStorage()
    now = int(time.time() * 1000)
    count, _ = await storage.increment("k", window_ms=60_000, now_ms=now)
    assert count == 1
    count, _ = await storage.increment("k", window_ms=60_000, now_ms=now)
    assert count == 2


async def test_database_storage_persists() -> None:
    adapter = InMemoryAdapter()
    storage = DatabaseRateLimitStorage(adapter)
    now = int(time.time() * 1000)
    count_a, _ = await storage.increment("k", window_ms=60_000, now_ms=now)
    count_b, _ = await storage.increment("k", window_ms=60_000, now_ms=now)
    assert count_a == 1 and count_b == 2


async def test_database_storage_uses_adapter_atomic_increment() -> None:
    class AtomicOnlyStore:
        def __init__(self) -> None:
            self.count = 0

        async def increment_rate_limit(
            self,
            key: str,
            *,
            window_ms: int,
            now_ms: int,
        ) -> tuple[int, int]:
            self.count += 1
            return self.count, now_ms - window_ms

        async def get_rate_limit(self, key: str):  # type: ignore[no-untyped-def]
            raise AssertionError("increment must not use read-before-write")

        async def upsert_rate_limit(self, rate_limit):  # type: ignore[no-untyped-def]
            raise AssertionError("increment must not use read-before-write")

        async def delete_rate_limit(self, key: str) -> None:
            return None

    storage = DatabaseRateLimitStorage(AtomicOnlyStore())
    now = int(time.time() * 1000)

    assert await storage.increment("k", window_ms=60_000, now_ms=now) == (1, now - 60_000)
    assert await storage.increment("k", window_ms=60_000, now_ms=now) == (2, now - 60_000)


async def test_limiter_blocks_after_threshold() -> None:
    limiter = RateLimiter(
        config=RateLimitOptions(window=timedelta(seconds=10), max_requests=2, enabled=True),
        advanced=AdvancedOptions(),
        storage=MemoryRateLimitStorage(),
        plugin_rules=[],
    )
    await limiter.check("/x", "1.2.3.4")
    await limiter.check("/x", "1.2.3.4")
    with pytest.raises(RateLimitError):
        await limiter.check("/x", "1.2.3.4")


async def test_limiter_uses_strict_default_for_sign_in() -> None:
    limiter = RateLimiter(
        config=RateLimitOptions(window=timedelta(seconds=60), max_requests=100, enabled=True),
        advanced=AdvancedOptions(),
        storage=MemoryRateLimitStorage(),
        plugin_rules=[],
    )
    for _ in range(3):
        await limiter.check("/sign-in/email", "1.2.3.4")
    with pytest.raises(RateLimitError):
        await limiter.check("/sign-in/email", "1.2.3.4")


async def test_disabled_limiter_never_blocks() -> None:
    limiter = RateLimiter(
        config=RateLimitOptions(enabled=False),
        advanced=AdvancedOptions(),
        storage=MemoryRateLimitStorage(),
        plugin_rules=[],
    )
    for _ in range(100):
        await limiter.check("/x", "1.2.3.4")
