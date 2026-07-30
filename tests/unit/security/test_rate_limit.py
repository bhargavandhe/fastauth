"""Unit tests for the rate limiter."""

from __future__ import annotations

import asyncio
import time
from datetime import timedelta

import pytest

from fastauth.domain.models import RateLimit
from fastauth.exceptions import RateLimitError
from fastauth.options import AdvancedOptions, LockoutOptions, RateLimitOptions
from fastauth.security.lockout import AccountLockoutTracker, lockout_key
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


async def test_memory_storage_resets_from_original_window_start() -> None:
    storage = MemoryRateLimitStorage()

    assert await storage.increment("k", window_ms=10_000, now_ms=0) == (1, 0)
    assert await storage.increment("k", window_ms=10_000, now_ms=5_000) == (2, 0)
    assert await storage.increment("k", window_ms=10_000, now_ms=11_000) == (1, 11_000)


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
            return self.count, now_ms

        async def get_rate_limit(self, key: str):  # type: ignore[no-untyped-def]
            raise AssertionError("increment must not use read-before-write")

        async def upsert_rate_limit(self, rate_limit):  # type: ignore[no-untyped-def]
            raise AssertionError("increment must not use read-before-write")

        async def rekey_rate_limit(
            self,
            old_key: str,
            new_key: str,
            *,
            window_ms: int,
            now_ms: int,
        ) -> None:
            raise AssertionError("increment must not rekey")

        async def delete_rate_limit(self, key: str) -> None:
            return None

    storage = DatabaseRateLimitStorage(AtomicOnlyStore())
    now = int(time.time() * 1000)

    assert await storage.increment("k", window_ms=60_000, now_ms=now) == (1, now)
    assert await storage.increment("k", window_ms=60_000, now_ms=now) == (2, now)


async def test_database_storage_resets_from_original_window_start() -> None:
    storage = DatabaseRateLimitStorage(InMemoryAdapter())

    assert await storage.increment("k", window_ms=10_000, now_ms=0) == (1, 0)
    assert await storage.increment("k", window_ms=10_000, now_ms=5_000) == (2, 0)
    assert await storage.increment("k", window_ms=10_000, now_ms=11_000) == (1, 11_000)


async def test_lockout_rekey_preserves_stricter_active_bucket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage = MemoryRateLimitStorage()
    tracker = AccountLockoutTracker(
        config=LockoutOptions(window=timedelta(seconds=60)),
        storage=storage,
    )
    monkeypatch.setattr(tracker, "now_ms", lambda: 10_000)
    await storage.upsert(RateLimit(key=lockout_key("old"), count=7, last_request_ms=1_000))
    await storage.upsert(RateLimit(key=lockout_key("new"), count=4, last_request_ms=2_000))

    await tracker.rekey("old", "new")

    assert await storage.get(lockout_key("old")) is None
    destination = await storage.get(lockout_key("new"))
    assert destination is not None
    assert destination.count == 7
    assert destination.last_request_ms == 1_000


async def test_lockout_rekey_clears_expired_buckets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage = MemoryRateLimitStorage()
    tracker = AccountLockoutTracker(
        config=LockoutOptions(window=timedelta(seconds=1)),
        storage=storage,
    )
    monkeypatch.setattr(tracker, "now_ms", lambda: 10_000)
    await storage.upsert(RateLimit(key=lockout_key("old"), count=7, last_request_ms=1_000))
    await storage.upsert(RateLimit(key=lockout_key("new"), count=8, last_request_ms=2_000))

    await tracker.rekey("old", "new")

    assert await storage.get(lockout_key("old")) is None
    assert await storage.get(lockout_key("new")) is None


async def test_lockout_rekey_preserves_concurrent_destination_increment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage = MemoryRateLimitStorage()
    tracker = AccountLockoutTracker(
        config=LockoutOptions(window=timedelta(seconds=60)),
        storage=storage,
    )
    monkeypatch.setattr(tracker, "now_ms", lambda: 10_000)
    await storage.upsert(RateLimit(key=lockout_key("old"), count=4, last_request_ms=1_000))
    await storage.upsert(RateLimit(key=lockout_key("new"), count=4, last_request_ms=1_000))

    await asyncio.gather(
        tracker.rekey("old", "new"),
        storage.increment(lockout_key("new"), window_ms=60_000, now_ms=10_000),
    )

    destination = await storage.get(lockout_key("new"))
    assert destination is not None
    assert destination.count == 5


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
