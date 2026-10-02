"""Bounded off-loop password work remains bounded across cancellation."""

import asyncio
import threading
import time

import pytest

from fastauth.security.passwords import BoundedPasswordHasher


class BlockingHasher:
    def __init__(self) -> None:
        self.started = threading.Event()
        self.release = threading.Event()
        self.lock = threading.Lock()
        self.running = 0
        self.maximum = 0

    def hash(self, plain: str) -> str:
        with self.lock:
            self.running += 1
            self.maximum = max(self.maximum, self.running)
        self.started.set()
        self.release.wait(timeout=2)
        with self.lock:
            self.running -= 1
        return plain

    def verify(self, plain: str, hashed: str) -> bool:
        return self.hash(plain) == hashed

    def needs_rehash(self, hashed: str) -> bool:
        return False


async def test_hash_work_yields_to_loop_and_limits_concurrency() -> None:
    hasher = BlockingHasher()
    executor = BoundedPasswordHasher(hasher, max_concurrency=2)
    jobs = [asyncio.create_task(executor.hash(f"password{iteration}")) for iteration in range(8)]
    ticks = 0
    deadline = time.monotonic() + 0.05
    while time.monotonic() < deadline:
        await asyncio.sleep(0.001)
        ticks += 1
    assert ticks >= 10
    assert hasher.maximum == 2
    hasher.release.set()
    assert await asyncio.gather(*jobs) == [f"password{iteration}" for iteration in range(8)]


async def test_cancelled_waiter_keeps_running_work_in_budget() -> None:
    hasher = BlockingHasher()
    executor = BoundedPasswordHasher(hasher, max_concurrency=1)
    first = asyncio.create_task(executor.hash("first"))
    while not hasher.started.is_set():
        await asyncio.sleep(0.001)
    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first
    second = asyncio.create_task(executor.hash("second"))
    await asyncio.sleep(0.02)
    assert hasher.maximum == 1
    assert not second.done()
    hasher.release.set()
    assert await second == "second"
    assert await executor.verify("ok", "ok") is True
    assert await executor.verify("wrong", "ok") is False


async def test_injected_hasher_preserves_each_callers_context_variables() -> None:
    from contextvars import ContextVar

    tenant: ContextVar[str] = ContextVar("tenant")

    class ContextHasher:
        def hash(self, plain: str) -> str:
            return f"{tenant.get()}:{plain}"

        def verify(self, plain: str, hashed: str) -> bool:
            return self.hash(plain) == hashed

        def needs_rehash(self, hashed: str) -> bool:
            return not hashed.startswith(f"{tenant.get()}:")

    executor = BoundedPasswordHasher(ContextHasher(), max_concurrency=2)

    async def use_tenant(name: str) -> str:
        token = tenant.set(name)
        try:
            hashed = await executor.hash("password")
            assert await executor.verify("password", hashed)
            assert not await executor.needs_rehash(hashed)
            return hashed
        finally:
            tenant.reset(token)

    assert await asyncio.gather(use_tenant("one"), use_tenant("two")) == [
        "one:password",
        "two:password",
    ]
