from __future__ import annotations

from authkit.config import PasswordConfig
from authkit.security.passwords import Argon2idHasher


def test_hash_and_verify_round_trip() -> None:
    hasher = Argon2idHasher(PasswordConfig())
    hashed = hasher.hash("correct horse battery staple")
    assert hashed != "correct horse battery staple"
    assert hasher.verify("correct horse battery staple", hashed) is True
    assert hasher.verify("wrong password", hashed) is False


def test_hash_is_random_per_call() -> None:
    hasher = Argon2idHasher(PasswordConfig())
    first = hasher.hash("same")
    second = hasher.hash("same")
    assert first != second
    assert hasher.verify("same", first)
    assert hasher.verify("same", second)


def test_needs_rehash_when_config_changes() -> None:
    weak = Argon2idHasher(PasswordConfig(argon2_time_cost=1, argon2_memory_cost_kib=8192))
    strong = Argon2idHasher(PasswordConfig(argon2_time_cost=3, argon2_memory_cost_kib=65536))
    legacy = weak.hash("hello")
    assert strong.needs_rehash(legacy) is True
    assert strong.needs_rehash(strong.hash("hello")) is False
