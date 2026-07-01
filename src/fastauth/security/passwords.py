"""Password hashing primitives."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from argon2 import PasswordHasher as Argon2PasswordHasher
from argon2 import Type
from argon2.exceptions import InvalidHashError, VerifyMismatchError

from fastauth.options import PasswordOptions

__all__ = ["Argon2idHasher", "PasswordHasher"]


@runtime_checkable
class PasswordHasher(Protocol):
    def hash(self, plain: str) -> str: ...
    def verify(self, plain: str, hashed: str) -> bool: ...
    def needs_rehash(self, hashed: str) -> bool: ...


class Argon2idHasher:
    def __init__(self, config: PasswordOptions) -> None:
        self.config = config
        self.engine = Argon2PasswordHasher(
            time_cost=config.argon2_time_cost,
            memory_cost=config.argon2_memory_cost_kib,
            parallelism=config.argon2_parallelism,
            type=Type.ID,
        )

    def hash(self, plain: str) -> str:
        return self.engine.hash(plain)

    def verify(self, plain: str, hashed: str) -> bool:
        try:
            return self.engine.verify(hashed, plain)
        except (VerifyMismatchError, InvalidHashError):
            return False

    def needs_rehash(self, hashed: str) -> bool:
        try:
            return self.engine.check_needs_rehash(hashed)
        except InvalidHashError:
            return True
