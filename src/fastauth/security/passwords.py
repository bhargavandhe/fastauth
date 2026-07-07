"""Password hashing primitives."""

from __future__ import annotations

from typing import Annotated, Protocol, cast, runtime_checkable

from argon2 import PasswordHasher as Argon2PasswordHasher
from argon2 import Type
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from pydantic import Field, SecretStr, TypeAdapter, ValidationError

from fastauth.exceptions import InvalidRequestError
from fastauth.options import PasswordOptions

__all__ = ["Argon2idHasher", "CredentialService", "PasswordHasher"]


@runtime_checkable
class PasswordHasher(Protocol):
    def hash(self, plain: str) -> str: ...
    def verify(self, plain: str, hashed: str) -> bool: ...
    def needs_rehash(self, hashed: str) -> bool: ...


class CredentialService:
    def __init__(self, config: PasswordOptions) -> None:
        self.config = config
        password_value = Annotated[
            str,
            Field(min_length=config.min_length, max_length=config.max_length),
        ]
        self.password_adapter = cast(TypeAdapter[str], TypeAdapter(password_value))

    def validate_password(self, password: SecretStr) -> str:
        value = password.get_secret_value()
        try:
            return self.password_adapter.validate_python(value, strict=True)
        except ValidationError as exc:
            first_error = exc.errors()[0]
            message = str(first_error.get("msg", "password does not satisfy policy"))
            raise InvalidRequestError(message=message) from exc


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
