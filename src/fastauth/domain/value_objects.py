"""Semantic Pydantic value objects used at public and domain boundaries."""

from __future__ import annotations

from typing import Annotated

from pydantic import ConfigDict, JsonValue, RootModel, StringConstraints, field_validator

__all__ = [
    "AccountId",
    "ApiKeyId",
    "ApiKeyMetadata",
    "ApiKeyPrefix",
    "AuditEventData",
    "EncryptedSecret",
    "JsonObject",
    "NonEmptyString",
    "PasswordHash",
    "PermissionSet",
    "RawToken",
    "RefreshTokenId",
    "SessionId",
    "TokenHash",
    "UserId",
    "UserMetadata",
    "VerificationId",
    "VerificationValueHash",
    "normalize_email",
]


HexId = Annotated[
    str,
    StringConstraints(strict=True, pattern=r"^[a-f0-9]{24,32}$"),
]

Sha256Hex = Annotated[
    str,
    StringConstraints(strict=True, pattern=r"^[a-f0-9]{64}$"),
]

NonEmptyString = Annotated[str, StringConstraints(strict=True, min_length=1)]


class StringValue(RootModel[str]):
    """Base for string-backed value objects that serialize as plain strings."""

    model_config = ConfigDict(frozen=True)


class UserId(RootModel[HexId]):
    model_config = ConfigDict(frozen=True)


class SessionId(RootModel[HexId]):
    model_config = ConfigDict(frozen=True)


class AccountId(RootModel[HexId]):
    model_config = ConfigDict(frozen=True)


class RefreshTokenId(RootModel[HexId]):
    model_config = ConfigDict(frozen=True)


class VerificationId(RootModel[HexId]):
    model_config = ConfigDict(frozen=True)


class ApiKeyId(RootModel[HexId]):
    model_config = ConfigDict(frozen=True)


class TokenHash(RootModel[Sha256Hex]):
    model_config = ConfigDict(frozen=True)


class VerificationValueHash(TokenHash):
    pass


class PasswordHash(RootModel[NonEmptyString]):
    model_config = ConfigDict(frozen=True)

    @field_validator("root")
    @classmethod
    def validate_argon2_hash(cls, value: str) -> str:
        if not value.startswith("$argon2"):
            raise ValueError("password hash must be an argon2 hash")
        return value



class RawToken(RootModel[NonEmptyString]):
    model_config = ConfigDict(frozen=True)


ApiKeyPrefixValue = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=32),
]


class ApiKeyPrefix(RootModel[ApiKeyPrefixValue]):
    model_config = ConfigDict(frozen=True)


class EncryptedSecret(RootModel[bytes]):
    model_config = ConfigDict(frozen=True)


class JsonObject(RootModel[dict[str, JsonValue]]):
    """Open-ended but JSON-serializable object."""

    model_config = ConfigDict(frozen=True)


class UserMetadata(JsonObject):
    pass


class ApiKeyMetadata(JsonObject):
    pass


class AuditEventData(JsonObject):
    pass


class PermissionSet(RootModel[dict[str, frozenset[str]]]):
    model_config = ConfigDict(frozen=True)


def normalize_email(value: object) -> object:
    if value is None:
        return None
    return str(value).lower()
