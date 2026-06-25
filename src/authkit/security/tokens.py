"""Token generation, hashing, and signed cookie packing."""

from __future__ import annotations

import hashlib
import hmac
import secrets

from itsdangerous import BadSignature, URLSafeSerializer
from pydantic import BaseModel, ConfigDict, SecretStr

__all__ = ["SignedCookieValue", "TokenPair", "TokenService"]


class TokenPair(BaseModel):
    """A plaintext token paired with its SHA-256 hash for at-rest storage.

    Pydantic v2 BaseModel (not ``NamedTuple``) per the project-wide "Pydantic
    everywhere" rule — see CONTRIBUTING.md.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")
    plain: str
    hashed: str


class TokenService:
    """Generates URL-safe tokens and produces SHA-256 hex digests for storage."""

    def __init__(self, byte_length: int = 32) -> None:
        self.byte_length = byte_length

    def generate_pair(self) -> TokenPair:
        plain = secrets.token_urlsafe(self.byte_length)
        return TokenPair(plain=plain, hashed=self.hash_only(plain))

    def hash_only(self, plain: str) -> str:
        return hashlib.sha256(plain.encode("utf-8")).hexdigest()

    def verify_match(self, plain: str, hashed: str) -> bool:
        return hmac.compare_digest(self.hash_only(plain), hashed)


class SignedCookieValue:
    """Signs/verifies a cookie payload with key rotation."""

    SALT = "authkit.cookie"

    def __init__(self, secret_key: SecretStr, rotation: list[SecretStr]) -> None:
        self.signer = URLSafeSerializer(secret_key.get_secret_value(), salt=self.SALT)
        self.verifiers = [
            URLSafeSerializer(secret.get_secret_value(), salt=self.SALT) for secret in rotation
        ]

    def pack(self, value: str) -> str:
        return self.signer.dumps(value)

    def unpack(self, signed: str) -> str | None:
        for serializer in (self.signer, *self.verifiers):
            try:
                loaded = serializer.loads(signed)
            except BadSignature:
                continue
            if isinstance(loaded, str):
                return loaded
        return None
