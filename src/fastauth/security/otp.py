"""Numeric one-time-password generation and verification.

Mirrors :class:`fastauth.security.tokens.TokenService` but emits
fixed-length decimal-digit codes (default 6) suitable for SMS / email
delivery rather than URL-safe opaque tokens. Codes are stored as their
SHA-256 hex digest so a database breach doesn't leak the live OTPs.

Verification is constant-time via :func:`hmac.compare_digest`. The
service is stateless — persistence (:class:`Verification` rows) and
expiry / attempt enforcement happen one layer up in
:mod:`fastauth.flows.email_otp`.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

from pydantic import BaseModel, ConfigDict

__all__ = ["OtpPair", "OtpService"]


class OtpPair(BaseModel):
    """A plaintext OTP paired with its SHA-256 hash for at-rest storage.

    Pydantic v2 frozen ``BaseModel`` per the project's "Pydantic
    everywhere" rule.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")
    plain: str
    hashed: str


class OtpService:
    """Generates fixed-length numeric OTPs and SHA-256-hashes them for storage."""

    def __init__(self, length: int = 6) -> None:
        if length < 4:
            raise ValueError("OTP length must be at least 4 digits")
        if length > 10:
            raise ValueError("OTP length must be at most 10 digits")
        self.length = length
        # secrets.SystemRandom uses os.urandom under the hood and is the
        # cryptographically-secure choice for OTP generation. Falling back
        # to random.randint would be insecure (predictable PRNG state).
        self.rng = secrets.SystemRandom()

    def generate_pair(self) -> OtpPair:
        plain = "".join(str(self.rng.randint(0, 9)) for _ in range(self.length))
        return OtpPair(plain=plain, hashed=self.hash_only(plain))

    def hash_only(self, plain: str) -> str:
        return hashlib.sha256(plain.encode("utf-8")).hexdigest()

    def verify_match(self, plain: str, hashed: str) -> bool:
        return hmac.compare_digest(self.hash_only(plain), hashed)
