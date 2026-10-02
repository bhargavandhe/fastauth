"""Typed decisions shared by atomic verification stores.

Call ``apply_verification_attempt`` only while holding the backend's atomic
mutation boundary. A read followed by an unguarded write is never sufficient.
"""

from __future__ import annotations

import hmac
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict

from fastauth.domain.models import Verification


class VerificationAttempt(BaseModel):
    model_config = ConfigDict(frozen=True)

    status: Literal["accepted", "invalid", "expired", "exhausted", "absent"]
    attempt_count: int = 0
    verification: Verification | None = None


def apply_verification_attempt(
    row: Verification | None,
    value_hash: str,
    *,
    now: datetime,
    max_attempts: int | None,
    consume: bool,
) -> VerificationAttempt:
    """Decide and mutate one challenge inside a store's atomic boundary."""
    if max_attempts is not None and max_attempts < 1:
        raise ValueError("max_attempts must be positive")
    if row is None or row.consumed_at is not None:
        return VerificationAttempt(status="absent")
    if row.expires_at <= now:
        row.consumed_at = now
        return VerificationAttempt(status="expired", attempt_count=row.attempt_count)
    if max_attempts is not None and row.attempt_count >= max_attempts:
        row.consumed_at = now
        return VerificationAttempt(status="exhausted", attempt_count=row.attempt_count)
    if not hmac.compare_digest(row.value_hash, value_hash):
        row.attempt_count += 1
        exhausted = max_attempts is not None and row.attempt_count >= max_attempts
        if exhausted:
            row.consumed_at = now
        row.updated_at = now
        return VerificationAttempt(
            status="exhausted" if exhausted else "invalid",
            attempt_count=row.attempt_count,
        )
    if consume:
        row.consumed_at = now
        row.updated_at = now
    return VerificationAttempt(
        status="accepted",
        attempt_count=row.attempt_count,
        verification=row.model_copy(deep=True),
    )
