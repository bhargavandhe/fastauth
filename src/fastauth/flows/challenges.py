"""Atomic consumption shared by opaque verification-link flows."""

from __future__ import annotations

from datetime import UTC, datetime

from fastauth.domain.enums import VerificationPurpose
from fastauth.domain.models import Verification
from fastauth.exceptions import TokenExpiredError, TokenInvalidError
from fastauth.runtime.context import AuthContext


async def consume_token(
    context: AuthContext,
    identifier: str,
    purpose: VerificationPurpose,
    value_hash: str,
    *,
    label: str,
) -> Verification:
    result = await context.adapter.attempt_verification(
        identifier,
        purpose,
        value_hash,
        now=datetime.now(UTC),
    )
    if result.status == "expired":
        raise TokenExpiredError(message=f"{label} token expired")
    if result.status != "accepted" or result.verification is None:
        raise TokenInvalidError(message=f"invalid {label} token")
    return result.verification
