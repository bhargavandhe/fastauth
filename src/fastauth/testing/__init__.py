"""Testing contracts and helpers for FastAuth extension authors."""

from __future__ import annotations

from fastauth.testing.adapter_contract import (
    AdapterContract,
    ApiKeyAdapterContract,
    AuditLogAdapterContract,
    ContractAdapter,
    CoreAdapterContract,
    CreationAdapterContract,
    FullAdapterContract,
    JwksAdapterContract,
    PasswordRehashAdapterContract,
    RateLimitAdapterContract,
    RefreshTokenAdapterContract,
    UserStatusAdapterContract,
)

__all__ = [
    "AdapterContract",
    "ApiKeyAdapterContract",
    "AuditLogAdapterContract",
    "ContractAdapter",
    "CoreAdapterContract",
    "CreationAdapterContract",
    "FullAdapterContract",
    "JwksAdapterContract",
    "PasswordRehashAdapterContract",
    "RateLimitAdapterContract",
    "RefreshTokenAdapterContract",
    "UserStatusAdapterContract",
]
