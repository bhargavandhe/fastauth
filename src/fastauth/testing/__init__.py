"""Testing contracts and helpers for FastAuth extension authors."""

from __future__ import annotations

from fastauth.testing.adapter_contract import (
    AdapterContract,
    ApiKeyAdapterContract,
    AuditLogAdapterContract,
    ContractAdapter,
    CoreAdapterContract,
    FullAdapterContract,
    JwksAdapterContract,
    RateLimitAdapterContract,
    RefreshTokenAdapterContract,
)

__all__ = [
    "AdapterContract",
    "ApiKeyAdapterContract",
    "AuditLogAdapterContract",
    "ContractAdapter",
    "CoreAdapterContract",
    "FullAdapterContract",
    "JwksAdapterContract",
    "RateLimitAdapterContract",
    "RefreshTokenAdapterContract",
]
