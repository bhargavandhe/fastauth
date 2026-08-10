"""Compatibility import for the public adapter contract test suite."""

from __future__ import annotations

from fastauth.testing.adapter_contract import (
    AdapterContract,
    ApiKeyAdapterContract,
    AuditLogAdapterContract,
    ContractAdapter,
    CoreAdapterContract,
    FullAdapterContract,
    JwksAdapterContract,
    MaintenanceAdapterContract,
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
    "MaintenanceAdapterContract",
    "RateLimitAdapterContract",
    "RefreshTokenAdapterContract",
]
