from __future__ import annotations

from fastauth.testing import (
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
from fastauth.testing.adapter_contract import (
    AdapterContract as DirectAdapterContract,
)
from fastauth.testing.adapter_contract import (
    __all__ as adapter_contract_all,
)


def test_adapter_contract_is_publicly_importable() -> None:
    assert AdapterContract is DirectAdapterContract
    assert AdapterContract is FullAdapterContract
    assert ContractAdapter.__name__ == "ContractAdapter"


def test_split_adapter_contracts_are_publicly_importable() -> None:
    assert CoreAdapterContract.__name__ == "CoreAdapterContract"
    assert RefreshTokenAdapterContract.__name__ == "RefreshTokenAdapterContract"
    assert ApiKeyAdapterContract.__name__ == "ApiKeyAdapterContract"
    assert JwksAdapterContract.__name__ == "JwksAdapterContract"
    assert AuditLogAdapterContract.__name__ == "AuditLogAdapterContract"
    assert RateLimitAdapterContract.__name__ == "RateLimitAdapterContract"
    assert FullAdapterContract.__name__ == "FullAdapterContract"


def test_full_adapter_contract_composes_split_contracts() -> None:
    assert issubclass(FullAdapterContract, CoreAdapterContract)
    assert issubclass(FullAdapterContract, RefreshTokenAdapterContract)
    assert issubclass(FullAdapterContract, ApiKeyAdapterContract)
    assert issubclass(FullAdapterContract, JwksAdapterContract)
    assert issubclass(FullAdapterContract, AuditLogAdapterContract)
    assert issubclass(FullAdapterContract, RateLimitAdapterContract)


def test_adapter_contract_module_exports_split_contracts() -> None:
    assert set(adapter_contract_all) == {
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
    }
