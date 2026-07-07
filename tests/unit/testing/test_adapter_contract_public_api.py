from __future__ import annotations

from fastauth.testing import AdapterContract, ContractAdapter
from fastauth.testing.adapter_contract import AdapterContract as DirectAdapterContract


def test_adapter_contract_is_publicly_importable() -> None:
    assert AdapterContract is DirectAdapterContract
    assert ContractAdapter.__name__ == "ContractAdapter"
