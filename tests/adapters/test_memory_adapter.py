from __future__ import annotations

import pytest

from fastauth.storage.memory import InMemoryAdapter
from tests.adapters.adapter_contract import FullAdapterContract


class TestInMemoryAdapter(FullAdapterContract):
    @pytest.fixture
    async def adapter(self) -> InMemoryAdapter:
        return InMemoryAdapter()
