from __future__ import annotations

from typing import Any

import pytest
from motor.motor_asyncio import AsyncIOMotorDatabase

from fastauth.storage.beanie import BeanieAdapter
from tests.adapters.adapter_contract import AdapterContract


@pytest.mark.usefixtures("beanie_database")
class TestBeanieAdapter(AdapterContract):
    @pytest.fixture
    async def adapter(self, beanie_database: AsyncIOMotorDatabase[Any]) -> BeanieAdapter:
        # Wipe collections between tests for isolation.
        for name in await beanie_database.list_collection_names():
            await beanie_database[name].delete_many({})
        return BeanieAdapter(beanie_database)
