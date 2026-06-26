from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorDatabase

from fastauth.domain.enums import JwtAlgorithm
from fastauth.domain.models import JwksKey, RefreshToken, User, new_object_id_hex
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

    async def test_mongo_owned_ids_are_objectids(
        self,
        adapter: BeanieAdapter,
        beanie_database: AsyncIOMotorDatabase[Any],
    ) -> None:
        user = await adapter.create_user(User(email="mongo-ids@example.com"))
        token = await adapter.create_refresh_token(
            RefreshToken(
                user_id=user.id,
                token_hash="refresh-token",
                family_id=new_object_id_hex(),
                expires_at=datetime.now(UTC) + timedelta(days=1),
            )
        )
        rotated = RefreshToken(
            id="temporary-id",
            user_id=user.id,
            token_hash="refresh-token-2",
            family_id=token.family_id,
            expires_at=datetime.now(UTC) + timedelta(days=1),
        )
        await adapter.rotate_refresh_token(
            current_token_id=token.id,
            new_token=rotated,
            consumed_at=datetime.now(UTC),
        )
        key = JwksKey(
            kid=new_object_id_hex(),
            alg=JwtAlgorithm.EDDSA,
            public_key="{}",
            private_key_encrypted=b"\x00",
        )
        await adapter.create_jwks_key(key)

        refresh_doc = await beanie_database["refresh_tokens"].find_one({"_id": ObjectId(token.id)})
        assert refresh_doc is not None
        assert isinstance(refresh_doc["family_id"], ObjectId)
        assert isinstance(refresh_doc["replaced_by"], ObjectId)

        jwks_doc = await beanie_database["jwks_keys"].find_one({"_id": ObjectId(key.id)})
        assert jwks_doc is not None
        assert isinstance(jwks_doc["kid"], ObjectId)
