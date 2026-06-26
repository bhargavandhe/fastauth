from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from bson import ObjectId
from pymongo.asynchronous.database import AsyncDatabase

from fastauth.domain.enums import AuditEventType, JwtAlgorithm, ProviderId, VerificationPurpose
from fastauth.domain.models import (
    Account,
    ApiKey,
    AuditLog,
    JwksKey,
    RefreshToken,
    Session,
    User,
    Verification,
    new_id,
)
from fastauth.storage.beanie import BeanieAdapter
from tests.adapters.adapter_contract import AdapterContract


@pytest.mark.usefixtures("beanie_database")
class TestBeanieAdapter(AdapterContract):
    @pytest.fixture
    async def adapter(self, beanie_database: AsyncDatabase[Any]) -> BeanieAdapter:
        # Wipe collections between tests for isolation.
        for name in await beanie_database.list_collection_names():
            await beanie_database[name].delete_many({})
        return BeanieAdapter(beanie_database)

    async def test_mongo_owned_ids_are_objectids(
        self,
        adapter: BeanieAdapter,
        beanie_database: AsyncDatabase[Any],
    ) -> None:
        user = await adapter.create_user(User(email="mongo-ids@example.com"))
        family_root_id = new_id()
        token = await adapter.create_refresh_token(
            RefreshToken(
                id=family_root_id,
                user_id=user.id,
                token_hash="refresh-token",
                family_id=family_root_id,
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
            kid="signing-key",
            alg=JwtAlgorithm.EDDSA,
            public_key="{}",
            private_key_encrypted=b"\x00",
        )
        await adapter.create_jwks_key(key)
        await adapter.create_audit_log(
            AuditLog(
                event_type=AuditEventType.USER_SIGNED_IN,
                user_id=user.id,
            )
        )

        refresh_doc = await beanie_database["refresh_tokens"].find_one({"_id": ObjectId(token.id)})
        assert refresh_doc is not None
        assert isinstance(refresh_doc["family_id"], ObjectId)
        assert isinstance(refresh_doc["replaced_by"], ObjectId)

        jwks_doc = await beanie_database["jwks_keys"].find_one({"_id": ObjectId(key.id)})
        assert jwks_doc is not None
        assert jwks_doc["kid"] == "signing-key"

        audit_doc = await beanie_database["audit_logs"].find_one({"user_id": ObjectId(user.id)})
        assert audit_doc is not None
        assert isinstance(audit_doc["_id"], ObjectId)
        assert isinstance(audit_doc["user_id"], ObjectId)

    async def test_update_methods_preserve_mongo_objectids(
        self,
        adapter: BeanieAdapter,
        beanie_database: AsyncDatabase[Any],
    ) -> None:
        user = await adapter.create_user(User(email="update-ids@example.com"))

        user.name = "Updated"
        await adapter.update_user(user)
        user_doc = await beanie_database["users"].find_one({"_id": ObjectId(user.id)})
        assert user_doc is not None
        assert isinstance(user_doc["_id"], ObjectId)

        session = await adapter.create_session(
            Session(
                user_id=user.id,
                token_hash="session-update",
                expires_at=datetime.now(UTC) + timedelta(days=1),
            )
        )
        session.user_agent = "updated-agent"
        await adapter.update_session(session)
        session_doc = await beanie_database["sessions"].find_one({"_id": ObjectId(session.id)})
        assert session_doc is not None
        assert isinstance(session_doc["user_id"], ObjectId)

        account = await adapter.create_account(
            Account(
                user_id=user.id,
                provider_id=ProviderId.CREDENTIAL,
                account_id=user.id,
                password="argon2",
            )
        )
        account.scope = "updated"
        await adapter.update_account(account)
        account_doc = await beanie_database["accounts"].find_one({"_id": ObjectId(account.id)})
        assert account_doc is not None
        assert isinstance(account_doc["user_id"], ObjectId)

        verification = await adapter.create_verification(
            Verification(
                identifier="update-ids@example.com",
                value_hash="verification-update",
                purpose=VerificationPurpose.EMAIL_VERIFICATION,
                expires_at=datetime.now(UTC) + timedelta(days=1),
            )
        )
        verification.attempt_count = 1
        await adapter.update_verification(verification)
        verification_doc = await beanie_database["verifications"].find_one(
            {"_id": ObjectId(verification.id)}
        )
        assert verification_doc is not None

        update_family_root_id = new_id()
        token = await adapter.create_refresh_token(
            RefreshToken(
                id=update_family_root_id,
                user_id=user.id,
                token_hash="refresh-update",
                family_id=update_family_root_id,
                expires_at=datetime.now(UTC) + timedelta(days=1),
            )
        )
        token.user_agent = "updated-agent"
        await adapter.update_refresh_token(token)
        token_doc = await beanie_database["refresh_tokens"].find_one({"_id": ObjectId(token.id)})
        assert token_doc is not None
        assert isinstance(token_doc["user_id"], ObjectId)
        assert isinstance(token_doc["family_id"], ObjectId)

        api_key = await adapter.create_api_key(
            ApiKey(
                user_id=user.id,
                name="api-key-update",
                key_hash="api-key-update",
                key_prefix="ak_",
            )
        )
        api_key.name = "updated-name"
        await adapter.update_api_key(api_key)
        api_key_doc = await beanie_database["api_keys"].find_one({"_id": ObjectId(api_key.id)})
        assert api_key_doc is not None
        assert isinstance(api_key_doc["user_id"], ObjectId)

        jwks_key = JwksKey(
            kid="updated-signing-key",
            alg=JwtAlgorithm.EDDSA,
            public_key="{}",
            private_key_encrypted=b"\x00",
        )
        await adapter.create_jwks_key(jwks_key)
        jwks_key.alg = JwtAlgorithm.RS256
        await adapter.update_jwks_key(jwks_key)
        jwks_doc = await beanie_database["jwks_keys"].find_one({"_id": ObjectId(jwks_key.id)})
        assert jwks_doc is not None
        assert jwks_doc["kid"] == "updated-signing-key"
