from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from bson import ObjectId
from pymongo.asynchronous.database import AsyncDatabase
from pytest import MonkeyPatch

from fastauth.domain.enums import (
    AuditEventType,
    JwtAlgorithm,
    PluginMigrationMode,
    ProviderId,
    VerificationPurpose,
)
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
from fastauth.plugins.migrations import (
    PluginMigrationFingerprintError,
    PluginMigrationPendingError,
    PluginSchemaPlan,
    build_schema_plan,
)
from fastauth.plugins.schema import (
    FieldSpec,
    IndexSpec,
    MigrationSpec,
    PluginFieldType,
    PluginSchema,
    TableSpec,
)
from fastauth.storage.beanie import BeanieAdapter, init_beanie_documents
from fastauth.storage.beanie.plugin_migrations import execute_mongo_plugin_migrations
from tests.adapters.adapter_contract import FullAdapterContract
from tests.adapters.session_matrix import SessionMatrixContract


def plugin_plan(
    *,
    versions: tuple[int, ...] = (1,),
    field_type: PluginFieldType = "str",
) -> PluginSchemaPlan:
    return build_schema_plan(
        (
            PluginSchema(
                plugin_id="adapter-contract",
                tables=(
                    TableSpec(
                        name="plugin_records",
                        fields=(
                            FieldSpec(name="id", python_type=field_type),
                            FieldSpec(name="label", python_type="str"),
                        ),
                        indexes=(
                            IndexSpec(
                                name="plugin_records_label_idx",
                                fields=("label",),
                            ),
                        ),
                    ),
                ),
                migrations=tuple(
                    MigrationSpec(name=f"plugin_records_v{version}", version=version)
                    for version in versions
                ),
            ),
        ),
    )


@pytest.mark.usefixtures("beanie_database")
class TestBeanieAdapter(FullAdapterContract, SessionMatrixContract):
    @pytest.fixture
    async def adapter(self, beanie_database: AsyncDatabase[Any]) -> BeanieAdapter:
        # Wipe collections between tests for isolation.
        for name in await beanie_database.list_collection_names():
            await beanie_database[name].delete_many({})
        return BeanieAdapter(beanie_database)

    async def test_custom_collection_affixes_select_custom_collections(
        self,
        beanie_database: AsyncDatabase[Any],
    ) -> None:
        await init_beanie_documents(
            beanie_database,
            collection_prefix="tenant_",
            collection_suffix="_auth",
        )
        adapter = BeanieAdapter(
            beanie_database,
            collection_prefix="tenant_",
            collection_suffix="_auth",
        )

        user = await adapter.create_user(User(email="custom-collections@example.com"))
        session = await adapter.create_session(
            Session(
                user_id=user.id,
                token_hash="custom-session",
                expires_at=datetime.now(UTC) + timedelta(days=1),
            )
        )

        default_user = await beanie_database["users"].find_one({"_id": ObjectId(user.id)})
        custom_user = await beanie_database["tenant_users_auth"].find_one(
            {"_id": ObjectId(user.id)}
        )
        default_session = await beanie_database["sessions"].find_one({"_id": ObjectId(session.id)})
        custom_session = await beanie_database["tenant_sessions_auth"].find_one(
            {"_id": ObjectId(session.id)}
        )

        assert default_user is None
        assert custom_user is not None
        assert default_session is None
        assert custom_session is not None
        assert await adapter.get_user_by_email("custom-collections@example.com") == user
        assert await adapter.get_session_by_token_hash("custom-session") == session

    async def test_mongo_owned_ids_are_objectids(
        self,
        adapter: BeanieAdapter,
        beanie_database: AsyncDatabase[Any],
    ) -> None:
        user = await adapter.create_user(User(email="mongo-ids@example.com"))
        session = await adapter.create_session(
            Session(
                user_id=user.id,
                token_hash="mongo-ids-session",
                expires_at=datetime.now(UTC) + timedelta(hours=1),
            )
        )
        family_root_id = new_id()
        family_created_at = datetime.now(UTC)
        token = await adapter.create_refresh_token(
            RefreshToken(
                id=family_root_id,
                user_id=user.id,
                session_id=session.id,
                token_hash="refresh-token",
                family_id=family_root_id,
                family_created_at=family_created_at,
                expires_at=datetime.now(UTC) + timedelta(days=1),
            )
        )
        rotated = RefreshToken(
            id="temporary-id",
            user_id=user.id,
            session_id=session.id,
            token_hash="refresh-token-2",
            family_id=token.family_id,
            family_created_at=family_created_at,
            expires_at=datetime.now(UTC) + timedelta(days=1),
        )
        await adapter.rotate_refresh_token(
            current_token_id=token.id,
            new_token=rotated,
            consumed_at=datetime.now(UTC),
        )
        key = JwksKey(
            kid="signing-key",
            alg=JwtAlgorithm.ED25519,
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

    async def test_delete_refresh_token_family_fails_closed_when_session_delete_fails(
        self,
        adapter: BeanieAdapter,
        monkeypatch: MonkeyPatch,
    ) -> None:
        user = await adapter.create_user(User(email="family-session-fail@example.com"))
        session = await adapter.create_session(
            Session(
                user_id=user.id,
                token_hash="family-session-fail-session",
                expires_at=datetime.now(UTC) + timedelta(hours=1),
            )
        )
        root_id = new_id()
        token = await adapter.create_refresh_token(
            RefreshToken(
                id=root_id,
                user_id=user.id,
                session_id=session.id,
                token_hash="family-session-fail-root",
                family_id=root_id,
                family_created_at=datetime.now(UTC),
                expires_at=datetime.now(UTC) + timedelta(days=1),
            )
        )
        original_find = adapter.session_doc.find

        class FailingDeleteQuery:
            async def delete(self) -> None:
                raise RuntimeError("session delete failed")

        def failing_find(*args: object, **kwargs: object) -> object:
            del args, kwargs
            return FailingDeleteQuery()

        monkeypatch.setattr(adapter.session_doc, "find", failing_find)

        with pytest.raises(RuntimeError, match="session delete failed"):
            await adapter.delete_refresh_token_family(token.family_id)

        monkeypatch.setattr(adapter.session_doc, "find", original_find)
        assert await adapter.get_refresh_token_by_hash("family-session-fail-root") is None
        assert await adapter.get_session_by_token_hash("family-session-fail-session") is None
        # A failed cleanup remains retryable; revoked family state is authoritative.
        cleanup = await adapter.delete_refresh_token_family(token.family_id)
        assert cleanup.deleted_tokens == 1
        assert cleanup.deleted_sessions == 1

    async def test_delete_refresh_token_family_deletes_sessions_and_tokens(
        self,
        adapter: BeanieAdapter,
    ) -> None:
        user = await adapter.create_user(User(email="family-delete-success@example.com"))
        session = await adapter.create_session(
            Session(
                user_id=user.id,
                token_hash="family-delete-success-session",
                expires_at=datetime.now(UTC) + timedelta(hours=1),
            )
        )
        root_id = new_id()
        token = await adapter.create_refresh_token(
            RefreshToken(
                id=root_id,
                user_id=user.id,
                session_id=session.id,
                token_hash="family-delete-success-root",
                family_id=root_id,
                family_created_at=datetime.now(UTC),
                expires_at=datetime.now(UTC) + timedelta(days=1),
            )
        )

        revoked = await adapter.delete_refresh_token_family(token.family_id)

        assert revoked.deleted_tokens == 1
        assert revoked.deleted_sessions == 1
        assert revoked.session_ids == frozenset({session.id})
        assert await adapter.get_refresh_token_by_hash("family-delete-success-root") is None
        assert await adapter.get_session_by_token_hash("family-delete-success-session") is None

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
        update_session = await adapter.create_session(
            Session(
                user_id=user.id,
                token_hash="refresh-update-session",
                expires_at=datetime.now(UTC) + timedelta(hours=1),
            )
        )
        token = await adapter.create_refresh_token(
            RefreshToken(
                id=update_family_root_id,
                user_id=user.id,
                session_id=update_session.id,
                token_hash="refresh-update",
                family_id=update_family_root_id,
                family_created_at=datetime.now(UTC),
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
            alg=JwtAlgorithm.ED25519,
            public_key="{}",
            private_key_encrypted=b"\x00",
        )
        await adapter.create_jwks_key(jwks_key)
        jwks_key.alg = JwtAlgorithm.RS256
        await adapter.update_jwks_key(jwks_key)
        jwks_doc = await beanie_database["jwks_keys"].find_one({"_id": ObjectId(jwks_key.id)})
        assert jwks_doc is not None
        assert jwks_doc["kid"] == "updated-signing-key"

    async def test_plugin_migrations_apply_replay_check_and_fingerprint(
        self,
        beanie_database: AsyncDatabase[Any],
    ) -> None:
        prefix = f"tenant_{new_id()[:8]}_"
        first = await execute_mongo_plugin_migrations(
            beanie_database,
            plan=plugin_plan(),
            mode=PluginMigrationMode.APPLY,
            collection_prefix=prefix,
            collection_suffix="_auth",
        )
        assert len(first.applied) == 1

        replay = await execute_mongo_plugin_migrations(
            beanie_database,
            plan=plugin_plan(),
            mode=PluginMigrationMode.APPLY,
            collection_prefix=prefix,
            collection_suffix="_auth",
        )
        assert replay.applied == ()

        with pytest.raises(PluginMigrationPendingError):
            await execute_mongo_plugin_migrations(
                beanie_database,
                plan=plugin_plan(versions=(1, 2)),
                mode=PluginMigrationMode.CHECK,
                collection_prefix=prefix,
                collection_suffix="_auth",
            )

        with pytest.raises(PluginMigrationFingerprintError):
            await execute_mongo_plugin_migrations(
                beanie_database,
                plan=plugin_plan(field_type="int"),
                mode=PluginMigrationMode.CHECK,
                collection_prefix=prefix,
                collection_suffix="_auth",
            )

        names = await beanie_database.list_collection_names()
        assert f"{prefix}plugin_records_auth" in names
        assert f"{prefix}plugin_migrations_auth" in names

    async def test_plugin_migrations_converge_under_concurrent_application(
        self,
        beanie_database: AsyncDatabase[Any],
    ) -> None:
        prefix = f"concurrent_{new_id()[:8]}_"

        async def apply_once() -> int:
            result = await execute_mongo_plugin_migrations(
                beanie_database,
                plan=plugin_plan(),
                mode=PluginMigrationMode.APPLY,
                collection_prefix=prefix,
                collection_suffix="",
            )
            return len(result.applied)

        assert sorted(await asyncio.gather(apply_once(), apply_once())) == [0, 1]


async def test_family_revocation_snapshot_racing_rotation_cannot_leave_successor(
    beanie_database: AsyncDatabase[Any],
    monkeypatch: MonkeyPatch,
) -> None:
    adapter = BeanieAdapter(beanie_database)
    user = await adapter.create_user(User(email="family-snapshot@example.com"))
    old_session = await adapter.create_session(
        Session(
            user_id=user.id,
            token_hash="old-session-race",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
    )
    root_id = new_id()
    root = await adapter.create_refresh_token(
        RefreshToken(
            id=root_id,
            family_id=root_id,
            user_id=user.id,
            session_id=old_session.id,
            token_hash="root-race",
            family_created_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(days=1),
        )
    )
    replacement = await adapter.create_session(
        Session(
            user_id=user.id,
            token_hash="replacement-race",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
    )
    snapshot_taken, continue_revoke = asyncio.Event(), asyncio.Event()
    original_find = adapter.refresh_token_doc.find

    class SnapshotQuery:
        def __init__(self, query: Any) -> None:
            self.query = query

        async def to_list(self) -> list[Any]:
            snapshot = await self.query.to_list()
            snapshot_taken.set()
            await continue_revoke.wait()
            return snapshot

        async def delete(self) -> Any:
            return await self.query.delete()

    def find_with_snapshot(query: Any, *args: Any, **kwargs: Any) -> Any:
        original = original_find(query, *args, **kwargs)
        if query == {"family_id": ObjectId(root.family_id)}:
            return SnapshotQuery(original)
        return original

    monkeypatch.setattr(adapter.refresh_token_doc, "find", find_with_snapshot)
    revoking = asyncio.create_task(adapter.delete_refresh_token_family(root.family_id))
    await asyncio.wait_for(snapshot_taken.wait(), timeout=10)
    successor = RefreshToken(
        user_id=user.id,
        session_id=replacement.id,
        token_hash="successor-race",
        family_id=root.family_id,
        family_created_at=root.family_created_at,
        expires_at=datetime.now(UTC) + timedelta(days=1),
    )
    try:
        rotated = await adapter.rotate_refresh_token(
            current_token_id=root.id, new_token=successor, consumed_at=datetime.now(UTC)
        )
    finally:
        continue_revoke.set()
    await asyncio.wait_for(revoking, timeout=10)
    assert await adapter.get_session_by_token_hash(replacement.token_hash) is None
    assert await adapter.get_refresh_token_by_hash(successor.token_hash) is None
    assert rotated is None


async def test_v015_mongo_migration_replaces_indexes_and_deduplicates_challenges(
    beanie_database: AsyncDatabase[Any],
) -> None:
    from fastauth.storage.beanie import migrate_mongo_storage_v015, preflight_mongo_storage_v015

    prefix = f"migration_{new_id()[:8]}_"
    users = beanie_database[f"{prefix}users"]
    verifications = beanie_database[f"{prefix}verifications"]
    await users.create_index("username", unique=True, sparse=True, name="users_username_unique")
    await users.insert_one({"email": "one@example.com", "username": None})
    await verifications.create_index(
        [("identifier", 1), ("purpose", 1), ("value_hash", 1)],
        unique=True,
        name="verifications_lookup_unique",
    )
    now = datetime.now(UTC)
    for age, value in [(2, "old"), (1, "new")]:
        await verifications.insert_one(
            {
                "identifier": "migration@example.com",
                "purpose": "password-reset",
                "value_hash": value,
                "created_at": now - timedelta(seconds=age),
                "updated_at": now,
                "expires_at": now + timedelta(minutes=5),
                "attempt_count": 0,
            }
        )
    with pytest.raises(RuntimeError, match=r"0\.15 migration"):
        await preflight_mongo_storage_v015(beanie_database, collection_prefix=prefix)
    migrated = await migrate_mongo_storage_v015(beanie_database, collection_prefix=prefix)
    assert migrated.removed_username_indexes == ("users_username_unique",)
    assert migrated.deleted_superseded_verifications == 1
    await preflight_mongo_storage_v015(beanie_database, collection_prefix=prefix)
    await users.insert_one({"email": "two@example.com", "username": None})
    await users.insert_one({"email": "named@example.com", "username": "unique-name"})
    from pymongo.errors import DuplicateKeyError

    with pytest.raises(DuplicateKeyError):
        await users.insert_one({"email": "duplicate@example.com", "username": "unique-name"})
    assert (await verifications.find_one({})) is not None
    assert await verifications.count_documents({"value_hash": "old"}) == 0
    replayed = await migrate_mongo_storage_v015(beanie_database, collection_prefix=prefix)
    assert replayed.deleted_superseded_verifications == 0
