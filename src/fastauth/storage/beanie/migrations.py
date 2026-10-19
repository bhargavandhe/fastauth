"""Explicit, offline MongoDB index migration for the 0.15 storage contract."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict
from pymongo.asynchronous.database import AsyncDatabase


class MongoStorageMigrationResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    removed_username_indexes: tuple[str, ...]
    deleted_superseded_verifications: int


async def preflight_mongo_storage_v015(
    database: AsyncDatabase[Any],
    *,
    collection_prefix: str = "",
    collection_suffix: str = "",
) -> None:
    """Reject old indexes before Beanie silently attempts an incompatible upgrade."""
    users = database[f"{collection_prefix}users{collection_suffix}"]
    for index in (await users.index_information()).values():
        if index.get("key") == [("username", 1)] and index.get("unique"):
            if index.get("partialFilterExpression") != {"username": {"$type": "string"}}:
                raise RuntimeError(
                    "Mongo storage needs the 0.15 migration: stop auth writers and run "
                    "migrate_mongo_storage_v015 before starting FastAuth"
                )
    challenges = database[f"{collection_prefix}verifications{collection_suffix}"]
    indexes = await challenges.index_information()
    if "verifications_lookup_unique" in indexes and "verifications_current_unique" not in indexes:
        raise RuntimeError(
            "Mongo storage needs atomic verification migration: stop auth writers and run "
            "migrate_mongo_storage_v015 before starting FastAuth 0.15"
        )


async def migrate_mongo_storage_v015(
    database: AsyncDatabase[Any],
    *,
    collection_prefix: str = "",
    collection_suffix: str = "",
) -> MongoStorageMigrationResult:
    """Upgrade an offline database; repeatable, never run with active auth writers.

    First validate/build string-only username uniqueness, then remove restrictive
    legacy username indexes. Keep only the newest challenge per identifier and
    purpose, including expired/consumed challenges, so an older token cannot be
    resurrected. No replica-set transactions are required.
    """
    users = database[f"{collection_prefix}users{collection_suffix}"]
    await users.create_index(
        "username",
        unique=True,
        name="users_username_strings_unique",
        partialFilterExpression={"username": {"$type": "string"}},
    )
    removed: list[str] = []
    for name, index in (await users.index_information()).items():
        if name == "users_username_strings_unique":
            continue
        if index.get("key") == [("username", 1)] and index.get("unique"):
            if index.get("partialFilterExpression") != {"username": {"$type": "string"}}:
                await users.drop_index(name)
                removed.append(name)
    challenges = database[f"{collection_prefix}verifications{collection_suffix}"]
    seen: set[tuple[str, str]] = set()
    deleted = 0
    cursor = challenges.find({}, projection={"_id": 1, "identifier": 1, "purpose": 1}).sort(
        [("created_at", -1), ("_id", -1)],
    )
    async for row in cursor:
        key = (str(row["identifier"]), str(row["purpose"]))
        if key in seen:
            result = await challenges.delete_one({"_id": row["_id"]})
            deleted += result.deleted_count
        else:
            seen.add(key)
    await challenges.create_index(
        [("identifier", 1), ("purpose", 1)],
        unique=True,
        name="verifications_current_unique",
    )
    await challenges.update_many(
        {"consumed_at": {"$exists": False}}, {"$set": {"consumed_at": None}}
    )
    return MongoStorageMigrationResult(
        removed_username_indexes=tuple(removed),
        deleted_superseded_verifications=deleted,
    )
