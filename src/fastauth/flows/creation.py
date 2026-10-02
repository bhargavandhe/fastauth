"""Cancellation-safe user/account creation with explicit compensating cleanup."""

from __future__ import annotations

import asyncio

from fastauth.domain.enums import ProviderId
from fastauth.domain.models import Account, User
from fastauth.exceptions import DuplicateError
from fastauth.storage.base import DatabaseAdapter


async def persist_user_account(
    adapter: DatabaseAdapter,
    user: User,
    *,
    provider_id: ProviderId,
    password_hash: str | None,
) -> User:
    """Commit a usable identity or compensate the user insert on account failure.

    Cancellation waits for the short write/compensation section to finish. Once
    this returns, session or notification failures must not remove the identity:
    the user can recover by signing in normally. Process/database outages still
    require operator reconciliation if compensating deletion itself fails.
    """

    async def commit() -> User:
        try:
            created = await adapter.create_user(user)
        except DuplicateError:
            # A conflicting pre-existing identity belongs to another operation.
            raise
        except BaseException:
            # Adapters must assign the owned identity before their insert await,
            # so even a lost insert acknowledgement can be compensated safely.
            await adapter.delete_user(user.id)
            raise
        try:
            await adapter.create_account(
                Account(
                    user_id=created.id,
                    provider_id=provider_id,
                    account_id=created.id,
                    password=password_hash,
                )
            )
        except BaseException:
            await adapter.delete_user(created.id)
            raise
        return created

    task = asyncio.create_task(commit())
    cancelled = False
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            cancelled = True
    result = task.result()
    if cancelled:
        raise asyncio.CancelledError
    return result
