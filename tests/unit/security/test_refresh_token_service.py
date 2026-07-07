"""Unit tests for refresh-token service race behaviour."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

from fastauth.domain.models import Session
from fastauth.exceptions import RefreshTokenReuseError
from fastauth.options import RefreshTokenOptions
from fastauth.security.refresh_tokens import RefreshTokenService
from fastauth.storage.base import RevokedRefreshFamily
from fastauth.storage.memory import InMemoryAdapter


class RaceyRefreshTokenAdapter(InMemoryAdapter):
    """Adapter that lets two reads observe the same pre-consumed token snapshot."""

    def __init__(self) -> None:
        super().__init__()
        self.read_count = 0
        self.both_read = asyncio.Event()

    async def get_refresh_token_by_hash(self, token_hash: str):
        token = await super().get_refresh_token_by_hash(token_hash)
        if token is None:
            return None
        self.read_count += 1
        if self.read_count == 2:
            self.both_read.set()
        await self.both_read.wait()
        return token.model_copy(deep=True)


class AtomicFamilyRevocationAdapter(InMemoryAdapter):
    async def delete_refresh_token_family(self, family_id: str) -> RevokedRefreshFamily:
        revoked = await super().delete_refresh_token_family(family_id)
        for session_id in revoked.session_ids:
            self.sessions.pop(session_id, None)
        return RevokedRefreshFamily(
            deleted_tokens=revoked.deleted_tokens,
            deleted_sessions=len(revoked.session_ids),
            session_ids=revoked.session_ids,
        )

    async def delete_session(self, session_id: str) -> None:
        raise AssertionError(f"delete_session should not be called for {session_id}")


async def test_concurrent_refresh_rotation_has_single_winner_and_revokes_family() -> None:
    adapter = RaceyRefreshTokenAdapter()
    service = RefreshTokenService(
        adapter=adapter,
        config=RefreshTokenOptions(enabled=True),
    )
    issued = await service.issue(user_id="user-1", session_id="session-1")
    assert issued is not None
    refresh_token = issued[1]

    results = await asyncio.gather(
        service.rotate(refresh_token, session_id="session-2"),
        service.rotate(refresh_token, session_id="session-3"),
        return_exceptions=True,
    )

    successes = [result for result in results if not isinstance(result, Exception)]
    reuse_errors = [result for result in results if isinstance(result, RefreshTokenReuseError)]
    assert len(successes) == 1
    assert len(reuse_errors) == 1
    assert adapter.refresh_tokens == {}


async def test_revoke_family_uses_adapter_level_session_revocation() -> None:
    adapter = AtomicFamilyRevocationAdapter()
    service = RefreshTokenService(
        adapter=adapter,
        config=RefreshTokenOptions(enabled=True),
    )
    issued = await service.issue(user_id="user-1", session_id="session-1")
    assert issued is not None
    adapter.sessions["session-1"] = Session(
        user_id="user-1",
        token_hash="hash",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )

    revoked = await service.revoke_family(next(iter(adapter.refresh_tokens.values())).family_id)

    assert revoked.deleted_tokens == 1
    assert revoked.deleted_sessions == 1
    assert adapter.refresh_tokens == {}
    assert adapter.sessions == {}
