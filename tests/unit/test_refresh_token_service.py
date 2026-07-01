"""Unit tests for refresh-token service race behaviour."""

from __future__ import annotations

import asyncio

from fastauth.exceptions import RefreshTokenReuseError
from fastauth.options import RefreshTokenOptions
from fastauth.security.refresh_tokens import RefreshTokenService
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


async def test_concurrent_refresh_rotation_has_single_winner_and_revokes_family() -> None:
    adapter = RaceyRefreshTokenAdapter()
    service = RefreshTokenService(
        adapter=adapter,
        config=RefreshTokenOptions(enabled=True),
    )
    issued = await service.issue(user_id="user-1")
    assert issued is not None
    refresh_token = issued[1]

    results = await asyncio.gather(
        service.rotate(refresh_token),
        service.rotate(refresh_token),
        return_exceptions=True,
    )

    successes = [result for result in results if not isinstance(result, Exception)]
    reuse_errors = [result for result in results if isinstance(result, RefreshTokenReuseError)]
    assert len(successes) == 1
    assert len(reuse_errors) == 1
    assert adapter.refresh_tokens == {}
