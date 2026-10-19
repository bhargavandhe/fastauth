"""Refresh conformance permits adapters to remove old access sessions on rotation."""

from datetime import datetime

import pytest

from fastauth.domain.models import RefreshToken
from fastauth.storage.memory import InMemoryAdapter
from fastauth.testing.adapter_contract import RefreshTokenAdapterContract


class EagerSessionCleanupAdapter(InMemoryAdapter):
    """Model the Mongo adapter's documented eager removal of replaced sessions."""

    async def rotate_refresh_token(
        self,
        *,
        current_token_id: str,
        new_token: RefreshToken,
        consumed_at: datetime,
    ) -> RefreshToken | None:
        current = self.refresh_tokens.get(current_token_id)
        rotated = await super().rotate_refresh_token(
            current_token_id=current_token_id,
            new_token=new_token,
            consumed_at=consumed_at,
        )
        if current is not None and rotated is not None and current.session_id != rotated.session_id:
            await self.delete_session(current.session_id)
        return rotated


@pytest.mark.parametrize(
    "entrypoint", ["session", "user", "user_except", "family", "legacy_family"]
)
async def test_family_revocation_contract_allows_eager_session_cleanup(entrypoint: str) -> None:
    await RefreshTokenAdapterContract().test_family_revocation_removes_access_sessions(
        EagerSessionCleanupAdapter(), entrypoint
    )
