"""Refresh-token issuance and rotation with theft-detection.

A refresh token is a long-lived opaque secret. Presenting it at
``POST /auth/refresh`` returns a fresh access session (a new session-strategy
token + a new refresh token) and marks the presented refresh token consumed.
If a previously-consumed token is presented again, that's theft — the
service revokes every token sharing the same ``family_id`` (the rotation
chain rooted at the initial sign-in) and the user must re-authenticate.

Refresh tokens are stored hashed (SHA-256). The plain token is returned to
the client exactly once, on issuance. There is no way to recover the plain
token from the database.

Storage shape: see :class:`authkit.domain.models.RefreshToken`. The
``consumed_at``-but-not-deleted invariant is what enables reuse detection;
a cleanup pass (or the Beanie TTL on ``expires_at``) removes
consumed-and-expired rows after the absolute window passes.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from authkit.config import RefreshTokenConfig
from authkit.domain.models import RefreshToken, new_id
from authkit.exceptions import RefreshTokenReuseError, TokenExpiredError, TokenInvalidError
from authkit.security.tokens import TokenPair, TokenService
from authkit.storage.base import DatabaseAdapter

__all__ = ["RefreshTokenService"]


class RefreshTokenService:
    """Issue, rotate, and verify refresh tokens.

    Initialised with the adapter + a :class:`RefreshTokenConfig`. When
    ``config.enabled`` is ``False``, every method is a no-op (issue returns
    ``None``, rotate raises ``TokenInvalidError``) so callers can guard on
    presence instead of carrying a stack of feature flags.
    """

    def __init__(
        self,
        *,
        adapter: DatabaseAdapter,
        config: RefreshTokenConfig,
        token_service: TokenService | None = None,
    ) -> None:
        self.adapter = adapter
        self.config = config
        self.token_service = token_service or TokenService(byte_length=48)

    @property
    def enabled(self) -> bool:
        return self.config.enabled

    async def issue(
        self,
        *,
        user_id: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> tuple[RefreshToken, str] | None:
        """Mint a brand-new refresh token (new family). Returns ``None`` if
        the service is disabled. The second element of the tuple is the plain
        token; the caller is responsible for returning it to the client.
        """
        if not self.enabled:
            return None
        pair = self.token_service.generate_pair()
        return await self.persist(
            pair, user_id=user_id, family_id=None, ip_address=ip_address, user_agent=user_agent
        )

    async def persist(
        self,
        pair: TokenPair,
        *,
        user_id: str,
        family_id: str | None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        expires_at: datetime | None = None,
    ) -> tuple[RefreshToken, str]:
        """Insert a new ``RefreshToken`` row. ``family_id=None`` starts a new chain."""
        token_id = new_id()
        chain_root = family_id or token_id
        exp = expires_at or datetime.now(UTC) + timedelta(seconds=self.config.max_age_seconds)
        record = RefreshToken(
            id=token_id,
            user_id=user_id,
            token_hash=pair.hashed,
            family_id=chain_root,
            expires_at=exp,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        await self.adapter.create_refresh_token(record)
        return record, pair.plain

    async def rotate(
        self,
        plain_token: str,
        *,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> tuple[RefreshToken, str]:
        """Exchange ``plain_token`` for a fresh refresh token in the same family.

        Raises :class:`TokenInvalidError` if the token doesn't exist;
        :class:`TokenExpiredError` if it's past ``expires_at``;
        :class:`RefreshTokenReuseError` if it was already consumed — in
        which case the entire family is revoked before raising.
        """
        if not self.enabled:
            raise TokenInvalidError()
        hashed = self.token_service.hash_only(plain_token)
        existing = await self.adapter.get_refresh_token_by_hash(hashed)
        if existing is None:
            raise TokenInvalidError()
        # Reuse-detection: a token that's already been rotated. Revoke its
        # whole family — every key in the chain is now considered burned.
        if existing.consumed_at is not None:
            await self.adapter.delete_refresh_tokens_in_family(existing.family_id)
            raise RefreshTokenReuseError()
        if existing.expires_at <= datetime.now(UTC):
            raise TokenExpiredError()
        # Enforce the absolute-max horizon if configured. The chain root's
        # `created_at` minus now must be < absolute_max_age_seconds.
        if self.config.absolute_max_age_seconds is not None:
            age_seconds = (datetime.now(UTC) - existing.created_at).total_seconds()
            if age_seconds > self.config.absolute_max_age_seconds:
                # Chain is too old. Revoke the family; user must sign in fresh.
                await self.adapter.delete_refresh_tokens_in_family(existing.family_id)
                raise TokenExpiredError()
        # Atomically mark the old token consumed and mint the new one. Only one
        # caller can win this compare-and-set; a loser means the token was
        # reused and the whole family must be burned.
        new_pair = self.token_service.generate_pair()
        token_id = new_id()
        new_record = RefreshToken(
            id=token_id,
            user_id=existing.user_id,
            token_hash=new_pair.hashed,
            family_id=existing.family_id,
            expires_at=datetime.now(UTC) + timedelta(seconds=self.config.max_age_seconds),
            ip_address=ip_address,
            user_agent=user_agent,
        )
        rotated = await self.adapter.rotate_refresh_token(
            current_token_id=existing.id,
            new_token=new_record,
            consumed_at=datetime.now(UTC),
        )
        if rotated is None:
            await self.adapter.delete_refresh_tokens_in_family(existing.family_id)
            raise RefreshTokenReuseError()
        return rotated, new_pair.plain

    async def revoke_for_user(self, user_id: str) -> int:
        return await self.adapter.delete_refresh_tokens_for_user(user_id)
