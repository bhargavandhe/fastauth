"""SessionStrategy protocol and DatabaseSessionStrategy."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict

from authkit.config import SessionConfig
from authkit.domain.models import Session, User
from authkit.security.tokens import TokenService
from authkit.storage.base import DatabaseAdapter

__all__ = ["DatabaseSessionStrategy", "SessionContext", "SessionStrategy"]


class SessionContext(BaseModel):
    """Returned by `SessionStrategy.create` and `read` operations."""

    model_config = ConfigDict(arbitrary_types_allowed=True)
    user: User
    session: Session
    token: str


@runtime_checkable
class SessionStrategy(Protocol):
    async def create(
        self,
        user: User,
        *,
        ip: str | None,
        user_agent: str | None,
    ) -> SessionContext: ...
    async def read(self, token: str) -> SessionContext | None: ...
    async def revoke(self, token: str) -> None: ...
    async def revoke_all(
        self,
        user_id: str,
        *,
        except_session_id: str | None = None,
    ) -> int: ...
    async def rotate(self, token: str) -> SessionContext | None: ...


class DatabaseSessionStrategy:
    def __init__(
        self,
        adapter: DatabaseAdapter,
        token_service: TokenService,
        config: SessionConfig,
    ) -> None:
        self.adapter = adapter
        self.tokens = token_service
        self.config = config

    async def create(
        self,
        user: User,
        *,
        ip: str | None,
        user_agent: str | None,
    ) -> SessionContext:
        pair = self.tokens.generate_pair()
        session = Session(
            user_id=user.id,
            token_hash=pair.hashed,
            expires_at=datetime.now(UTC) + timedelta(seconds=self.config.max_age_seconds),
            ip_address=ip,
            user_agent=user_agent,
        )
        await self.adapter.create_session(session)
        return SessionContext(user=user, session=session, token=pair.plain)

    async def read(self, token: str) -> SessionContext | None:
        token_hash = self.tokens.hash_only(token)
        session = await self.adapter.get_session_by_token_hash(token_hash)
        if session is None or session.expires_at <= datetime.now(UTC):
            return None
        user = await self.adapter.get_user_by_id(session.user_id)
        if user is None:
            return None
        return SessionContext(user=user, session=session, token=token)

    async def revoke(self, token: str) -> None:
        token_hash = self.tokens.hash_only(token)
        session = await self.adapter.get_session_by_token_hash(token_hash)
        if session is not None:
            await self.adapter.delete_session(session.id)

    async def revoke_all(self, user_id: str, *, except_session_id: str | None = None) -> int:
        return await self.adapter.delete_sessions_for_user(
            user_id,
            except_session_id=except_session_id,
        )

    async def rotate(self, token: str) -> SessionContext | None:
        current = await self.read(token)
        if current is None:
            return None
        await self.adapter.delete_session(current.session.id)
        return await self.create(
            current.user,
            ip=current.session.ip_address,
            user_agent=current.session.user_agent,
        )
