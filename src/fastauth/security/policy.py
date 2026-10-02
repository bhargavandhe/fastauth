"""Typed account policy and token-authenticated actor boundaries.

Application callbacks run after first-party account checks and may deny access;
they cannot override suspension, verification or freshness requirements.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta

from pydantic import BaseModel, ConfigDict

from fastauth.api.responses import SessionView, UserView, session_view, user_view
from fastauth.domain.enums import HookPhase
from fastauth.domain.events import UserUpdated
from fastauth.domain.models import ApiKey, Session, User
from fastauth.domain.value_objects import UserId
from fastauth.exceptions import (
    AdapterFeatureUnsupportedError,
    EmailNotVerifiedError,
    InvalidCredentialsError,
    NotFoundError,
    PolicyDeniedError,
)
from fastauth.options import SessionOptions
from fastauth.runtime.event_bus import EventBus
from fastauth.runtime.hooks import DatabaseHooks
from fastauth.security.sessions import RefreshSessionStrategy, SessionContext, SessionStrategy
from fastauth.storage.base import DatabaseAdapter, UserStatusStore

__all__ = [
    "AuthenticatedActor",
    "PolicyDecision",
    "PolicyHook",
    "PolicyRequest",
    "PolicyService",
    "PolicySessionStrategy",
]


class AuthenticatedActor(BaseModel):
    """Safe snapshot obtained by validating an actual session token.

    Python callers are trusted and can construct models themselves. This is
    not a signed capability: use ``authenticate`` at each untrusted boundary.
    """

    model_config = ConfigDict(frozen=True)
    user: UserView
    session: SessionView


class PolicyRequest(BaseModel):
    model_config = ConfigDict(frozen=True)
    action: str
    user: User
    session: Session | None = None
    api_key: ApiKey | None = None


class PolicyDecision(BaseModel):
    model_config = ConfigDict(frozen=True)
    allowed: bool = True
    reason: str = "operation denied by application policy"


PolicyHook = Callable[[PolicyRequest], Awaitable[PolicyDecision]]


class PolicyService:
    def __init__(
        self,
        adapter: DatabaseAdapter,
        sessions: SessionStrategy,
        config: SessionOptions,
        events: EventBus,
        hook: PolicyHook | None = None,
        *,
        hooks: DatabaseHooks | None = None,
    ) -> None:
        self.adapter = adapter
        self.sessions = sessions
        self.config = config
        self.events = events
        self.hook = hook
        self.hooks = hooks or DatabaseHooks()

    async def authorize(
        self,
        user: User,
        *,
        action: str,
        session: Session | None = None,
        api_key: ApiKey | None = None,
        require_verified: bool = False,
        max_age: timedelta | None = None,
    ) -> None:
        """Apply account invariants, optional freshness and application policy."""
        if not user.active:
            raise PolicyDeniedError(message="account is suspended")
        if require_verified and not user.email_verified:
            raise EmailNotVerifiedError()
        if max_age is not None:
            now = datetime.now(UTC)
            if max_age <= timedelta(0):
                raise ValueError("max_age must be positive")
            if (
                session is None
                or session.authenticated_at is None
                or session.authenticated_at > now
                or now - session.authenticated_at > max_age
            ):
                raise PolicyDeniedError(message="recent authentication is required")
        if self.hook is not None:
            decision = await self.hook(
                PolicyRequest(action=action, user=user, session=session, api_key=api_key)
            )
            if not decision.allowed:
                raise PolicyDeniedError(message=decision.reason)

    async def authenticate(
        self, token: str, *, require_verified: bool = False, max_age: timedelta | None = None
    ) -> AuthenticatedActor:
        """Resolve an actual token and enforce configured/requested policies."""
        context = await self.sessions.read(token)
        if context is None:
            raise InvalidCredentialsError()
        await self.authorize(
            context.user,
            action="session.read",
            session=context.session,
            require_verified=require_verified or self.config.require_verified_user,
            max_age=max_age,
        )
        return AuthenticatedActor(
            user=user_view(context.user), session=session_view(context.session)
        )

    async def set_active(self, user_id: UserId, *, active: bool, reason: str) -> UserView:
        """Trusted administrator operation; never mounted on the public router.

        Status is persisted before revocation so racing requests also fail the
        user-state check. Audit publication is best effort like other events.
        """
        if not reason.strip():
            raise ValueError("a reason is required for a trusted status change")
        user = await self.adapter.get_user_by_id(user_id.root)
        if user is None:
            raise NotFoundError(resource="user")
        if not isinstance(self.adapter, UserStatusStore):
            raise AdapterFeatureUnsupportedError(feature="atomic privileged user status updates")
        proposed = user.model_copy(deep=True)
        proposed.active = active
        transformed = await self.hooks.run(
            HookPhase.BEFORE_UPDATE,
            "user",
            proposed,
            actor_user_id=None,
        )
        if not isinstance(transformed, User):
            raise TypeError("before-update user hook must return User or None")
        # Activation first clears any old credentials left by interrupted
        # suspension cleanup. The privileged write never replaces profile data.
        if transformed.active and not user.active:
            await self.adapter.delete_refresh_tokens_for_user(user.id)
            await self.adapter.delete_sessions_for_user(user.id)
        user = await self.adapter.set_user_active(user.id, active=transformed.active)
        await self.events.publish(
            UserUpdated(
                user_id=user.id,
                changed_fields=["active"],
                extra={"trusted_admin": True, "active": user.active, "reason": reason},
            )
        )
        if not user.active:
            await self.adapter.delete_refresh_tokens_for_user(user.id)
            await self.adapter.delete_sessions_for_user(user.id)
        await self.hooks.run(HookPhase.AFTER_UPDATE, "user", user, actor_user_id=None)
        return user_view(user)


class PolicySessionStrategy:
    """Enforce account policy across every session transport and provider."""

    def __init__(self, strategy: SessionStrategy, policy: PolicyService) -> None:
        self.strategy = strategy
        self.policy = policy

    async def create(self, user: User, *, ip: str | None, user_agent: str | None) -> SessionContext:
        # Signup may issue a restricted bootstrap session. Reads and renewal
        # remain blocked by require_verified_user until verification succeeds.
        await self.policy.authorize(user, action="session.issue")
        created = await self.strategy.create(user, ip=ip, user_agent=user_agent)
        return await self.check_issued_user(created)

    async def check_issued_user(self, created: SessionContext) -> SessionContext:
        """Close the issue-versus-suspension race before returning credentials."""
        current = await self.policy.adapter.get_user_by_id(created.user.id)
        if current is None or not current.active:
            await self.strategy.revoke(created.token)
            await self.policy.adapter.delete_refresh_tokens_for_session(created.session.id)
            raise PolicyDeniedError(message="account is suspended or no longer exists")
        return created.model_copy(update={"user": current})

    async def renew(
        self,
        user: User,
        *,
        session_id: str,
        authenticated_at: datetime | None,
        ip: str | None,
        user_agent: str | None,
    ) -> SessionContext:
        await self.policy.authorize(
            user,
            action="session.refresh",
            require_verified=self.policy.config.require_verified_user,
        )
        if not isinstance(self.strategy, RefreshSessionStrategy):
            raise PolicyDeniedError(
                message="session strategy does not support secure refresh renewal"
            )
        renewed = await self.strategy.renew(
            user,
            session_id=session_id,
            authenticated_at=authenticated_at,
            ip=ip,
            user_agent=user_agent,
        )
        return await self.check_issued_user(renewed)

    async def read(self, token: str) -> SessionContext | None:
        context = await self.strategy.read(token)
        if context is None:
            return None
        try:
            await self.policy.authorize(
                context.user,
                action="session.read",
                session=context.session,
                require_verified=self.policy.config.require_verified_user,
            )
        except (PolicyDeniedError, EmailNotVerifiedError):
            return None
        return context

    async def revoke(self, token: str) -> None:
        # Logout must revoke refresh credentials even when access policy now
        # rejects the otherwise valid session (for example a bootstrap token).
        current = await self.strategy.read(token)
        await self.strategy.revoke(token)
        if current is not None:
            await self.policy.adapter.delete_refresh_tokens_for_session(current.session.id)

    async def revoke_all(self, user_id: str, *, except_session_id: str | None = None) -> int:
        return await self.strategy.revoke_all(user_id, except_session_id=except_session_id)

    async def rotate(self, token: str) -> SessionContext | None:
        if await self.read(token) is None:
            return None
        return await self.strategy.rotate(token)
