"""``POST /auth/refresh`` flow: exchange a refresh token for a fresh session."""

from __future__ import annotations

from pydantic import Field, SecretStr

from fastauth.api.commands import (
    BearerCredentialDelivery,
    CredentialDelivery,
)
from fastauth.api.responses import authentication_response
from fastauth.domain.models import WireModel
from fastauth.exceptions import InvalidRequestError, TokenInvalidError
from fastauth.flows.credentials import SessionResponse
from fastauth.runtime.context import AuthContext
from fastauth.security.sessions import SessionContext

__all__ = ["RefreshTokenRequest", "refresh_session"]


class RefreshTokenRequest(WireModel):
    """Body of ``POST /auth/refresh``."""

    refresh_token: SecretStr
    delivery: CredentialDelivery = Field(default_factory=BearerCredentialDelivery)


async def refresh_session(
    context: AuthContext,
    request: RefreshTokenRequest,
    *,
    ip: str | None,
    user_agent: str | None,
) -> tuple[SessionResponse, SessionContext]:
    """Rotate the refresh token + mint a fresh session for the same user.

    Three outcomes other than success:

    * Token is unknown or mis-formatted → :class:`TokenInvalidError` (400).
    * Token is expired → :class:`TokenExpiredError` (400).
    * Token was already consumed (reuse / theft) → the rotation chain is
      revoked, then :class:`RefreshTokenReuseError` (401) is raised.
    """
    if not context.refresh_token_service.enabled:
        raise TokenInvalidError()
    if not isinstance(request.delivery, BearerCredentialDelivery):
        raise InvalidRequestError(
            message="refresh token rotation requires bearer credential delivery",
        )
    existing = await context.refresh_token_service.get_valid(
        request.refresh_token.get_secret_value(),
    )
    user = await context.adapter.get_user_by_id(existing.user_id)
    if user is None:
        await context.refresh_token_service.revoke_family(existing.family_id)
        raise TokenInvalidError()
    session_context = await context.session_strategy.create(
        user,
        ip=ip,
        user_agent=user_agent,
    )
    try:
        new_record, new_plain = await context.refresh_token_service.rotate(
            request.refresh_token.get_secret_value(),
            session_id=session_context.session.id,
            ip_address=ip,
            user_agent=user_agent,
        )
    except Exception:
        await context.adapter.delete_session(session_context.session.id)
        raise
    if new_record.user_id != user.id:
        await context.adapter.delete_session(session_context.session.id)
        raise TokenInvalidError()
    if existing.session_id != session_context.session.id:
        await context.adapter.delete_session(existing.session_id)
    return (
        authentication_response(
            user=user,
            session=session_context.session,
            token=session_context.token,
            refresh_token=new_plain,
        ),
        session_context,
    )
