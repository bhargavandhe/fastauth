"""``POST /auth/refresh`` flow: exchange a refresh token for a fresh session."""

from __future__ import annotations

from authkit.domain.models import WireModel
from authkit.exceptions import TokenInvalidError
from authkit.flows.credentials import SessionResponse
from authkit.runtime.context import AuthContext
from authkit.security.sessions import SessionContext

__all__ = ["RefreshTokenRequest", "refresh_session"]


class RefreshTokenRequest(WireModel):
    """Body of ``POST /auth/refresh``."""

    refresh_token: str
    include_token: bool = True


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
    new_record, new_plain = await context.refresh_token_service.rotate(
        request.refresh_token,
        ip_address=ip,
        user_agent=user_agent,
    )
    user = await context.adapter.get_user_by_id(new_record.user_id)
    if user is None:
        # The token's user was deleted between issuance and refresh — revoke
        # the chain (already consumed by rotate) and treat as invalid.
        await context.refresh_token_service.revoke_for_user(new_record.user_id)
        raise TokenInvalidError()
    session_context = await context.session_strategy.create(
        user,
        ip=ip,
        user_agent=user_agent,
    )
    return (
        SessionResponse(
            user=user,
            session=session_context.session,
            token=session_context.token if request.include_token else None,
            refresh_token=new_plain,
        ),
        session_context,
    )
