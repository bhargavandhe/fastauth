"""Session-management flow: list / revoke-one / revoke-all-except-current.

These flows operate against the database-backed session store. In JWT
session mode, the database isn't populated with per-session rows (the JWT
itself is the session), so :func:`list_sessions` returns an empty list and
the revoke flows are no-ops. Refresh tokens (introduced in Phase D) own
the analogous revocation surface for JWT mode.

The list-response model deliberately omits ``token_hash`` — exposing it to
the client would defeat the point of hashing tokens at rest.
"""

from __future__ import annotations

from datetime import datetime

from fastauth.domain.models import User, WireModel
from fastauth.exceptions import NotFoundError
from fastauth.runtime.context import AuthContext

__all__ = [
    "ListSessionsResponse",
    "RevokeSessionsResponse",
    "SessionSummary",
    "list_sessions_for_user",
    "revoke_other_sessions",
    "revoke_session",
]


class SessionSummary(WireModel):
    """Public-safe view of a :class:`Session` (no ``token_hash``)."""

    id: str
    user_id: str
    expires_at: datetime
    ip_address: str | None
    user_agent: str | None
    created_at: datetime
    updated_at: datetime
    is_current: bool


class ListSessionsResponse(WireModel):
    sessions: list[SessionSummary]


class RevokeSessionsResponse(WireModel):
    revoked: int


async def list_sessions_for_user(
    context: AuthContext,
    *,
    user: User,
    current_session_id: str | None,
) -> ListSessionsResponse:
    """Return every session belonging to ``user``.

    ``current_session_id`` is the session id that the caller's request
    is authenticated with (so it can be marked ``is_current=True``). Pass
    ``None`` if no session is associated with the request (e.g. when an
    admin lists another user's sessions; not currently exposed via HTTP).
    """
    sessions = await context.adapter.list_sessions_for_user(user.id)
    return ListSessionsResponse(
        sessions=[
            SessionSummary(
                id=s.id,
                user_id=s.user_id,
                expires_at=s.expires_at,
                ip_address=s.ip_address,
                user_agent=s.user_agent,
                created_at=s.created_at,
                updated_at=s.updated_at,
                is_current=(s.id == current_session_id),
            )
            for s in sessions
        ],
    )


async def revoke_session(
    context: AuthContext,
    *,
    user: User,
    session_id: str,
) -> RevokeSessionsResponse:
    """Revoke a specific session by id. Must belong to the caller.

    Raises :class:`NotFoundError` if the session doesn't exist, belongs to a
    different user, or has already been revoked. The lookup happens by
    listing the user's sessions and filtering — adapter-agnostic and
    inexpensive (a user typically has <10 sessions). Adapters that want a
    faster path can override the relevant adapter methods.
    """
    sessions = await context.adapter.list_sessions_for_user(user.id)
    target = next((s for s in sessions if s.id == session_id), None)
    if target is None:
        raise NotFoundError(resource="session")
    await context.adapter.delete_session(target.id)
    return RevokeSessionsResponse(revoked=1)


async def revoke_other_sessions(
    context: AuthContext,
    *,
    user: User,
    current_session_id: str | None,
) -> RevokeSessionsResponse:
    """Revoke every session for ``user`` except ``current_session_id``."""
    revoked = await context.session_strategy.revoke_all(
        user.id,
        except_session_id=current_session_id,
    )
    return RevokeSessionsResponse(revoked=revoked)
