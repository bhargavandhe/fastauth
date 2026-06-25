"""Authenticated change-password flow.

Unlike ``flows.password_reset``, this flow runs when the caller is already
signed in: they prove possession of the *current* password and provide a
*new* one. The current session stays alive; other sessions are revoked by
default (callers can opt out via ``revoke_other_sessions=false`` — e.g. when
the change is performed from a "settings" page where the user explicitly
trusts every device they're signed in from).
"""

from __future__ import annotations

from pydantic import ConfigDict, Field

from authkit.domain.enums import ProviderId
from authkit.domain.events import PasswordChanged, SessionsRevokedAll
from authkit.domain.models import User, WireModel
from authkit.exceptions import InvalidCredentialsError, NotFoundError
from authkit.flows.credentials import EmptyResponse
from authkit.runtime.context import AuthContext

__all__ = ["ChangePasswordRequest", "change_password"]


class ChangePasswordRequest(WireModel):
    """Request body for ``POST /auth/change-password``.

    ``current_password`` must verify against the user's credential-provider
    account. ``new_password`` is bound by the same ``min_length=8`` rule as
    sign-up. ``revoke_other_sessions`` defaults to ``True`` — the typical
    safe behaviour for password changes is to invalidate every other device
    the user is signed in from. The current session always stays alive (the
    user just proved possession of the current password from this session).
    """

    model_config = ConfigDict(extra="forbid")
    current_password: str
    new_password: str = Field(min_length=8)
    revoke_other_sessions: bool = True


async def change_password(
    context: AuthContext,
    user: User,
    *,
    current_session_id: str,
    request: ChangePasswordRequest,
    ip: str | None,
    user_agent: str | None,
) -> EmptyResponse:
    account = await context.adapter.get_account_for_user(user.id, ProviderId.CREDENTIAL)
    if account is None or account.password is None:
        raise NotFoundError(resource="credential_account")
    if not context.password_hasher.verify(request.current_password, account.password):
        raise InvalidCredentialsError()

    account.password = context.password_hasher.hash(request.new_password)
    await context.adapter.update_account(account)

    revoked = 0
    if request.revoke_other_sessions:
        sessions = await context.adapter.list_sessions_for_user(user.id)
        for session in sessions:
            if session.id != current_session_id:
                await context.adapter.delete_session(session.id)
                revoked += 1

    await context.event_bus.publish(
        PasswordChanged(user_id=user.id, ip_address=ip, user_agent=user_agent),
    )
    if revoked:
        await context.event_bus.publish(
            SessionsRevokedAll(user_id=user.id, ip_address=ip, user_agent=user_agent),
        )
    return EmptyResponse(success=True)
