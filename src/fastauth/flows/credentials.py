"""Email/username + password sign-up, sign-in, sign-out, and get-session flows."""

from __future__ import annotations

from pydantic import ConfigDict, EmailStr, Field

from fastauth.domain.enums import HookPhase, ProviderId
from fastauth.domain.events import (
    AccountLockedOut,
    SessionCreated,
    SessionRevoked,
    UserSignedIn,
    UserSignedOut,
    UserSignedUp,
)
from fastauth.domain.models import Account, Session, User, WireModel
from fastauth.exceptions import InvalidCredentialsError
from fastauth.runtime.context import AuthContext
from fastauth.security.sessions import SessionContext

__all__ = [
    "EmptyResponse",
    "SessionResponse",
    "SignInEmailRequest",
    "SignInUsernameRequest",
    "SignUpEmailRequest",
    "complete_sign_in",
    "get_session",
    "sign_in_email",
    "sign_in_username",
    "sign_out",
    "sign_up_email",
]


# Argon2id hash of zero bytes — used for constant-time anti-enumeration on
# sign-in when the user is not found.
PLACEHOLDER_HASH = (
    "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA"
    "$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)


async def maybe_issue_refresh_token(
    context: AuthContext,
    *,
    user_id: str,
    include_token: bool,
    ip: str | None,
    user_agent: str | None,
) -> str | None:
    """Mint a refresh token if both the config and request opted in.

    Returns the plain refresh token string (the caller embeds it in the
    response) or ``None`` if either gate is closed. Refresh tokens piggyback
    on ``include_token`` so cookie-only clients don't unintentionally receive
    a long-lived secret they have nowhere safe to store.
    """
    if not include_token or not context.refresh_token_service.enabled:
        return None
    issued = await context.refresh_token_service.issue(
        user_id=user_id,
        ip_address=ip,
        user_agent=user_agent,
    )
    if issued is None:
        return None
    _record, plain = issued
    return plain


async def record_failure_and_maybe_emit(
    context: AuthContext,
    identifier: str,
    ip: str | None,
    user_agent: str | None,
) -> None:
    """Record a failed sign-in and raise AccountLockedError if it triggered a lock.

    When the attempt crosses the lockout threshold, this function:
    1. Emits the ``AccountLockedOut`` event.
    2. Raises ``AccountLockedError`` so the response carries 423 +
       ``Retry-After`` directly — better UX than returning 401 on the
       triggering attempt and 423 only on the next one.

    Returns ``None`` (caller raises ``InvalidCredentialsError``) when the
    attempt is still below the threshold.
    """
    from fastauth.exceptions import AccountLockedError

    retry_after = await context.lockout_tracker.record_failure(identifier)
    if retry_after is not None:
        await context.event_bus.publish(
            AccountLockedOut(
                identifier=identifier,
                retry_after_seconds=retry_after,
                ip_address=ip,
                user_agent=user_agent,
            ),
        )
        raise AccountLockedError(retry_after_seconds=retry_after)


class SignUpEmailRequest(WireModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr
    password: str = Field(min_length=8)
    name: str | None = None
    username: str | None = Field(default=None, pattern=r"^[a-zA-Z0-9_.-]{3,32}$")
    include_token: bool = False


class SignInEmailRequest(WireModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr
    password: str
    include_token: bool = False


class SignInUsernameRequest(WireModel):
    model_config = ConfigDict(extra="forbid")
    username: str
    password: str
    include_token: bool = False


class SessionResponse(WireModel):
    """Response payload for sign-up and sign-in flows.

    ``token`` is populated only when the caller passes ``include_token=true`` in
    the request body — SPAs and mobile clients that prefer ``Authorization:
    Bearer`` over cookies opt in this way. When the field is omitted from the
    request the response carries ``token=None`` so cookie-only clients don't
    accidentally leak the plain token through logs or client-side storage.

    ``refresh_token`` is populated only when ``RefreshTokenConfig.enabled`` is
    ``True`` AND ``include_token=True`` on the request (refresh tokens only
    make sense for clients that are also receiving an access token they
    intend to refresh). When the flow doesn't issue one, the field is
    ``None``.
    """

    user: User
    session: Session
    token: str | None = None
    refresh_token: str | None = None


class EmptyResponse(WireModel):
    success: bool = True


async def sign_up_email(
    context: AuthContext,
    request: SignUpEmailRequest,
    *,
    ip: str | None,
    user_agent: str | None,
) -> tuple[SessionResponse, SessionContext]:
    user = User(
        email=request.email,
        name=request.name,
        username=request.username,
    )
    user = await context.hooks.run(HookPhase.BEFORE_CREATE, "user", user, actor_user_id=None)
    user = await context.adapter.create_user(user)
    await context.hooks.run(HookPhase.AFTER_CREATE, "user", user, actor_user_id=user.id)

    account = Account(
        user_id=user.id,
        provider_id=ProviderId.CREDENTIAL,
        account_id=user.id,
        password=context.password_hasher.hash(request.password),
    )
    await context.adapter.create_account(account)

    session_context = await context.session_strategy.create(user, ip=ip, user_agent=user_agent)

    await context.event_bus.publish(
        UserSignedUp(
            user_id=user.id,
            identifier=user.email,
            ip_address=ip,
            user_agent=user_agent,
        ),
    )
    await context.event_bus.publish(
        SessionCreated(
            user_id=user.id,
            session_id=session_context.session.id,
            ip_address=ip,
            user_agent=user_agent,
        ),
    )

    refresh_plain = await maybe_issue_refresh_token(
        context,
        user_id=user.id,
        include_token=request.include_token,
        ip=ip,
        user_agent=user_agent,
    )
    return (
        SessionResponse(
            user=user,
            session=session_context.session,
            token=session_context.token if request.include_token else None,
            refresh_token=refresh_plain,
        ),
        session_context,
    )


async def sign_in_email(
    context: AuthContext,
    request: SignInEmailRequest,
    *,
    ip: str | None,
    user_agent: str | None,
) -> tuple[SessionResponse, SessionContext]:
    user = await context.adapter.get_user_by_email(request.email)
    return await complete_sign_in(
        context,
        user,
        request.password,
        identifier=request.email,
        ip=ip,
        user_agent=user_agent,
        include_token=request.include_token,
    )


async def sign_in_username(
    context: AuthContext,
    request: SignInUsernameRequest,
    *,
    ip: str | None,
    user_agent: str | None,
) -> tuple[SessionResponse, SessionContext]:
    user = await context.adapter.get_user_by_username(request.username)
    return await complete_sign_in(
        context,
        user,
        request.password,
        identifier=request.username,
        ip=ip,
        user_agent=user_agent,
        include_token=request.include_token,
    )


async def complete_sign_in(
    context: AuthContext,
    user: User | None,
    password: str,
    *,
    identifier: str,
    ip: str | None,
    user_agent: str | None,
    include_token: bool = False,
) -> tuple[SessionResponse, SessionContext]:
    # Lockout check: if too many recent failures for this identifier, reject
    # before examining any password material.
    await context.lockout_tracker.check_locked(identifier)

    if user is None:
        # Constant-time path: hash anyway so timing is uniform.
        context.password_hasher.verify(password, PLACEHOLDER_HASH)
        await record_failure_and_maybe_emit(context, identifier, ip, user_agent)
        raise InvalidCredentialsError()

    account = await context.adapter.get_account_for_user(user.id, ProviderId.CREDENTIAL)
    stored = account.password if account is not None else None
    if stored is None or not context.password_hasher.verify(password, stored):
        await record_failure_and_maybe_emit(context, identifier, ip, user_agent)
        raise InvalidCredentialsError()

    # Successful sign-in: clear the failure counter so future attempts have
    # a clean slate.
    await context.lockout_tracker.reset(identifier)

    session_context = await context.session_strategy.create(user, ip=ip, user_agent=user_agent)

    await context.event_bus.publish(
        UserSignedIn(
            user_id=user.id,
            identifier=user.email,
            ip_address=ip,
            user_agent=user_agent,
        ),
    )
    await context.event_bus.publish(
        SessionCreated(
            user_id=user.id,
            session_id=session_context.session.id,
            ip_address=ip,
            user_agent=user_agent,
        ),
    )

    return (
        SessionResponse(
            user=user,
            session=session_context.session,
            token=session_context.token if include_token else None,
            refresh_token=await maybe_issue_refresh_token(
                context,
                user_id=user.id,
                include_token=include_token,
                ip=ip,
                user_agent=user_agent,
            ),
        ),
        session_context,
    )


async def sign_out(context: AuthContext, token: str | None) -> EmptyResponse:
    if token is None:
        return EmptyResponse(success=False)
    found = await context.session_strategy.read(token)
    await context.session_strategy.revoke(token)
    if found is not None:
        await context.event_bus.publish(UserSignedOut(user_id=found.user.id))
        await context.event_bus.publish(
            SessionRevoked(user_id=found.user.id, session_id=found.session.id),
        )
    return EmptyResponse(success=True)


async def get_session(context: AuthContext, token: str | None) -> SessionResponse | None:
    if token is None:
        return None
    current = await context.session_strategy.read(token)
    if current is None:
        return None
    return SessionResponse(user=current.user, session=current.session)
