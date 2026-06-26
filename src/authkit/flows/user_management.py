"""Authenticated user profile, password setup, verification, and account deletion."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote

from pydantic import ConfigDict, Field, model_validator

from authkit.domain.enums import EmailMessageKind, ProviderId, VerificationPurpose
from authkit.domain.events import (
    OtpGenerated,
    PasswordChanged,
    SessionsRevokedAll,
    UserDeleted,
    UserDeleteRequested,
    UserUpdated,
)
from authkit.domain.models import Account, EmailMessage, User, Verification, WireModel
from authkit.exceptions import (
    InvalidCredentialsError,
    NotFoundError,
    PasswordAlreadySetError,
    TokenExpiredError,
    TokenInvalidError,
)
from authkit.flows.credentials import EmptyResponse, record_failure_and_maybe_emit
from authkit.runtime.context import AuthContext

__all__ = [
    "DeleteAccountConfirmRequest",
    "DeleteAccountRequest",
    "SetPasswordRequest",
    "UpdateUserRequest",
    "VerifyPasswordRequest",
    "VerifyPasswordResponse",
    "confirm_delete_account",
    "delete_account_with_password",
    "request_delete_account",
    "set_password",
    "update_user",
    "verify_password",
]


class UpdateUserRequest(WireModel):
    """Authenticated profile update for caller-owned mutable user fields."""

    model_config = ConfigDict(extra="forbid")
    name: str | None = None
    image: str | None = None
    metadata: dict[str, Any] | None = None

    @model_validator(mode="after")
    def reject_metadata_null(self) -> UpdateUserRequest:
        if "metadata" in self.model_fields_set and self.metadata is None:
            raise ValueError("metadata must be an object")
        return self


class SetPasswordRequest(WireModel):
    model_config = ConfigDict(extra="forbid")
    new_password: str = Field(min_length=8)
    revoke_other_sessions: bool = True


class VerifyPasswordRequest(WireModel):
    model_config = ConfigDict(extra="forbid")
    password: str


class VerifyPasswordResponse(WireModel):
    valid: bool


class DeleteAccountRequest(WireModel):
    model_config = ConfigDict(extra="forbid")
    password: str


class DeleteAccountConfirmRequest(WireModel):
    model_config = ConfigDict(extra="forbid")
    token: str


async def update_user(
    context: AuthContext,
    user: User,
    request: UpdateUserRequest,
    *,
    ip: str | None,
    user_agent: str | None,
) -> User:
    changed_fields: list[str] = []
    if "name" in request.model_fields_set:
        user.name = request.name
        changed_fields.append("name")
    if "image" in request.model_fields_set:
        user.image = request.image
        changed_fields.append("image")
    if "metadata" in request.model_fields_set:
        user.metadata = request.metadata or {}
        changed_fields.append("metadata")

    if not changed_fields:
        return user

    updated = await context.adapter.update_user(user)
    await context.event_bus.publish(
        UserUpdated(
            user_id=user.id,
            changed_fields=changed_fields,
            ip_address=ip,
            user_agent=user_agent,
        ),
    )
    return updated


async def set_password(
    context: AuthContext,
    user: User,
    *,
    current_session_id: str,
    request: SetPasswordRequest,
    ip: str | None,
    user_agent: str | None,
) -> EmptyResponse:
    account = await context.adapter.get_account_for_user(user.id, ProviderId.CREDENTIAL)
    if account is not None and account.password is not None:
        raise PasswordAlreadySetError()
    if account is None:
        account = await context.adapter.create_account(
            Account(
                user_id=user.id,
                provider_id=ProviderId.CREDENTIAL,
                account_id=user.id,
            ),
        )

    account.password = context.password_hasher.hash(request.new_password)
    await context.adapter.update_account(account)

    revoked = 0
    if request.revoke_other_sessions:
        revoked = await context.adapter.delete_sessions_for_user(
            user.id,
            except_session_id=current_session_id,
        )

    await context.event_bus.publish(
        PasswordChanged(user_id=user.id, ip_address=ip, user_agent=user_agent),
    )
    if revoked:
        await context.event_bus.publish(
            SessionsRevokedAll(user_id=user.id, ip_address=ip, user_agent=user_agent),
        )
    return EmptyResponse(success=True)


async def verify_password(
    context: AuthContext,
    user: User,
    request: VerifyPasswordRequest,
    *,
    ip: str | None,
    user_agent: str | None,
) -> VerifyPasswordResponse:
    await verify_current_password(
        context,
        user,
        request.password,
        ip=ip,
        user_agent=user_agent,
    )
    return VerifyPasswordResponse(valid=True)


async def delete_account_with_password(
    context: AuthContext,
    user: User,
    request: DeleteAccountRequest,
    *,
    ip: str | None,
    user_agent: str | None,
) -> EmptyResponse:
    await verify_current_password(
        context,
        user,
        request.password,
        ip=ip,
        user_agent=user_agent,
    )
    await delete_account_state(context, user, ip=ip, user_agent=user_agent)
    return EmptyResponse(success=True)


async def request_delete_account(
    context: AuthContext,
    user: User,
    *,
    ip: str | None,
    user_agent: str | None,
) -> EmptyResponse:
    ttl_minutes = context.config.delete_account.token_ttl_minutes
    pair = context.token_service.generate_pair()
    await context.adapter.create_verification(
        Verification(
            identifier=user.email,
            value_hash=pair.hashed,
            purpose=VerificationPurpose.ACCOUNT_DELETION,
            expires_at=datetime.now(UTC) + timedelta(minutes=ttl_minutes),
        ),
    )
    await context.event_bus.publish(
        OtpGenerated(
            identifier=user.email,
            purpose=VerificationPurpose.ACCOUNT_DELETION.value,
            plain=pair.plain,
        ),
    )

    confirm_url = (
        context.config.delete_account.base_confirm_url + f"?token={quote(pair.plain)}"
    )
    html, text = context.template_renderer.render(
        "delete_account",
        {"confirm_url": confirm_url, "expires_in_minutes": ttl_minutes},
    )
    await context.email_sender.send(
        EmailMessage(
            kind=EmailMessageKind.ACCOUNT_DELETION,
            to=user.email,
            subject=context.config.delete_account.subject,
            html=html,
            text=text,
        ),
    )
    await context.event_bus.publish(
        UserDeleteRequested(
            user_id=user.id,
            identifier=user.email,
            ip_address=ip,
            user_agent=user_agent,
        ),
    )
    return EmptyResponse(success=True)


async def confirm_delete_account(
    context: AuthContext,
    user: User,
    request: DeleteAccountConfirmRequest,
    *,
    ip: str | None,
    user_agent: str | None,
) -> EmptyResponse:
    token_hash = context.token_service.hash_only(request.token)
    verification = await context.adapter.get_verification(
        user.email,
        VerificationPurpose.ACCOUNT_DELETION,
        token_hash,
    )
    if verification is None:
        raise TokenInvalidError(message="invalid account-deletion token")
    if verification.expires_at <= datetime.now(UTC):
        await context.adapter.delete_verification(verification.id)
        raise TokenExpiredError(message="account-deletion token expired")

    await delete_account_state(context, user, ip=ip, user_agent=user_agent)
    return EmptyResponse(success=True)


async def verify_current_password(
    context: AuthContext,
    user: User,
    password: str,
    *,
    ip: str | None,
    user_agent: str | None,
) -> None:
    identifier = user.email
    await context.lockout_tracker.check_locked(identifier)
    account = await context.adapter.get_account_for_user(user.id, ProviderId.CREDENTIAL)
    if account is None or account.password is None:
        raise NotFoundError(resource="credential_account")
    if not context.password_hasher.verify(password, account.password):
        await record_failure_and_maybe_emit(context, identifier, ip, user_agent)
        raise InvalidCredentialsError()
    await context.lockout_tracker.reset(identifier)


async def delete_account_state(
    context: AuthContext,
    user: User,
    *,
    ip: str | None,
    user_agent: str | None,
) -> None:
    await context.adapter.delete_user(user.id)
    await context.event_bus.publish(
        UserDeleted(user_id=user.id, ip_address=ip, user_agent=user_agent),
    )
