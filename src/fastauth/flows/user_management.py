"""Authenticated user profile, password setup, verification, and account deletion."""

from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import quote

from pydantic import ConfigDict, SecretStr, model_validator

from fastauth.domain.enums import EmailMessageKind, ProviderId, VerificationPurpose
from fastauth.domain.events import (
    OtpGenerated,
    PasswordChanged,
    SessionsRevokedAll,
    UserDeleted,
    UserDeleteRequested,
    UserUpdated,
)
from fastauth.domain.models import Account, EmailMessage, User, Verification, WireModel
from fastauth.domain.value_objects import UserMetadata, Username
from fastauth.exceptions import (
    DuplicateError,
    FeatureNotEnabledError,
    InvalidCredentialsError,
    NotFoundError,
    PasswordAlreadySetError,
    TokenExpiredError,
    TokenInvalidError,
)
from fastauth.flows.callbacks import resolve_callback_url
from fastauth.flows.credentials import (
    EmptyResponse,
    record_failure_and_maybe_emit,
    validate_password_policy,
)
from fastauth.plugins.email_password import require_email_password
from fastauth.runtime.context import AuthContext

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
    metadata: UserMetadata | None = None
    username: Username | None = None

    @model_validator(mode="after")
    def reject_explicit_nulls(self) -> UpdateUserRequest:
        if "metadata" in self.model_fields_set and self.metadata is None:
            raise ValueError("metadata must be an object")
        if "username" in self.model_fields_set and self.username is None:
            raise ValueError("username must not be null")
        return self


class SetPasswordRequest(WireModel):
    model_config = ConfigDict(extra="forbid")
    new_password: SecretStr
    revoke_other_sessions: bool = True


class VerifyPasswordRequest(WireModel):
    model_config = ConfigDict(extra="forbid")
    password: SecretStr


class VerifyPasswordResponse(WireModel):
    valid: bool


class DeleteAccountRequest(WireModel):
    model_config = ConfigDict(extra="forbid")
    password: SecretStr


class DeleteAccountConfirmRequest(WireModel):
    model_config = ConfigDict(extra="forbid")
    token: SecretStr


async def update_user(
    context: AuthContext,
    user: User,
    request: UpdateUserRequest,
    *,
    ip: str | None,
    user_agent: str | None,
) -> User:
    changed_fields: list[str] = []
    old_username: str | None = None
    if "name" in request.model_fields_set:
        user.name = request.name
        changed_fields.append("name")
    if "image" in request.model_fields_set:
        user.image = request.image
        changed_fields.append("image")
    if "metadata" in request.model_fields_set:
        user.metadata = request.metadata.model_dump(mode="json") if request.metadata else {}
        changed_fields.append("metadata")
    if "username" in request.model_fields_set:
        plugin = require_email_password(context)
        if not plugin.options.allow_username_change:
            raise FeatureNotEnabledError(feature="username-change")
        assert request.username is not None
        if request.username != user.username:
            existing = await context.adapter.get_user_by_username(request.username)
            if existing is not None and existing.id != user.id:
                raise DuplicateError(resource="user", field="username")
            old_username = user.username
            user.username = request.username
            changed_fields.append("username")

    if not changed_fields:
        return user

    updated = await context.adapter.update_user(user)
    if old_username is not None and updated.username is not None:
        await context.lockout_tracker.rekey(old_username, updated.username)
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

    account.password = context.password_hasher.hash(
        validate_password_policy(context, request.new_password),
    )
    await context.adapter.update_account(account)
    await context.lockout_tracker.reset(user.email)
    if user.username is not None:
        await context.lockout_tracker.reset(user.username)

    revoked = 0
    if request.revoke_other_sessions:
        revoked = await context.adapter.delete_sessions_for_user(
            user.id,
            except_session_id=current_session_id,
        )
        await context.refresh_token_service.revoke_for_user_except_session(
            user.id,
            current_session_id,
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
    app_base_url: str | None = None,
) -> EmptyResponse:
    expires_in = context.config.delete_account.expires_in
    ttl_minutes = max(1, int(expires_in.total_seconds() // 60))
    pair = context.token_service.generate_pair()
    await context.adapter.create_verification(
        Verification(
            identifier=user.email,
            value_hash=pair.hashed,
            purpose=VerificationPurpose.ACCOUNT_DELETION,
            expires_at=datetime.now(UTC) + expires_in,
        ),
    )
    await context.event_bus.publish(
        OtpGenerated(
            identifier=user.email,
            purpose=VerificationPurpose.ACCOUNT_DELETION.value,
            plain=pair.plain,
        ),
    )

    confirm_base_url = resolve_callback_url(
        app_base_url=app_base_url or context.config.app.base_url,
        callback_path=context.config.delete_account.callback_path,
        override=context.config.delete_account.callback_url_override,
    )
    confirm_url = confirm_base_url + f"?token={quote(pair.plain)}"
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
    token_hash = context.token_service.hash_only(request.token.get_secret_value())
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
    password: SecretStr,
    *,
    ip: str | None,
    user_agent: str | None,
) -> None:
    identifier = user.email
    await context.lockout_tracker.check_locked(identifier)
    account = await context.adapter.get_account_for_user(user.id, ProviderId.CREDENTIAL)
    if account is None or account.password is None:
        raise NotFoundError(resource="credential_account")
    if not context.password_hasher.verify(password.get_secret_value(), account.password):
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
