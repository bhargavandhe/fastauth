"""Pythonic public SDK managers layered over the command API."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import EmailStr, SecretStr

from fastauth.api.commands import (
    BearerCredentialDelivery,
    ChangePasswordCommand,
    ConfirmEmailChangeCommand,
    ConfirmUserDeletionCommand,
    CookieCredentialDelivery,
    CredentialDelivery,
    DeleteUserCommand,
    GetSessionCommand,
    ListSessionsCommand,
    RefreshSessionCommand,
    RequestContext,
    RequestEmailChangeCommand,
    RequestPasswordResetCommand,
    RequestUserDeletionCommand,
    ResetPasswordCommand,
    RevokeOtherSessionsCommand,
    RevokeSessionCommand,
    SessionPrincipal,
    SetPasswordCommand,
    SignInEmailCommand,
    SignInUsernameCommand,
    SignOutCommand,
    SignUpEmailCommand,
    UpdateUserCommand,
    UserPrincipal,
    VerifyPasswordCommand,
)
from fastauth.api.responses import AuthenticationResponse, UserView
from fastauth.domain.value_objects import UserMetadata, Username
from fastauth.flows.credentials import EmptyResponse
from fastauth.flows.sessions import ListSessionsResponse, RevokeSessionsResponse
from fastauth.flows.user_management import VerifyPasswordResponse
from fastauth.runtime.manager_inputs import SessionIdInput, UserIdInput, to_session_id, to_user_id

if TYPE_CHECKING:
    from fastauth.runtime.auth import FastAuth

__all__ = [
    "EmailChangesManager",
    "PasswordsManager",
    "SessionsManager",
    "SignInManager",
    "SignUpManager",
    "UsersManager",
]


class SignUpManager:
    def __init__(self, auth: FastAuth) -> None:
        self._auth = auth

    async def email(
        self,
        email: EmailStr,
        password: SecretStr,
        *,
        name: str | None = None,
        username: Username | None = None,
        context: RequestContext | None = None,
        delivery: CredentialDelivery | None = None,
    ) -> AuthenticationResponse:
        return await self._auth.api.sign_up.email(
            SignUpEmailCommand(
                email=email,
                password=password,
                name=name,
                username=username,
                context=context or RequestContext(),
                delivery=delivery or CookieCredentialDelivery(),
            )
        )


class SignInManager:
    def __init__(self, auth: FastAuth) -> None:
        self._auth = auth

    async def email(
        self,
        email: EmailStr,
        password: SecretStr,
        *,
        context: RequestContext | None = None,
        delivery: CredentialDelivery | None = None,
    ) -> AuthenticationResponse:
        return await self._auth.api.sign_in.email(
            SignInEmailCommand(
                email=email,
                password=password,
                context=context or RequestContext(),
                delivery=delivery or CookieCredentialDelivery(),
            )
        )

    async def username(
        self,
        username: Username,
        password: SecretStr,
        *,
        context: RequestContext | None = None,
        delivery: CredentialDelivery | None = None,
    ) -> AuthenticationResponse:
        return await self._auth.api.sign_in.username(
            SignInUsernameCommand(
                username=username,
                password=password,
                context=context or RequestContext(),
                delivery=delivery or CookieCredentialDelivery(),
            )
        )


class SessionsManager:
    def __init__(self, auth: FastAuth) -> None:
        self._auth = auth

    async def get(self, token: SecretStr | None = None) -> AuthenticationResponse | None:
        return await self._auth.api.session.get(GetSessionCommand(token=token))

    async def refresh(
        self,
        refresh_token: SecretStr,
        *,
        context: RequestContext | None = None,
        delivery: CredentialDelivery | None = None,
    ) -> AuthenticationResponse:
        return await self._auth.api.session.refresh(
            RefreshSessionCommand(
                refresh_token=refresh_token,
                context=context or RequestContext(),
                delivery=delivery or BearerCredentialDelivery(),
            )
        )

    async def list(self, uid: UserIdInput) -> ListSessionsResponse:
        return await self._auth.api.session.list(
            ListSessionsCommand(principal=UserPrincipal(user_id=to_user_id(uid)))
        )

    async def revoke(
        self,
        uid: UserIdInput,
        sid: SessionIdInput,
    ) -> RevokeSessionsResponse:
        return await self._auth.api.session.revoke(
            RevokeSessionCommand(
                principal=UserPrincipal(user_id=to_user_id(uid)),
                session_id=to_session_id(sid),
            )
        )

    async def revoke_other(
        self,
        uid: UserIdInput,
        sid: SessionIdInput,
    ) -> RevokeSessionsResponse:
        return await self._auth.api.session.revoke_other(
            RevokeOtherSessionsCommand(
                principal=SessionPrincipal(user_id=to_user_id(uid), session_id=to_session_id(sid)),
            )
        )

    async def sign_out(self, token: SecretStr | None = None) -> EmptyResponse:
        return await self._auth.api.sign_out(SignOutCommand(token=token))


class UsersManager:
    def __init__(self, auth: FastAuth) -> None:
        self._auth = auth

    async def update(
        self,
        uid: UserIdInput,
        *,
        name: str | None = None,
        image: str | None = None,
        metadata: UserMetadata | None = None,
        context: RequestContext | None = None,
    ) -> UserView:
        return await self._auth.api.user.update(
            UpdateUserCommand(
                principal=UserPrincipal(user_id=to_user_id(uid)),
                name=name,
                image=image,
                metadata=metadata,
                context=context or RequestContext(),
            )
        )

    async def delete(
        self,
        uid: UserIdInput,
        password: SecretStr,
        *,
        context: RequestContext | None = None,
    ) -> EmptyResponse:
        return await self._auth.api.user.delete(
            DeleteUserCommand(
                principal=UserPrincipal(user_id=to_user_id(uid)),
                password=password,
                context=context or RequestContext(),
            )
        )

    async def request_delete(
        self,
        uid: UserIdInput,
        *,
        context: RequestContext | None = None,
    ) -> EmptyResponse:
        return await self._auth.api.user.request_delete(
            RequestUserDeletionCommand(
                principal=UserPrincipal(user_id=to_user_id(uid)),
                context=context or RequestContext(),
            )
        )

    async def confirm_delete(
        self,
        uid: UserIdInput,
        token: SecretStr,
        *,
        context: RequestContext | None = None,
    ) -> EmptyResponse:
        return await self._auth.api.user.confirm_delete(
            ConfirmUserDeletionCommand(
                principal=UserPrincipal(user_id=to_user_id(uid)),
                token=token,
                context=context or RequestContext(),
            )
        )


class PasswordsManager:
    def __init__(self, auth: FastAuth) -> None:
        self._auth = auth

    async def change(
        self,
        *,
        user_id: UserIdInput,
        session_id: SessionIdInput,
        current_password: SecretStr,
        new_password: SecretStr,
        revoke_other_sessions: bool = True,
        context: RequestContext | None = None,
    ) -> EmptyResponse:
        return await self._auth.api.password.change(
            ChangePasswordCommand(
                principal=SessionPrincipal(
                    user_id=to_user_id(user_id),
                    session_id=to_session_id(session_id),
                ),
                current_password=current_password,
                new_password=new_password,
                revoke_other_sessions=revoke_other_sessions,
                context=context or RequestContext(),
            )
        )

    async def request_reset(
        self,
        email: EmailStr,
        *,
        redirect_url: str | None = None,
        context: RequestContext | None = None,
    ) -> EmptyResponse:
        return await self._auth.api.password.request_reset(
            RequestPasswordResetCommand(
                email=email,
                redirect_url=redirect_url,
                context=context or RequestContext(),
            )
        )

    async def reset(
        self,
        email: EmailStr,
        token: SecretStr,
        new_password: SecretStr,
        *,
        context: RequestContext | None = None,
    ) -> EmptyResponse:
        return await self._auth.api.password.reset(
            ResetPasswordCommand(
                email=email,
                token=token,
                new_password=new_password,
                context=context or RequestContext(),
            )
        )

    async def set(
        self,
        *,
        user_id: UserIdInput,
        session_id: SessionIdInput,
        new_password: SecretStr,
        revoke_other_sessions: bool = True,
        context: RequestContext | None = None,
    ) -> EmptyResponse:
        return await self._auth.api.user.set_password(
            SetPasswordCommand(
                principal=SessionPrincipal(
                    user_id=to_user_id(user_id),
                    session_id=to_session_id(session_id),
                ),
                new_password=new_password,
                revoke_other_sessions=revoke_other_sessions,
                context=context or RequestContext(),
            )
        )

    async def verify(
        self,
        uid: UserIdInput,
        password: SecretStr,
        *,
        context: RequestContext | None = None,
    ) -> VerifyPasswordResponse:
        return await self._auth.api.user.verify_password(
            VerifyPasswordCommand(
                principal=UserPrincipal(user_id=to_user_id(uid)),
                password=password,
                context=context or RequestContext(),
            )
        )


class EmailChangesManager:
    def __init__(self, auth: FastAuth) -> None:
        self._auth = auth

    async def request(
        self,
        uid: UserIdInput,
        new_email: EmailStr,
        password: SecretStr,
        *,
        context: RequestContext | None = None,
    ) -> EmptyResponse:
        return await self._auth.api.user.change_email(
            RequestEmailChangeCommand(
                principal=UserPrincipal(user_id=to_user_id(uid)),
                new_email=new_email,
                password=password,
                context=context or RequestContext(),
            )
        )

    async def confirm(
        self,
        new_email: EmailStr,
        token: SecretStr,
        *,
        context: RequestContext | None = None,
    ) -> EmptyResponse:
        return await self._auth.api.user.confirm_email_change(
            ConfirmEmailChangeCommand(
                new_email=new_email,
                token=token,
                context=context or RequestContext(),
            )
        )
