"""AuthApi — typed server-side callable surface (mirrors HTTP endpoints)."""

from __future__ import annotations

from typing import Any

from pydantic import ConfigDict

from fastauth.api import legacy as legacy_commands
from fastauth.api.commands import (
    ChangePasswordCommand,
    ConfirmEmailChangeCommand,
    ConfirmUserDeletionCommand,
    DeleteUserCommand,
    GetSessionCommand,
    ListSessionsCommand,
    RefreshSessionCommand,
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
from fastauth.api.responses import AuthenticationResponse, UserView, user_view
from fastauth.domain.models import User, WireModel
from fastauth.exceptions import InvalidCredentialsError, InvalidRequestError
from fastauth.flows.change_email import (
    ConfirmEmailChangeRequest,
    RequestEmailChangeRequest,
)
from fastauth.flows.change_email import (
    confirm_email_change as confirm_email_change_flow,
)
from fastauth.flows.change_email import (
    request_email_change as request_email_change_flow,
)
from fastauth.flows.change_password import ChangePasswordRequest
from fastauth.flows.change_password import change_password as change_password_flow
from fastauth.flows.credentials import (
    EmptyResponse,
    SessionResponse,
    SignInEmailRequest,
    SignInUsernameRequest,
    SignUpEmailRequest,
)
from fastauth.flows.credentials import (
    get_session as get_session_flow,
)
from fastauth.flows.credentials import (
    sign_in_email as sign_in_email_flow,
)
from fastauth.flows.credentials import (
    sign_in_username as sign_in_username_flow,
)
from fastauth.flows.credentials import (
    sign_out as sign_out_flow,
)
from fastauth.flows.credentials import (
    sign_up_email as sign_up_email_flow,
)
from fastauth.flows.password_reset import (
    ForgotPasswordRequest,
    ResetPasswordRequest,
)
from fastauth.flows.password_reset import (
    forgot_password as forgot_password_flow,
)
from fastauth.flows.password_reset import (
    reset_password as reset_password_flow,
)
from fastauth.flows.refresh import RefreshTokenRequest
from fastauth.flows.refresh import refresh_session as refresh_session_flow
from fastauth.flows.sessions import (
    ListSessionsResponse,
    RevokeSessionsResponse,
)
from fastauth.flows.sessions import (
    list_sessions_for_user as list_sessions_flow,
)
from fastauth.flows.sessions import (
    revoke_other_sessions as revoke_other_sessions_flow,
)
from fastauth.flows.sessions import (
    revoke_session as revoke_session_flow,
)
from fastauth.flows.user_management import (
    DeleteAccountConfirmRequest,
    DeleteAccountRequest,
    SetPasswordRequest,
    UpdateUserRequest,
    VerifyPasswordRequest,
    VerifyPasswordResponse,
)
from fastauth.flows.user_management import (
    confirm_delete_account as confirm_delete_account_flow,
)
from fastauth.flows.user_management import (
    delete_account_with_password as delete_account_with_password_flow,
)
from fastauth.flows.user_management import (
    request_delete_account as request_delete_account_flow,
)
from fastauth.flows.user_management import (
    set_password as set_password_flow,
)
from fastauth.flows.user_management import (
    update_user as update_user_flow,
)
from fastauth.flows.user_management import (
    verify_password as verify_password_flow,
)
from fastauth.flows.verification import (
    SendVerificationEmailRequest,
    VerifyEmailRequest,
)
from fastauth.flows.verification import (
    send_verification_email as send_verification_email_flow,
)
from fastauth.flows.verification import (
    verify_email as verify_email_flow,
)
from fastauth.plugins.email_password import require_email_password, require_username_sign_in
from fastauth.runtime.context import AuthContext
from fastauth.security.sessions import SessionContext

__all__ = ["AuthApi", "HealthResponse"]


class HealthResponse(WireModel):
    """Response payload for ``GET /auth/health`` and ``AuthApi.health()``."""

    model_config = ConfigDict(extra="forbid")
    status: str
    name: str


PrincipalCommandInput = (
    ListSessionsCommand
    | RevokeSessionCommand
    | RevokeOtherSessionsCommand
    | ChangePasswordCommand
    | UpdateUserCommand
    | SetPasswordCommand
    | VerifyPasswordCommand
    | DeleteUserCommand
    | RequestUserDeletionCommand
    | ConfirmUserDeletionCommand
    | RequestEmailChangeCommand
    | legacy_commands.ListSessionsCommand
    | legacy_commands.RevokeSessionCommand
    | legacy_commands.RevokeOtherSessionsCommand
    | legacy_commands.ChangePasswordCommand
    | legacy_commands.UpdateUserCommand
    | legacy_commands.SetPasswordCommand
    | legacy_commands.VerifyPasswordCommand
    | legacy_commands.DeleteUserCommand
    | legacy_commands.RequestUserDeletionCommand
    | legacy_commands.ConfirmUserDeletionCommand
    | legacy_commands.RequestEmailChangeCommand
)


def command_user_id(command: PrincipalCommandInput) -> str:
    principal = getattr(command, "principal", None)
    if isinstance(principal, UserPrincipal):
        return principal.user_id
    user = getattr(command, "user", None)
    if isinstance(user, User):
        return user.id
    raise InvalidCredentialsError()


async def resolve_command_user(context: AuthContext, command: PrincipalCommandInput) -> User:
    user = await context.adapter.get_user_by_id(command_user_id(command))
    if user is None:
        raise InvalidCredentialsError()
    return user


def command_session_id(
    command: PrincipalCommandInput,
) -> str | None:
    principal = getattr(command, "principal", None)
    if isinstance(principal, SessionPrincipal):
        return principal.session_id
    legacy_session_id = getattr(command, "current_session_id", None)
    if isinstance(legacy_session_id, str):
        return legacy_session_id
    return None


def require_command_session_id(command: PrincipalCommandInput) -> str:
    session_id = command_session_id(command)
    if session_id is None:
        raise InvalidRequestError(message="session_id is required")
    return session_id


async def resolve_session_command_user(
    context: AuthContext,
    command: PrincipalCommandInput,
) -> User:
    user = await resolve_command_user(context, command)
    session_id = require_command_session_id(command)
    sessions = await context.adapter.list_sessions_for_user(user.id)
    if not any(session.id == session_id for session in sessions):
        raise InvalidCredentialsError()
    return user


class RouterAuthApi:
    """Router-only bridge from HTTP handlers to flow functions."""

    def __init__(self, context: AuthContext) -> None:
        self.context = context

    async def health(self) -> HealthResponse:
        return HealthResponse(status="ok", name=self.context.config.app.name)

    async def internal_sign_in_username(
        self,
        request: SignInUsernameRequest,
        *,
        ip: str | None,
        user_agent: str | None,
    ) -> tuple[SessionResponse, SessionContext]:
        return await sign_in_username_flow(self.context, request, ip=ip, user_agent=user_agent)

    async def internal_sign_out(self, token: str | None) -> EmptyResponse:
        return await sign_out_flow(self.context, token)

    async def internal_get_session(self, token: str | None) -> SessionResponse | None:
        return await get_session_flow(self.context, token)

    async def internal_send_verification_email(
        self,
        request: SendVerificationEmailRequest,
        *,
        ip: str | None,
        user_agent: str | None,
    ) -> EmptyResponse:
        return await send_verification_email_flow(
            self.context,
            request,
            ip=ip,
            user_agent=user_agent,
        )

    async def internal_verify_email(
        self,
        request: VerifyEmailRequest,
        *,
        ip: str | None,
        user_agent: str | None,
    ) -> tuple[SessionResponse, SessionContext]:
        return await verify_email_flow(
            self.context,
            request,
            ip=ip,
            user_agent=user_agent,
        )

    async def internal_forgot_password(
        self,
        request: ForgotPasswordRequest,
        *,
        ip: str | None,
        user_agent: str | None,
    ) -> EmptyResponse:
        return await forgot_password_flow(
            self.context,
            request,
            ip=ip,
            user_agent=user_agent,
        )

    async def internal_reset_password(
        self,
        request: ResetPasswordRequest,
        *,
        ip: str | None,
        user_agent: str | None,
    ) -> EmptyResponse:
        return await reset_password_flow(
            self.context,
            request,
            ip=ip,
            user_agent=user_agent,
        )

    async def internal_change_password(
        self,
        user: User,
        *,
        current_session_id: str,
        request: ChangePasswordRequest,
        ip: str | None,
        user_agent: str | None,
    ) -> EmptyResponse:
        return await change_password_flow(
            self.context,
            user,
            current_session_id=current_session_id,
            request=request,
            ip=ip,
            user_agent=user_agent,
        )

    async def internal_update_user(
        self,
        user: User,
        request: UpdateUserRequest,
        *,
        ip: str | None,
        user_agent: str | None,
    ) -> User:
        return await update_user_flow(
            self.context,
            user,
            request,
            ip=ip,
            user_agent=user_agent,
        )

    async def internal_set_password(
        self,
        user: User,
        *,
        current_session_id: str,
        request: SetPasswordRequest,
        ip: str | None,
        user_agent: str | None,
    ) -> EmptyResponse:
        return await set_password_flow(
            self.context,
            user,
            current_session_id=current_session_id,
            request=request,
            ip=ip,
            user_agent=user_agent,
        )

    async def internal_verify_password(
        self,
        user: User,
        request: VerifyPasswordRequest,
        *,
        ip: str | None,
        user_agent: str | None,
    ) -> VerifyPasswordResponse:
        return await verify_password_flow(
            self.context,
            user,
            request,
            ip=ip,
            user_agent=user_agent,
        )

    async def internal_delete_account_with_password(
        self,
        user: User,
        request: DeleteAccountRequest,
        *,
        ip: str | None,
        user_agent: str | None,
    ) -> EmptyResponse:
        return await delete_account_with_password_flow(
            self.context,
            user,
            request,
            ip=ip,
            user_agent=user_agent,
        )

    async def internal_request_delete_account(
        self,
        user: User,
        *,
        ip: str | None,
        user_agent: str | None,
    ) -> EmptyResponse:
        return await request_delete_account_flow(
            self.context,
            user,
            ip=ip,
            user_agent=user_agent,
        )

    async def internal_confirm_delete_account(
        self,
        user: User,
        request: DeleteAccountConfirmRequest,
        *,
        ip: str | None,
        user_agent: str | None,
    ) -> EmptyResponse:
        return await confirm_delete_account_flow(
            self.context,
            user,
            request,
            ip=ip,
            user_agent=user_agent,
        )

    async def internal_request_email_change(
        self,
        user: User,
        request: RequestEmailChangeRequest,
        *,
        ip: str | None,
        user_agent: str | None,
    ) -> EmptyResponse:
        return await request_email_change_flow(
            self.context,
            user,
            request,
            ip=ip,
            user_agent=user_agent,
        )

    async def internal_confirm_email_change(
        self,
        request: ConfirmEmailChangeRequest,
        *,
        ip: str | None,
        user_agent: str | None,
    ) -> EmptyResponse:
        return await confirm_email_change_flow(
            self.context,
            request,
            ip=ip,
            user_agent=user_agent,
        )

    async def internal_list_sessions(
        self,
        user: User,
        *,
        current_session_id: str | None,
    ) -> ListSessionsResponse:
        return await list_sessions_flow(
            self.context,
            user=user,
            current_session_id=current_session_id,
        )

    async def internal_revoke_session(
        self,
        user: User,
        *,
        session_id: str,
    ) -> RevokeSessionsResponse:
        return await revoke_session_flow(self.context, user=user, session_id=session_id)

    async def internal_revoke_other_sessions(
        self,
        user: User,
        *,
        current_session_id: str | None,
    ) -> RevokeSessionsResponse:
        return await revoke_other_sessions_flow(
            self.context,
            user=user,
            current_session_id=current_session_id,
        )

    async def internal_refresh_session(
        self,
        request: RefreshTokenRequest,
        *,
        ip: str | None,
        user_agent: str | None,
    ) -> tuple[SessionResponse, SessionContext]:
        return await refresh_session_flow(
            self.context,
            request,
            ip=ip,
            user_agent=user_agent,
        )


class AuthApi:
    """Public server-side API surface built from command/result models."""

    def __init__(self, context: AuthContext) -> None:
        self.context = context
        self.sign_up = SignUpApi(self)
        self.sign_in = SignInApi(self)
        self.session = SessionApi(self)
        self.password = PasswordApi(self)
        self.user = UserApi(self)

    async def health(self) -> HealthResponse:
        return HealthResponse(status="ok", name=self.context.config.app.name)

    async def sign_out(self, command: SignOutCommand) -> EmptyResponse:
        token = command.token.get_secret_value() if command.token is not None else None
        return await sign_out_flow(self.context, token)

    async def generate_openapi_schema(self) -> dict[str, Any]:
        """Build the fastauth OpenAPI 3.1 schema offline (no running ASGI server).

        Requires ``OpenApiPlugin`` to be installed. Constructs a throwaway
        ``FastAPI`` app, mounts the fastauth router on it, and delegates to the
        plugin's ``render_schema`` helper so the title/version/etc. match the
        served ``/openapi.json`` response.

        **Rule exception — returns a plain ``dict``:** OpenAPI 3.1 documents are
        an external specification with thousands of optional fields; no static
        Pydantic model can faithfully capture every valid document. FastAPI's
        own ``get_openapi`` returns ``dict[str, Any]`` for the same reason. This
        is one of the four documented carve-outs from the "no plain dicts
        returned" rule (see CONTRIBUTING.md).
        """
        from fastapi import FastAPI

        from fastauth.plugins.openapi import OpenApiPlugin
        from fastauth.web.fastapi import build_router

        plugin = self.context.plugins.by_id.get("fastauth-openapi")
        if not isinstance(plugin, OpenApiPlugin):
            raise RuntimeError("OpenApiPlugin is not installed")
        temp_app = FastAPI()
        temp_app.include_router(build_router(self.context, self))
        return plugin.render_schema(temp_app)


class SignUpApi:
    def __init__(self, api: AuthApi) -> None:
        self._api = api

    async def email(self, command: SignUpEmailCommand) -> AuthenticationResponse:
        require_email_password(self._api.context)
        response, _session = await sign_up_email_flow(
            self._api.context,
            SignUpEmailRequest(
                email=command.email,
                password=command.password,
                name=command.name,
                username=command.username,
                delivery=command.delivery,
            ),
            ip=command.context.ip_address,
            user_agent=command.context.user_agent,
        )
        return response


class SignInApi:
    def __init__(self, api: AuthApi) -> None:
        self._api = api

    async def email(self, command: SignInEmailCommand) -> AuthenticationResponse:
        require_email_password(self._api.context)
        response, _session = await sign_in_email_flow(
            self._api.context,
            SignInEmailRequest(
                email=command.email,
                password=command.password,
                delivery=command.delivery,
            ),
            ip=command.context.ip_address,
            user_agent=command.context.user_agent,
        )
        return response

    async def username(self, command: SignInUsernameCommand) -> AuthenticationResponse:
        require_username_sign_in(self._api.context)
        response, _session = await sign_in_username_flow(
            self._api.context,
            SignInUsernameRequest(
                username=command.username,
                password=command.password,
                delivery=command.delivery,
            ),
            ip=command.context.ip_address,
            user_agent=command.context.user_agent,
        )
        return response


class SessionApi:
    def __init__(self, api: AuthApi) -> None:
        self._api = api

    async def get(self, command: GetSessionCommand) -> AuthenticationResponse | None:
        token = command.token.get_secret_value() if command.token is not None else None
        return await get_session_flow(self._api.context, token)

    async def refresh(self, command: RefreshSessionCommand) -> AuthenticationResponse:
        response, _session = await refresh_session_flow(
            self._api.context,
            RefreshTokenRequest(
                refresh_token=command.refresh_token,
                delivery=command.delivery,
            ),
            ip=command.context.ip_address,
            user_agent=command.context.user_agent,
        )
        return response

    async def list(
        self,
        command: ListSessionsCommand | legacy_commands.ListSessionsCommand,
    ) -> ListSessionsResponse:
        user = await resolve_command_user(self._api.context, command)
        return await list_sessions_flow(
            self._api.context,
            user=user,
            current_session_id=command_session_id(command),
        )

    async def revoke(
        self,
        command: RevokeSessionCommand | legacy_commands.RevokeSessionCommand,
    ) -> RevokeSessionsResponse:
        user = await resolve_command_user(self._api.context, command)
        return await revoke_session_flow(
            self._api.context,
            user=user,
            session_id=command.session_id,
        )

    async def revoke_other(
        self,
        command: RevokeOtherSessionsCommand | legacy_commands.RevokeOtherSessionsCommand,
    ) -> RevokeSessionsResponse:
        user = await resolve_session_command_user(self._api.context, command)
        return await revoke_other_sessions_flow(
            self._api.context,
            user=user,
            current_session_id=require_command_session_id(command),
        )


class PasswordApi:
    def __init__(self, api: AuthApi) -> None:
        self._api = api

    async def change(
        self,
        command: ChangePasswordCommand | legacy_commands.ChangePasswordCommand,
    ) -> EmptyResponse:
        require_email_password(self._api.context)
        user = await resolve_session_command_user(self._api.context, command)
        return await change_password_flow(
            self._api.context,
            user,
            current_session_id=require_command_session_id(command),
            request=ChangePasswordRequest(
                current_password=command.current_password,
                new_password=command.new_password,
                revoke_other_sessions=command.revoke_other_sessions,
            ),
            ip=command.context.ip_address,
            user_agent=command.context.user_agent,
        )

    async def request_reset(self, command: RequestPasswordResetCommand) -> EmptyResponse:
        require_email_password(self._api.context)
        return await forgot_password_flow(
            self._api.context,
            ForgotPasswordRequest(
                email=command.email,
                redirect_url=command.redirect_url,
            ),
            ip=command.context.ip_address,
            user_agent=command.context.user_agent,
        )

    async def reset(self, command: ResetPasswordCommand) -> EmptyResponse:
        require_email_password(self._api.context)
        return await reset_password_flow(
            self._api.context,
            ResetPasswordRequest(
                email=command.email,
                token=command.token,
                new_password=command.new_password,
            ),
            ip=command.context.ip_address,
            user_agent=command.context.user_agent,
        )


class UserApi:
    def __init__(self, api: AuthApi) -> None:
        self._api = api

    async def update(
        self,
        command: UpdateUserCommand | legacy_commands.UpdateUserCommand,
    ) -> UserView:
        require_email_password(self._api.context)
        user = await resolve_command_user(self._api.context, command)
        payload = command.model_dump(
            include={"name", "image", "metadata"},
            exclude_unset=True,
        )
        updated = await update_user_flow(
            self._api.context,
            user,
            UpdateUserRequest.model_validate(payload),
            ip=command.context.ip_address,
            user_agent=command.context.user_agent,
        )
        return user_view(updated)

    async def set_password(
        self,
        command: SetPasswordCommand | legacy_commands.SetPasswordCommand,
    ) -> EmptyResponse:
        require_email_password(self._api.context)
        user = await resolve_session_command_user(self._api.context, command)
        return await set_password_flow(
            self._api.context,
            user,
            current_session_id=require_command_session_id(command),
            request=SetPasswordRequest(
                new_password=command.new_password,
                revoke_other_sessions=command.revoke_other_sessions,
            ),
            ip=command.context.ip_address,
            user_agent=command.context.user_agent,
        )

    async def verify_password(
        self,
        command: VerifyPasswordCommand | legacy_commands.VerifyPasswordCommand,
    ) -> VerifyPasswordResponse:
        require_email_password(self._api.context)
        user = await resolve_command_user(self._api.context, command)
        return await verify_password_flow(
            self._api.context,
            user,
            VerifyPasswordRequest(password=command.password),
            ip=command.context.ip_address,
            user_agent=command.context.user_agent,
        )

    async def delete(
        self,
        command: DeleteUserCommand | legacy_commands.DeleteUserCommand,
    ) -> EmptyResponse:
        require_email_password(self._api.context)
        user = await resolve_command_user(self._api.context, command)
        return await delete_account_with_password_flow(
            self._api.context,
            user,
            DeleteAccountRequest(password=command.password),
            ip=command.context.ip_address,
            user_agent=command.context.user_agent,
        )

    async def request_delete(
        self,
        command: RequestUserDeletionCommand | legacy_commands.RequestUserDeletionCommand,
    ) -> EmptyResponse:
        require_email_password(self._api.context)
        user = await resolve_command_user(self._api.context, command)
        return await request_delete_account_flow(
            self._api.context,
            user,
            ip=command.context.ip_address,
            user_agent=command.context.user_agent,
        )

    async def confirm_delete(
        self,
        command: ConfirmUserDeletionCommand | legacy_commands.ConfirmUserDeletionCommand,
    ) -> EmptyResponse:
        require_email_password(self._api.context)
        user = await resolve_command_user(self._api.context, command)
        return await confirm_delete_account_flow(
            self._api.context,
            user,
            DeleteAccountConfirmRequest(token=command.token),
            ip=command.context.ip_address,
            user_agent=command.context.user_agent,
        )

    async def change_email(
        self,
        command: RequestEmailChangeCommand | legacy_commands.RequestEmailChangeCommand,
    ) -> EmptyResponse:
        require_email_password(self._api.context)
        user = await resolve_command_user(self._api.context, command)
        return await request_email_change_flow(
            self._api.context,
            user,
            RequestEmailChangeRequest(
                new_email=command.new_email,
                password=command.password,
            ),
            ip=command.context.ip_address,
            user_agent=command.context.user_agent,
        )

    async def confirm_email_change(self, command: ConfirmEmailChangeCommand) -> EmptyResponse:
        require_email_password(self._api.context)
        return await confirm_email_change_flow(
            self._api.context,
            ConfirmEmailChangeRequest(
                new_email=command.new_email,
                token=command.token,
            ),
            ip=command.context.ip_address,
            user_agent=command.context.user_agent,
        )
