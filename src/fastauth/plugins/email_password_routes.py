"""HTTP endpoint handlers owned by the email/password plugin."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from fastapi import Request, Response

from fastauth.api.commands import CookieCredentialDelivery
from fastauth.api.responses import UserView, user_view
from fastauth.flows.change_email import (
    ConfirmEmailChangeRequest,
    RequestEmailChangeRequest,
    confirm_email_change,
    request_email_change,
)
from fastauth.flows.change_password import ChangePasswordRequest, change_password
from fastauth.flows.credentials import (
    EmptyResponse,
    SessionResponse,
    SignInEmailRequest,
    SignInUsernameRequest,
    SignUpEmailRequest,
    sign_in_email,
    sign_in_username,
    sign_up_email,
)
from fastauth.flows.password_reset import (
    ForgotPasswordRequest,
    ResetPasswordRequest,
    forgot_password,
    reset_password,
)
from fastauth.flows.user_management import (
    DeleteAccountConfirmRequest,
    DeleteAccountRequest,
    SetPasswordRequest,
    UpdateUserRequest,
    VerifyPasswordRequest,
    VerifyPasswordResponse,
    confirm_delete_account,
    delete_account_with_password,
    request_delete_account,
    set_password,
    update_user,
    verify_password,
)
from fastauth.flows.verification import (
    SendVerificationEmailRequest,
    VerifyEmailRequest,
    send_verification_email,
    verify_email,
)
from fastauth.plugins.base import EndpointSpec
from fastauth.web.fastapi import clear_session_cookie, client_ip, set_session_cookie

if TYPE_CHECKING:
    from fastauth.plugins.email_password import EmailPasswordPlugin


class EmailPasswordRouteHandlers:
    def __init__(self, plugin: EmailPasswordPlugin) -> None:
        self.plugin = plugin

    async def sign_up_email_handler(
        self,
        body: SignUpEmailRequest,
        request: Request,
        response: Response,
    ) -> SessionResponse:
        context = self.plugin.require_context()
        result, session_context = await sign_up_email(
            context,
            body,
            ip=client_ip(request, context),
            user_agent=request.headers.get("user-agent"),
        )
        if isinstance(body.delivery, CookieCredentialDelivery):
            set_session_cookie(
                response,
                context,
                session_context.token,
                context.config.session.max_age_seconds,
            )
        return result

    async def sign_in_email_handler(
        self,
        body: SignInEmailRequest,
        request: Request,
        response: Response,
    ) -> SessionResponse:
        context = self.plugin.require_context()
        result, session_context = await sign_in_email(
            context,
            body,
            ip=client_ip(request, context),
            user_agent=request.headers.get("user-agent"),
        )
        if isinstance(body.delivery, CookieCredentialDelivery):
            set_session_cookie(
                response,
                context,
                session_context.token,
                context.config.session.max_age_seconds,
            )
        return result

    async def sign_in_username_handler(
        self,
        body: SignInUsernameRequest,
        request: Request,
        response: Response,
    ) -> SessionResponse:
        from fastauth.plugins.email_password import require_username_sign_in

        context = self.plugin.require_context()
        require_username_sign_in(context)
        result, session_context = await sign_in_username(
            context,
            body,
            ip=client_ip(request, context),
            user_agent=request.headers.get("user-agent"),
        )
        if isinstance(body.delivery, CookieCredentialDelivery):
            set_session_cookie(
                response,
                context,
                session_context.token,
                context.config.session.max_age_seconds,
            )
        return result

    async def send_verification_email_handler(
        self,
        body: SendVerificationEmailRequest,
        request: Request,
    ) -> EmptyResponse:
        context = self.plugin.require_context()
        return await send_verification_email(
            context,
            body,
            ip=client_ip(request, context),
            user_agent=request.headers.get("user-agent"),
        )

    async def verify_email_handler(
        self,
        body: VerifyEmailRequest,
        request: Request,
        response: Response,
    ) -> SessionResponse:
        context = self.plugin.require_context()
        result, session_context = await verify_email(
            context,
            body,
            ip=client_ip(request, context),
            user_agent=request.headers.get("user-agent"),
        )
        set_session_cookie(
            response,
            context,
            session_context.token,
            context.config.session.max_age_seconds,
        )
        return result

    async def forgot_password_handler(
        self,
        body: ForgotPasswordRequest,
        request: Request,
    ) -> EmptyResponse:
        context = self.plugin.require_context()
        return await forgot_password(
            context,
            body,
            ip=client_ip(request, context),
            user_agent=request.headers.get("user-agent"),
        )

    async def reset_password_handler(
        self,
        body: ResetPasswordRequest,
        request: Request,
    ) -> EmptyResponse:
        context = self.plugin.require_context()
        return await reset_password(
            context,
            body,
            ip=client_ip(request, context),
            user_agent=request.headers.get("user-agent"),
        )

    async def change_password_handler(
        self,
        body: ChangePasswordRequest,
        request: Request,
    ) -> EmptyResponse:
        context = self.plugin.require_context()
        session_context = await self.plugin.require_session(request)
        return await change_password(
            context,
            session_context.user,
            current_session_id=session_context.session.id,
            request=body,
            ip=client_ip(request, context),
            user_agent=request.headers.get("user-agent"),
        )

    async def update_user_handler(
        self,
        body: UpdateUserRequest,
        request: Request,
    ) -> UserView:
        context = self.plugin.require_context()
        session_context = await self.plugin.require_session(request)
        updated = await update_user(
            context,
            session_context.user,
            body,
            ip=client_ip(request, context),
            user_agent=request.headers.get("user-agent"),
        )
        return user_view(updated)

    async def set_password_handler(
        self,
        body: SetPasswordRequest,
        request: Request,
    ) -> EmptyResponse:
        context = self.plugin.require_context()
        session_context = await self.plugin.require_session(request)
        return await set_password(
            context,
            session_context.user,
            current_session_id=session_context.session.id,
            request=body,
            ip=client_ip(request, context),
            user_agent=request.headers.get("user-agent"),
        )

    async def verify_password_handler(
        self,
        body: VerifyPasswordRequest,
        request: Request,
    ) -> VerifyPasswordResponse:
        context = self.plugin.require_context()
        session_context = await self.plugin.require_session(request)
        return await verify_password(
            context,
            session_context.user,
            body,
            ip=client_ip(request, context),
            user_agent=request.headers.get("user-agent"),
        )

    async def delete_account_handler(
        self,
        body: DeleteAccountRequest,
        request: Request,
        response: Response,
    ) -> EmptyResponse:
        context = self.plugin.require_context()
        session_context = await self.plugin.require_session(request)
        result = await delete_account_with_password(
            context,
            session_context.user,
            body,
            ip=client_ip(request, context),
            user_agent=request.headers.get("user-agent"),
        )
        clear_session_cookie(response, context)
        return result

    async def request_delete_account_handler(self, request: Request) -> EmptyResponse:
        context = self.plugin.require_context()
        session_context = await self.plugin.require_session(request)
        return await request_delete_account(
            context,
            session_context.user,
            ip=client_ip(request, context),
            user_agent=request.headers.get("user-agent"),
        )

    async def confirm_delete_account_handler(
        self,
        body: DeleteAccountConfirmRequest,
        request: Request,
        response: Response,
    ) -> EmptyResponse:
        context = self.plugin.require_context()
        session_context = await self.plugin.require_session(request)
        result = await confirm_delete_account(
            context,
            session_context.user,
            body,
            ip=client_ip(request, context),
            user_agent=request.headers.get("user-agent"),
        )
        clear_session_cookie(response, context)
        return result

    async def request_email_change_handler(
        self,
        body: RequestEmailChangeRequest,
        request: Request,
    ) -> EmptyResponse:
        context = self.plugin.require_context()
        session_context = await self.plugin.require_session(request)
        return await request_email_change(
            context,
            session_context.user,
            body,
            ip=client_ip(request, context),
            user_agent=request.headers.get("user-agent"),
        )

    async def confirm_email_change_handler(
        self,
        body: ConfirmEmailChangeRequest,
        request: Request,
    ) -> EmptyResponse:
        context = self.plugin.require_context()
        return await confirm_email_change(
            context,
            body,
            ip=client_ip(request, context),
            user_agent=request.headers.get("user-agent"),
        )

    def authentication_endpoints(self) -> list[EndpointSpec]:
        endpoints = [
            EndpointSpec.post(
                "/sign-up/email",
                name="sign_up_email",
                tags=["Auth"],
                response_model=SessionResponse,
                handler=self.sign_up_email_handler,
            ),
            EndpointSpec.post(
                "/sign-in/email",
                name="sign_in_email",
                tags=["Auth"],
                response_model=SessionResponse,
                handler=self.sign_in_email_handler,
            ),
        ]
        if self.plugin.options.allow_username_sign_in:
            endpoints.append(
                EndpointSpec.post(
                    "/sign-in/username",
                    name="sign_in_username",
                    tags=["Auth"],
                    response_model=SessionResponse,
                    handler=self.sign_in_username_handler,
                ),
            )
        return endpoints

    def verification_endpoints(self) -> list[EndpointSpec]:
        return [
            EndpointSpec.post(
                "/send-verification-email",
                name="send_verification_email",
                tags=["Auth"],
                response_model=EmptyResponse,
                handler=self.send_verification_email_handler,
            ),
            EndpointSpec.post(
                "/verify-email",
                name="verify_email",
                tags=["Auth"],
                response_model=SessionResponse,
                handler=self.verify_email_handler,
            ),
        ]

    def password_endpoints(self) -> list[EndpointSpec]:
        return [
            EndpointSpec.post(
                "/forgot-password",
                name="forgot_password",
                tags=["Auth"],
                response_model=EmptyResponse,
                handler=self.forgot_password_handler,
            ),
            EndpointSpec.post(
                "/reset-password",
                name="reset_password",
                tags=["Auth"],
                response_model=EmptyResponse,
                handler=self.reset_password_handler,
            ),
            EndpointSpec.post(
                "/change-password",
                name="change_password",
                tags=["Auth"],
                response_model=EmptyResponse,
                handler=self.change_password_handler,
            ),
            EndpointSpec.post(
                "/set-password",
                name="set_password",
                tags=["Auth"],
                response_model=EmptyResponse,
                handler=self.set_password_handler,
            ),
            EndpointSpec.post(
                "/verify-password",
                name="verify_password",
                tags=["Auth"],
                response_model=VerifyPasswordResponse,
                handler=self.verify_password_handler,
            ),
        ]

    def account_endpoints(self) -> list[EndpointSpec]:
        return [
            EndpointSpec.route(
                "PATCH",
                "/user",
                name="update_user",
                tags=["Auth"],
                response_model=UserView,
                handler=self.update_user_handler,
            ),
            EndpointSpec.post(
                "/delete-account",
                name="delete_account",
                tags=["Auth"],
                response_model=EmptyResponse,
                handler=self.delete_account_handler,
            ),
            EndpointSpec.post(
                "/delete-account/request",
                name="request_delete_account",
                tags=["Auth"],
                response_model=EmptyResponse,
                handler=self.request_delete_account_handler,
            ),
            EndpointSpec.post(
                "/delete-account/confirm",
                name="confirm_delete_account",
                tags=["Auth"],
                response_model=EmptyResponse,
                handler=self.confirm_delete_account_handler,
            ),
            EndpointSpec.post(
                "/change-email/request",
                name="request_email_change",
                tags=["Auth"],
                response_model=EmptyResponse,
                handler=self.request_email_change_handler,
            ),
            EndpointSpec.post(
                "/change-email/confirm",
                name="confirm_email_change",
                tags=["Auth"],
                response_model=EmptyResponse,
                handler=self.confirm_email_change_handler,
            ),
        ]

    def endpoints(self) -> list[EndpointSpec]:
        return [
            *self.authentication_endpoints(),
            *self.verification_endpoints(),
            *self.password_endpoints(),
            *self.account_endpoints(),
        ]


def email_password_endpoints(plugin: EmailPasswordPlugin) -> Sequence[EndpointSpec]:
    return EmailPasswordRouteHandlers(plugin).endpoints()
