"""Email/password first-party auth provider plugin."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import timedelta
from typing import TYPE_CHECKING, Any, ClassVar

from pydantic import Field

from fastauth.plugins.base import EndpointSpec, Plugin, PluginOptions

if TYPE_CHECKING:
    from fastauth.runtime.context import AuthContext

__all__ = [
    "EmailPasswordOptions",
    "EmailPasswordPlugin",
    "email_password_options",
    "require_email_password",
]


class EmailPasswordOptions(PluginOptions):
    """Static options for the email/password provider."""

    allow_username_sign_in: bool = True
    allow_bearer_tokens: bool = True
    require_email_verification: bool = False
    email_verification_expires_in: timedelta = Field(default=timedelta(minutes=15), gt=timedelta(0))
    password_reset_expires_in: timedelta = Field(default=timedelta(minutes=30), gt=timedelta(0))
    email_change_expires_in: timedelta = Field(default=timedelta(minutes=15), gt=timedelta(0))
    delete_account_expires_in: timedelta = Field(default=timedelta(minutes=15), gt=timedelta(0))


class EmailPasswordPlugin(Plugin):
    """Enable built-in email/password routes."""

    id: ClassVar[str] = "fastauth-email-password"

    def __init__(self, options: EmailPasswordOptions | None = None) -> None:
        self.options = options or EmailPasswordOptions()

    def endpoints(self) -> Sequence[EndpointSpec]:
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
        from fastauth.web.fastapi import clear_session_cookie, client_ip, set_session_cookie

        def annotate(
            handler: Callable[..., Any],
            annotations: dict[str, object],
        ) -> Callable[..., Any]:
            handler.__annotations__ = annotations
            return handler

        async def sign_up_email_handler(
            body: SignUpEmailRequest,
            request: Request,
            response: Response,
        ) -> SessionResponse:
            context = self.require_context()
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
            body: SignInEmailRequest,
            request: Request,
            response: Response,
        ) -> SessionResponse:
            context = self.require_context()
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
            body: SignInUsernameRequest,
            request: Request,
            response: Response,
        ) -> SessionResponse:
            context = self.require_context()
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
            body: SendVerificationEmailRequest,
            request: Request,
        ) -> EmptyResponse:
            context = self.require_context()
            return await send_verification_email(
                context,
                body,
                ip=client_ip(request, context),
                user_agent=request.headers.get("user-agent"),
            )

        async def verify_email_handler(
            body: VerifyEmailRequest,
            request: Request,
            response: Response,
        ) -> SessionResponse:
            context = self.require_context()
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
            body: ForgotPasswordRequest,
            request: Request,
        ) -> EmptyResponse:
            context = self.require_context()
            return await forgot_password(
                context,
                body,
                ip=client_ip(request, context),
                user_agent=request.headers.get("user-agent"),
            )

        async def reset_password_handler(
            body: ResetPasswordRequest,
            request: Request,
        ) -> EmptyResponse:
            context = self.require_context()
            return await reset_password(
                context,
                body,
                ip=client_ip(request, context),
                user_agent=request.headers.get("user-agent"),
            )

        async def change_password_handler(
            body: ChangePasswordRequest,
            request: Request,
        ) -> EmptyResponse:
            context = self.require_context()
            session_context = await self.require_session(request)
            return await change_password(
                context,
                session_context.user,
                current_session_id=session_context.session.id,
                request=body,
                ip=client_ip(request, context),
                user_agent=request.headers.get("user-agent"),
            )

        async def update_user_handler(
            body: UpdateUserRequest,
            request: Request,
        ) -> UserView:
            context = self.require_context()
            session_context = await self.require_session(request)
            updated = await update_user(
                context,
                session_context.user,
                body,
                ip=client_ip(request, context),
                user_agent=request.headers.get("user-agent"),
            )
            return user_view(updated)

        async def set_password_handler(
            body: SetPasswordRequest,
            request: Request,
        ) -> EmptyResponse:
            context = self.require_context()
            session_context = await self.require_session(request)
            return await set_password(
                context,
                session_context.user,
                current_session_id=session_context.session.id,
                request=body,
                ip=client_ip(request, context),
                user_agent=request.headers.get("user-agent"),
            )

        async def verify_password_handler(
            body: VerifyPasswordRequest,
            request: Request,
        ) -> VerifyPasswordResponse:
            context = self.require_context()
            session_context = await self.require_session(request)
            return await verify_password(
                context,
                session_context.user,
                body,
                ip=client_ip(request, context),
                user_agent=request.headers.get("user-agent"),
            )

        async def delete_account_handler(
            body: DeleteAccountRequest,
            request: Request,
            response: Response,
        ) -> EmptyResponse:
            context = self.require_context()
            session_context = await self.require_session(request)
            result = await delete_account_with_password(
                context,
                session_context.user,
                body,
                ip=client_ip(request, context),
                user_agent=request.headers.get("user-agent"),
            )
            clear_session_cookie(response, context)
            return result

        async def request_delete_account_handler(request: Request) -> EmptyResponse:
            context = self.require_context()
            session_context = await self.require_session(request)
            return await request_delete_account(
                context,
                session_context.user,
                ip=client_ip(request, context),
                user_agent=request.headers.get("user-agent"),
            )

        async def confirm_delete_account_handler(
            body: DeleteAccountConfirmRequest,
            request: Request,
            response: Response,
        ) -> EmptyResponse:
            context = self.require_context()
            session_context = await self.require_session(request)
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
            body: RequestEmailChangeRequest,
            request: Request,
        ) -> EmptyResponse:
            context = self.require_context()
            session_context = await self.require_session(request)
            return await request_email_change(
                context,
                session_context.user,
                body,
                ip=client_ip(request, context),
                user_agent=request.headers.get("user-agent"),
            )

        async def confirm_email_change_handler(
            body: ConfirmEmailChangeRequest,
            request: Request,
        ) -> EmptyResponse:
            context = self.require_context()
            return await confirm_email_change(
                context,
                body,
                ip=client_ip(request, context),
                user_agent=request.headers.get("user-agent"),
            )

        endpoints = [
            EndpointSpec.post(
                "/sign-up/email",
                name="sign_up_email",
                tags=["Auth"],
                request_model=SignUpEmailRequest,
                response_model=SessionResponse,
                handler=annotate(
                    sign_up_email_handler,
                    {
                        "body": SignUpEmailRequest,
                        "request": Request,
                        "response": Response,
                        "return": SessionResponse,
                    },
                ),
            ),
            EndpointSpec.post(
                "/sign-in/email",
                name="sign_in_email",
                tags=["Auth"],
                request_model=SignInEmailRequest,
                response_model=SessionResponse,
                handler=annotate(
                    sign_in_email_handler,
                    {
                        "body": SignInEmailRequest,
                        "request": Request,
                        "response": Response,
                        "return": SessionResponse,
                    },
                ),
            ),
            EndpointSpec.post(
                "/send-verification-email",
                name="send_verification_email",
                tags=["Auth"],
                request_model=SendVerificationEmailRequest,
                response_model=EmptyResponse,
                handler=annotate(
                    send_verification_email_handler,
                    {
                        "body": SendVerificationEmailRequest,
                        "request": Request,
                        "return": EmptyResponse,
                    },
                ),
            ),
            EndpointSpec.post(
                "/verify-email",
                name="verify_email",
                tags=["Auth"],
                request_model=VerifyEmailRequest,
                response_model=SessionResponse,
                handler=annotate(
                    verify_email_handler,
                    {
                        "body": VerifyEmailRequest,
                        "request": Request,
                        "response": Response,
                        "return": SessionResponse,
                    },
                ),
            ),
            EndpointSpec.post(
                "/forgot-password",
                name="forgot_password",
                tags=["Auth"],
                request_model=ForgotPasswordRequest,
                response_model=EmptyResponse,
                handler=annotate(
                    forgot_password_handler,
                    {
                        "body": ForgotPasswordRequest,
                        "request": Request,
                        "return": EmptyResponse,
                    },
                ),
            ),
            EndpointSpec.post(
                "/reset-password",
                name="reset_password",
                tags=["Auth"],
                request_model=ResetPasswordRequest,
                response_model=EmptyResponse,
                handler=annotate(
                    reset_password_handler,
                    {
                        "body": ResetPasswordRequest,
                        "request": Request,
                        "return": EmptyResponse,
                    },
                ),
            ),
            EndpointSpec.post(
                "/change-password",
                name="change_password",
                tags=["Auth"],
                request_model=ChangePasswordRequest,
                response_model=EmptyResponse,
                handler=annotate(
                    change_password_handler,
                    {
                        "body": ChangePasswordRequest,
                        "request": Request,
                        "return": EmptyResponse,
                    },
                ),
            ),
            EndpointSpec.route(
                "PATCH",
                "/user",
                name="update_user",
                tags=["Auth"],
                request_model=UpdateUserRequest,
                response_model=UserView,
                handler=annotate(
                    update_user_handler,
                    {
                        "body": UpdateUserRequest,
                        "request": Request,
                        "return": UserView,
                    },
                ),
            ),
            EndpointSpec.post(
                "/set-password",
                name="set_password",
                tags=["Auth"],
                request_model=SetPasswordRequest,
                response_model=EmptyResponse,
                handler=annotate(
                    set_password_handler,
                    {
                        "body": SetPasswordRequest,
                        "request": Request,
                        "return": EmptyResponse,
                    },
                ),
            ),
            EndpointSpec.post(
                "/verify-password",
                name="verify_password",
                tags=["Auth"],
                request_model=VerifyPasswordRequest,
                response_model=VerifyPasswordResponse,
                handler=annotate(
                    verify_password_handler,
                    {
                        "body": VerifyPasswordRequest,
                        "request": Request,
                        "return": VerifyPasswordResponse,
                    },
                ),
            ),
            EndpointSpec.post(
                "/delete-account",
                name="delete_account",
                tags=["Auth"],
                request_model=DeleteAccountRequest,
                response_model=EmptyResponse,
                handler=annotate(
                    delete_account_handler,
                    {
                        "body": DeleteAccountRequest,
                        "request": Request,
                        "response": Response,
                        "return": EmptyResponse,
                    },
                ),
            ),
            EndpointSpec.post(
                "/delete-account/request",
                name="request_delete_account",
                tags=["Auth"],
                response_model=EmptyResponse,
                handler=annotate(
                    request_delete_account_handler,
                    {"request": Request, "return": EmptyResponse},
                ),
            ),
            EndpointSpec.post(
                "/delete-account/confirm",
                name="confirm_delete_account",
                tags=["Auth"],
                request_model=DeleteAccountConfirmRequest,
                response_model=EmptyResponse,
                handler=annotate(
                    confirm_delete_account_handler,
                    {
                        "body": DeleteAccountConfirmRequest,
                        "request": Request,
                        "response": Response,
                        "return": EmptyResponse,
                    },
                ),
            ),
            EndpointSpec.post(
                "/change-email/request",
                name="request_email_change",
                tags=["Auth"],
                request_model=RequestEmailChangeRequest,
                response_model=EmptyResponse,
                handler=annotate(
                    request_email_change_handler,
                    {
                        "body": RequestEmailChangeRequest,
                        "request": Request,
                        "return": EmptyResponse,
                    },
                ),
            ),
            EndpointSpec.post(
                "/change-email/confirm",
                name="confirm_email_change",
                tags=["Auth"],
                request_model=ConfirmEmailChangeRequest,
                response_model=EmptyResponse,
                handler=annotate(
                    confirm_email_change_handler,
                    {
                        "body": ConfirmEmailChangeRequest,
                        "request": Request,
                        "return": EmptyResponse,
                    },
                ),
            ),
        ]
        if self.options.allow_username_sign_in:
            endpoints.append(
                EndpointSpec.post(
                    "/sign-in/username",
                    name="sign_in_username",
                    tags=["Auth"],
                    request_model=SignInUsernameRequest,
                    response_model=SessionResponse,
                    handler=annotate(
                        sign_in_username_handler,
                        {
                            "body": SignInUsernameRequest,
                            "request": Request,
                            "response": Response,
                            "return": SessionResponse,
                        },
                    ),
                ),
            )
        return endpoints


def email_password_options(context: AuthContext) -> EmailPasswordOptions | None:
    for plugin in context.plugins.plugins:
        if isinstance(plugin, EmailPasswordPlugin):
            return plugin.options
    return None


def require_email_password(context: AuthContext) -> EmailPasswordPlugin:
    from fastauth.exceptions import FeatureNotEnabledError

    plugin = context.plugins.by_id.get(EmailPasswordPlugin.id)
    if not isinstance(plugin, EmailPasswordPlugin):
        raise FeatureNotEnabledError(feature="email-password")
    return plugin
