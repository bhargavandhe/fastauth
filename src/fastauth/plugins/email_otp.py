"""``EmailOtpPlugin`` — sign-in / verify-email / password-reset / change-email via email OTP.

Surface mirrors better-auth's email-OTP plugin:

* ``POST /email-otp/send-verification-otp``
* ``POST /email-otp/check-verification-otp``
* ``POST /sign-in/email-otp``
* ``POST /email-otp/verify-email``
* ``POST /email-otp/request-password-reset``
* ``POST /email-otp/reset-password``
* ``POST /email-otp/request-email-change``  (when email-change is enabled)
* ``POST /email-otp/change-email``           (when email-change is enabled)

The actual flow logic lives in :mod:`fastauth.flows.email_otp` so the
plugin file stays focused on HTTP wiring + config + audit subscriptions.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import timedelta
from typing import ClassVar

from fastapi import Request, Response

from fastauth.api.commands import CookieCredentialDelivery
from fastauth.exceptions import InvalidCredentialsError
from fastauth.flows.credentials import EmptyResponse, SessionResponse
from fastauth.flows.email_otp import (
    ChangeEmailOtpRequest,
    CheckOtpRequest,
    RequestEmailChangeOtpRequest,
    RequestPasswordResetOtpRequest,
    ResetPasswordOtpRequest,
    SendOtpRequest,
    SignInOtpRequest,
    VerifyEmailOtpRequest,
    change_email_with_otp,
    check_otp,
    request_email_change_otp,
    request_password_reset_otp,
    reset_password_with_otp,
    send_otp,
    sign_in_with_otp,
    verify_email_with_otp,
)
from fastauth.plugins.base import EndpointSpec, Plugin, RateLimitRule
from fastauth.plugins.email_otp_options import EmailChangeOtpOptions, EmailOtpOptions
from fastauth.runtime.context import AuthContext
from fastauth.security.otp import OtpService

__all__ = ["EmailChangeOtpOptions", "EmailOtpOptions", "EmailOtpPlugin"]


class EmailOtpPlugin(Plugin):
    """Plugin enabling email-OTP sign-in, verification, password reset, and
    optionally email-change. See the module docstring for the endpoint list.
    """

    id: ClassVar[str] = "fastauth-email-otp"

    def __init__(self, options: EmailOtpOptions | None = None) -> None:
        self.options = options or EmailOtpOptions()
        self.config = self.options
        self.otp_service = OtpService(length=self.config.code_length)
        self.context: AuthContext | None = None

    def bind(self, context: AuthContext) -> None:
        self.context = context

    def assert_bound(self) -> AuthContext:
        if self.context is None:
            raise RuntimeError("EmailOtpPlugin is not bound to an AuthContext")
        return self.context

    # --- Helpers --------------------------------------------------------

    def client_ip(self, request: Request) -> str | None:
        from fastauth.web.fastapi import client_ip

        return client_ip(request, self.assert_bound())

    async def require_session_user(self, request: Request) -> object:
        """Authenticated dependency. Returns the current ``User``."""
        from fastauth.web.fastapi import extract_session_token

        context = self.assert_bound()
        token = extract_session_token(request, context)
        if token is None:
            raise InvalidCredentialsError()
        session_context = await context.session_strategy.read(token)
        if session_context is None:
            raise InvalidCredentialsError()
        return session_context.user

    # --- Endpoint handlers ---------------------------------------------

    async def send_otp_handler(
        self,
        body: SendOtpRequest,
        request: Request,
    ) -> EmptyResponse:
        return await send_otp(
            self.assert_bound(),
            body,
            config=self.config,
            otp_service=self.otp_service,
            ip=self.client_ip(request),
            user_agent=request.headers.get("user-agent"),
        )

    async def check_otp_handler(self, body: CheckOtpRequest) -> EmptyResponse:
        return await check_otp(
            self.assert_bound(),
            body,
            config=self.config,
            otp_service=self.otp_service,
        )

    async def sign_in_handler(
        self,
        body: SignInOtpRequest,
        request: Request,
        response: Response,
    ) -> SessionResponse:
        from fastauth.web.fastapi import set_session_cookie

        context = self.assert_bound()
        result, session_context = await sign_in_with_otp(
            context,
            body,
            config=self.config,
            otp_service=self.otp_service,
            ip=self.client_ip(request),
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

    async def verify_email_handler(
        self,
        body: VerifyEmailOtpRequest,
        request: Request,
    ) -> EmptyResponse:
        return await verify_email_with_otp(
            self.assert_bound(),
            body,
            config=self.config,
            otp_service=self.otp_service,
            ip=self.client_ip(request),
            user_agent=request.headers.get("user-agent"),
        )

    async def request_password_reset_handler(
        self,
        body: RequestPasswordResetOtpRequest,
        request: Request,
    ) -> EmptyResponse:
        return await request_password_reset_otp(
            self.assert_bound(),
            body,
            config=self.config,
            otp_service=self.otp_service,
            ip=self.client_ip(request),
            user_agent=request.headers.get("user-agent"),
        )

    async def reset_password_handler(
        self,
        body: ResetPasswordOtpRequest,
        request: Request,
    ) -> EmptyResponse:
        return await reset_password_with_otp(
            self.assert_bound(),
            body,
            config=self.config,
            otp_service=self.otp_service,
            ip=self.client_ip(request),
            user_agent=request.headers.get("user-agent"),
        )

    async def request_email_change_handler(
        self,
        body: RequestEmailChangeOtpRequest,
        request: Request,
    ) -> EmptyResponse:
        from fastauth.domain.models import User

        context = self.assert_bound()
        user_obj = await self.require_session_user(request)
        assert isinstance(user_obj, User)  # pyright narrowing
        return await request_email_change_otp(
            context,
            user_obj,
            body,
            auth_config=context.config,
            config=self.config,
            otp_service=self.otp_service,
            ip=self.client_ip(request),
            user_agent=request.headers.get("user-agent"),
        )

    async def change_email_handler(
        self,
        body: ChangeEmailOtpRequest,
        request: Request,
    ) -> EmptyResponse:
        from fastauth.domain.models import User

        user_obj = await self.require_session_user(request)
        assert isinstance(user_obj, User)
        return await change_email_with_otp(
            self.assert_bound(),
            user_obj,
            body,
            config=self.config,
            otp_service=self.otp_service,
            ip=self.client_ip(request),
            user_agent=request.headers.get("user-agent"),
        )

    # --- Plugin spec ----------------------------------------------------

    def endpoints(self) -> Sequence[EndpointSpec]:
        specs: list[EndpointSpec] = [
            EndpointSpec(
                method="POST",
                path="/email-otp/send-verification-otp",
                name="email_otp_send",
                tags=["EmailOTP"],
                handler=self.send_otp_handler,
                response_model=EmptyResponse,
            ),
            EndpointSpec(
                method="POST",
                path="/email-otp/check-verification-otp",
                name="email_otp_check",
                tags=["EmailOTP"],
                handler=self.check_otp_handler,
                response_model=EmptyResponse,
            ),
            EndpointSpec(
                method="POST",
                path="/sign-in/email-otp",
                name="email_otp_sign_in",
                tags=["EmailOTP"],
                handler=self.sign_in_handler,
                response_model=SessionResponse,
            ),
            EndpointSpec(
                method="POST",
                path="/email-otp/verify-email",
                name="email_otp_verify_email",
                tags=["EmailOTP"],
                handler=self.verify_email_handler,
                response_model=EmptyResponse,
            ),
            EndpointSpec(
                method="POST",
                path="/email-otp/request-password-reset",
                name="email_otp_request_password_reset",
                tags=["EmailOTP"],
                handler=self.request_password_reset_handler,
                response_model=EmptyResponse,
            ),
            EndpointSpec(
                method="POST",
                path="/email-otp/reset-password",
                name="email_otp_reset_password",
                tags=["EmailOTP"],
                handler=self.reset_password_handler,
                response_model=EmptyResponse,
            ),
        ]
        if self.config.email_change.enabled:
            specs.extend(
                [
                    EndpointSpec(
                        method="POST",
                        path="/email-otp/request-email-change",
                        name="email_otp_request_email_change",
                        tags=["EmailOTP"],
                        handler=self.request_email_change_handler,
                        response_model=EmptyResponse,
                    ),
                    EndpointSpec(
                        method="POST",
                        path="/email-otp/change-email",
                        name="email_otp_change_email",
                        tags=["EmailOTP"],
                        handler=self.change_email_handler,
                        response_model=EmptyResponse,
                    ),
                ],
            )
        return specs

    def rate_limit_rules(self) -> Sequence[RateLimitRule]:
        # Send-OTP and request-password-reset are externally pokeable; tighter
        # bucket prevents abuse. Sign-in / verify-email / reset-password rely
        # on the per-OTP attempt cap PLUS the global lockout, so the per-IP
        # rate limit can be looser.
        return [
            RateLimitRule(
                path="/email-otp/send-verification-otp",
                window=timedelta(seconds=60),
                max_requests=3,
            ),
            RateLimitRule(
                path="/email-otp/request-password-reset",
                window=timedelta(seconds=60),
                max_requests=3,
            ),
            RateLimitRule(
                path="/email-otp/check-verification-otp",
                window=timedelta(seconds=60),
                max_requests=10,
            ),
            RateLimitRule(
                path="/sign-in/email-otp",
                window=timedelta(seconds=60),
                max_requests=10,
            ),
            RateLimitRule(
                path="/email-otp/verify-email",
                window=timedelta(seconds=60),
                max_requests=10,
            ),
            RateLimitRule(
                path="/email-otp/reset-password",
                window=timedelta(seconds=60),
                max_requests=10,
            ),
        ]
