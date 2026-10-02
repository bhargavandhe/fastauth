"""Typed service namespaces shared with the first-party HTTP flows.

These are trusted server calls: no implicit network rate limit is applied. Use
``auth.actions`` at custom untrusted entry points. Methods taking a session token
resolve it through the configured session strategy, never trust a caller's ID.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, TypeVar

from pydantic import BaseModel, ConfigDict, Field, SecretStr

from fastauth.api.commands import RequestContext
from fastauth.api.responses import AuthenticationResponse
from fastauth.domain.enums import AuditEventType
from fastauth.exceptions import CsrfError, FeatureNotEnabledError, InvalidCredentialsError
from fastauth.flows import email_otp as otp_flows
from fastauth.flows.credentials import EmptyResponse
from fastauth.flows.email_otp import (
    ChangeEmailOtpRequest,
    CheckOtpRequest,
    EmailOtpPurpose,
    RequestEmailChangeOtpRequest,
    RequestPasswordResetOtpRequest,
    ResetPasswordOtpRequest,
    SendOtpRequest,
    SignInOtpRequest,
    VerifyEmailOtpRequest,
)
from fastauth.flows.verification import (
    SendVerificationEmailRequest,
    VerifyEmailRequest,
    send_verification_email,
    verify_email,
)
from fastauth.plugins.audit_logs import AuditLogsPlugin, AuditLogsResponse, audit_log_view
from fastauth.plugins.base import Plugin
from fastauth.plugins.email_otp import EmailOtpPlugin
from fastauth.plugins.email_password import require_email_password
from fastauth.runtime.context import AuthContext
from fastauth.security.sessions import SessionContext

if TYPE_CHECKING:
    from fastauth.plugins.jwt import JwtPlugin, TokenResponse
    from fastauth.security.jwt import JwksDocument

__all__ = [
    "AuditLogsApi",
    "AuditQuery",
    "ChangeEmailOtpRequest",
    "CheckOtpRequest",
    "EmailOtpApi",
    "EmailOtpPurpose",
    "JwtApi",
    "RequestEmailChangeOtpRequest",
    "RequestPasswordResetOtpRequest",
    "ResetPasswordOtpRequest",
    "SendOtpRequest",
    "SendVerificationEmailRequest",
    "SignInOtpRequest",
    "VerificationApi",
    "VerifyEmailOtpRequest",
    "VerifyEmailRequest",
]

ServicePluginT = TypeVar("ServicePluginT", bound=Plugin)


def service_plugin(context: AuthContext, plugin_type: type[ServicePluginT]) -> ServicePluginT:
    plugin = context.plugins.by_id.get(plugin_type.id)
    if not isinstance(plugin, plugin_type):
        raise FeatureNotEnabledError(feature=plugin_type.id)
    return plugin


async def service_session(context: AuthContext, token: SecretStr) -> SessionContext:
    session = await context.session_strategy.read(token.get_secret_value())
    if session is None:
        raise InvalidCredentialsError()
    return session


class VerificationApi:
    """Token-based email verification using the same flows and DTOs as HTTP."""

    def __init__(self, context: AuthContext) -> None:
        self.context = context

    async def send(
        self, request: SendVerificationEmailRequest, *, context: RequestContext | None = None
    ) -> EmptyResponse:
        require_email_password(self.context)
        metadata = context or RequestContext()
        return await send_verification_email(
            self.context, request, ip=metadata.ip_address, user_agent=metadata.user_agent
        )

    async def confirm(
        self, request: VerifyEmailRequest, *, context: RequestContext | None = None
    ) -> AuthenticationResponse:
        require_email_password(self.context)
        metadata = context or RequestContext()
        result, session = await verify_email(
            self.context, request, ip=metadata.ip_address, user_agent=metadata.user_agent
        )
        del session
        return result


class EmailOtpApi:
    """Email OTP sign-in, verification, recovery, and authenticated email changes."""

    def __init__(self, context: AuthContext) -> None:
        self.context = context

    async def send(
        self, request: SendOtpRequest, *, context: RequestContext | None = None
    ) -> EmptyResponse:
        plugin = service_plugin(self.context, EmailOtpPlugin)
        metadata = context or RequestContext()
        return await otp_flows.send_otp(
            self.context,
            request,
            config=plugin.options,
            otp_service=plugin.otp_service,
            ip=metadata.ip_address,
            user_agent=metadata.user_agent,
        )

    async def check(self, request: CheckOtpRequest) -> EmptyResponse:
        plugin = service_plugin(self.context, EmailOtpPlugin)
        return await otp_flows.check_otp(
            self.context, request, config=plugin.options, otp_service=plugin.otp_service
        )

    async def sign_in(
        self, request: SignInOtpRequest, *, context: RequestContext | None = None
    ) -> AuthenticationResponse:
        plugin = service_plugin(self.context, EmailOtpPlugin)
        metadata = context or RequestContext()
        result, session = await otp_flows.sign_in_with_otp(
            self.context,
            request,
            config=plugin.options,
            otp_service=plugin.otp_service,
            ip=metadata.ip_address,
            user_agent=metadata.user_agent,
        )
        del session
        return result

    async def verify_email(
        self, request: VerifyEmailOtpRequest, *, context: RequestContext | None = None
    ) -> EmptyResponse:
        plugin = service_plugin(self.context, EmailOtpPlugin)
        metadata = context or RequestContext()
        return await otp_flows.verify_email_with_otp(
            self.context,
            request,
            config=plugin.options,
            otp_service=plugin.otp_service,
            ip=metadata.ip_address,
            user_agent=metadata.user_agent,
        )

    async def request_password_reset(
        self, request: RequestPasswordResetOtpRequest, *, context: RequestContext | None = None
    ) -> EmptyResponse:
        plugin = service_plugin(self.context, EmailOtpPlugin)
        metadata = context or RequestContext()
        return await otp_flows.request_password_reset_otp(
            self.context,
            request,
            config=plugin.options,
            otp_service=plugin.otp_service,
            ip=metadata.ip_address,
            user_agent=metadata.user_agent,
        )

    async def reset_password(
        self, request: ResetPasswordOtpRequest, *, context: RequestContext | None = None
    ) -> EmptyResponse:
        plugin = service_plugin(self.context, EmailOtpPlugin)
        metadata = context or RequestContext()
        return await otp_flows.reset_password_with_otp(
            self.context,
            request,
            config=plugin.options,
            otp_service=plugin.otp_service,
            ip=metadata.ip_address,
            user_agent=metadata.user_agent,
        )

    async def request_email_change(
        self,
        token: SecretStr,
        request: RequestEmailChangeOtpRequest,
        *,
        context: RequestContext | None = None,
    ) -> EmptyResponse:
        plugin = service_plugin(self.context, EmailOtpPlugin)
        if not plugin.options.email_change.enabled:
            raise FeatureNotEnabledError(feature="email-otp.email-change")
        session = await service_session(self.context, token)
        metadata = context or RequestContext()
        return await otp_flows.request_email_change_otp(
            self.context,
            session.user,
            request,
            auth_config=self.context.config,
            config=plugin.options,
            otp_service=plugin.otp_service,
            ip=metadata.ip_address,
            user_agent=metadata.user_agent,
        )

    async def change_email(
        self,
        token: SecretStr,
        request: ChangeEmailOtpRequest,
        *,
        context: RequestContext | None = None,
    ) -> EmptyResponse:
        plugin = service_plugin(self.context, EmailOtpPlugin)
        if not plugin.options.email_change.enabled:
            raise FeatureNotEnabledError(feature="email-otp.email-change")
        session = await service_session(self.context, token)
        metadata = context or RequestContext()
        return await otp_flows.change_email_with_otp(
            self.context,
            session.user,
            request,
            config=plugin.options,
            otp_service=plugin.otp_service,
            ip=metadata.ip_address,
            user_agent=metadata.user_agent,
        )


class JwtApi:
    """Exchange an authenticated session for a JWT; publish public keys."""

    def __init__(self, context: AuthContext) -> None:
        self.context = context

    def plugin(self) -> JwtPlugin:
        if "fastauth-jwt" not in self.context.plugins.by_id:
            raise FeatureNotEnabledError(feature="fastauth-jwt")
        from fastauth.plugins.jwt import JwtPlugin

        return service_plugin(self.context, JwtPlugin)

    async def issue(self, token: SecretStr) -> TokenResponse:
        plugin = self.plugin()
        from fastauth.plugins.jwt import TokenResponse

        session = await service_session(self.context, token)
        return TokenResponse(
            token=await plugin.issue_token_for(session.user, session=session.session)
        )

    async def jwks(self) -> JwksDocument:
        plugin = self.plugin()
        return await plugin.jwks_handler()


class AuditQuery(BaseModel):
    """Bounded, typed filters shared by user-scoped and admin audit queries."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    event_type: AuditEventType | None = None
    identifier: str | None = None
    limit: int = Field(default=50, ge=1, le=100)
    offset: int = Field(default=0, ge=0)


class AuditLogsApi:
    """Read session-owned events or explicitly allowlisted admin queries."""

    def __init__(self, context: AuthContext) -> None:
        self.context = context

    async def list(self, token: SecretStr, query: AuditQuery | None = None) -> AuditLogsResponse:
        plugin = service_plugin(self.context, AuditLogsPlugin)
        session = await service_session(self.context, token)
        return await self.query(plugin, query or AuditQuery(), user_id=session.user.id)

    async def list_all(
        self, token: SecretStr, query: AuditQuery | None = None, *, user_id: str | None = None
    ) -> AuditLogsResponse:
        plugin = service_plugin(self.context, AuditLogsPlugin)
        session = await service_session(self.context, token)
        if session.user.id not in plugin.options.admin_user_ids:
            raise CsrfError(message="admin access required")
        return await self.query(plugin, query or AuditQuery(), user_id=user_id)

    async def query(
        self, plugin: AuditLogsPlugin, query: AuditQuery, *, user_id: str | None
    ) -> AuditLogsResponse:
        """Trusted storage-level query; application authorization is required."""
        events, total = await plugin.assert_store().list_audit_logs(
            user_id=user_id,
            event_type=query.event_type,
            identifier=query.identifier,
            limit=query.limit,
            offset=query.offset,
        )
        return AuditLogsResponse(
            events=[audit_log_view(event) for event in events],
            total=total,
            limit=query.limit,
            offset=query.offset,
        )
