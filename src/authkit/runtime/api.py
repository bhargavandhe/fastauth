"""AuthApi — typed server-side callable surface (mirrors HTTP endpoints)."""

from __future__ import annotations

from typing import Any

from pydantic import ConfigDict

from authkit.domain.models import User, WireModel
from authkit.flows.change_email import (
    ConfirmEmailChangeRequest,
    RequestEmailChangeRequest,
)
from authkit.flows.change_email import (
    confirm_email_change as confirm_email_change_flow,
)
from authkit.flows.change_email import (
    request_email_change as request_email_change_flow,
)
from authkit.flows.change_password import ChangePasswordRequest
from authkit.flows.change_password import change_password as change_password_flow
from authkit.flows.credentials import (
    EmptyResponse,
    SessionResponse,
    SignInEmailRequest,
    SignInUsernameRequest,
    SignUpEmailRequest,
)
from authkit.flows.credentials import (
    get_session as get_session_flow,
)
from authkit.flows.credentials import (
    sign_in_email as sign_in_email_flow,
)
from authkit.flows.credentials import (
    sign_in_username as sign_in_username_flow,
)
from authkit.flows.credentials import (
    sign_out as sign_out_flow,
)
from authkit.flows.credentials import (
    sign_up_email as sign_up_email_flow,
)
from authkit.flows.password_reset import (
    ForgotPasswordRequest,
    ResetPasswordRequest,
)
from authkit.flows.password_reset import (
    forgot_password as forgot_password_flow,
)
from authkit.flows.password_reset import (
    reset_password as reset_password_flow,
)
from authkit.flows.refresh import RefreshTokenRequest
from authkit.flows.refresh import refresh_session as refresh_session_flow
from authkit.flows.sessions import (
    ListSessionsResponse,
    RevokeSessionsResponse,
)
from authkit.flows.sessions import (
    list_sessions_for_user as list_sessions_flow,
)
from authkit.flows.sessions import (
    revoke_other_sessions as revoke_other_sessions_flow,
)
from authkit.flows.sessions import (
    revoke_session as revoke_session_flow,
)
from authkit.flows.verification import (
    SendVerificationEmailRequest,
    VerifyEmailRequest,
)
from authkit.flows.verification import (
    send_verification_email as send_verification_email_flow,
)
from authkit.flows.verification import (
    verify_email as verify_email_flow,
)
from authkit.runtime.context import AuthContext
from authkit.security.sessions import SessionContext

__all__ = ["AuthApi", "HealthResponse"]


class HealthResponse(WireModel):
    """Response payload for ``GET /auth/health`` and ``AuthApi.health()``."""

    model_config = ConfigDict(extra="forbid")
    status: str
    name: str


class AuthApi:
    """Server-side callable surface. More methods are registered in later tasks."""

    def __init__(self, context: AuthContext) -> None:
        self.context = context

    async def health(self) -> HealthResponse:
        return HealthResponse(status="ok", name=self.context.config.app.name)

    async def sign_up_email(
        self,
        request: SignUpEmailRequest,
        *,
        ip: str | None,
        user_agent: str | None,
    ) -> tuple[SessionResponse, SessionContext]:
        return await sign_up_email_flow(self.context, request, ip=ip, user_agent=user_agent)

    async def sign_in_email(
        self,
        request: SignInEmailRequest,
        *,
        ip: str | None,
        user_agent: str | None,
    ) -> tuple[SessionResponse, SessionContext]:
        return await sign_in_email_flow(self.context, request, ip=ip, user_agent=user_agent)

    async def sign_in_username(
        self,
        request: SignInUsernameRequest,
        *,
        ip: str | None,
        user_agent: str | None,
    ) -> tuple[SessionResponse, SessionContext]:
        return await sign_in_username_flow(self.context, request, ip=ip, user_agent=user_agent)

    async def sign_out(self, token: str | None) -> EmptyResponse:
        return await sign_out_flow(self.context, token)

    async def get_session(self, token: str | None) -> SessionResponse | None:
        return await get_session_flow(self.context, token)

    async def send_verification_email(
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

    async def verify_email(
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

    async def forgot_password(
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

    async def reset_password(
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

    async def change_password(
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

    async def request_email_change(
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

    async def confirm_email_change(
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

    async def list_sessions(
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

    async def revoke_session(
        self,
        user: User,
        *,
        session_id: str,
    ) -> RevokeSessionsResponse:
        return await revoke_session_flow(self.context, user=user, session_id=session_id)

    async def revoke_other_sessions(
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

    async def refresh_session(
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

    async def generate_openapi_schema(self) -> dict[str, Any]:
        """Build the authkit OpenAPI 3.1 schema offline (no running ASGI server).

        Requires ``OpenApiPlugin`` to be installed. Constructs a throwaway
        ``FastAPI`` app, mounts the authkit router on it, and delegates to the
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

        from authkit.plugins.openapi import OpenApiPlugin
        from authkit.web.fastapi import build_router

        plugin = self.context.plugins.by_id.get("authkit-openapi")
        if not isinstance(plugin, OpenApiPlugin):
            raise RuntimeError("OpenApiPlugin is not installed")
        temp_app = FastAPI()
        temp_app.include_router(build_router(self.context, self))
        return plugin.render_schema(temp_app)
