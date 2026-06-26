"""Glue between FastAuth's plugin/endpoint surface and FastAPI's APIRouter."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Coroutine
from typing import Any, cast

from fastapi import APIRouter, Depends, FastAPI, Request, Response
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pydantic.alias_generators import to_camel

from fastauth.domain.enums import WireFormat
from fastauth.domain.models import User
from fastauth.exceptions import (
    EXCEPTION_HTTP_STATUS,
    AccountLockedError,
    FastAuthError,
    RateLimitError,
)
from fastauth.flows.change_email import (
    ConfirmEmailChangeRequest,
    RequestEmailChangeRequest,
)
from fastauth.flows.change_password import ChangePasswordRequest
from fastauth.flows.credentials import (
    EmptyResponse,
    SessionResponse,
    SignInEmailRequest,
    SignInUsernameRequest,
    SignUpEmailRequest,
)
from fastauth.flows.password_reset import (
    ForgotPasswordRequest,
    ResetPasswordRequest,
)
from fastauth.flows.refresh import RefreshTokenRequest
from fastauth.flows.sessions import (
    ListSessionsResponse,
    RevokeSessionsResponse,
)
from fastauth.flows.user_management import (
    DeleteAccountConfirmRequest,
    DeleteAccountRequest,
    SetPasswordRequest,
    UpdateUserRequest,
    VerifyPasswordRequest,
    VerifyPasswordResponse,
)
from fastauth.flows.verification import (
    SendVerificationEmailRequest,
    VerifyEmailRequest,
)
from fastauth.runtime.api import AuthApi, HealthResponse
from fastauth.runtime.context import AuthContext
from fastauth.security.sessions import SessionContext
from fastauth.web.csrf import CsrfMiddleware
from fastauth.web.security_headers import SecurityHeadersMiddleware

__all__ = [
    "FastAuthRoute",
    "build_router",
    "clear_session_cookie",
    "client_ip",
    "extract_session_token",
    "http_status_for",
    "install_csrf",
    "install_security_headers",
    "rate_limit_dependency",
    "set_session_cookie",
]


def client_ip(request: Request, context: AuthContext) -> str | None:
    for header in context.config.advanced.ip_address_headers:
        value = request.headers.get(header)
        if value:
            return value.split(",")[0].strip()
    return request.client.host if request.client else None


def extract_session_token(request: Request, context: AuthContext) -> str | None:
    cookie_value = request.cookies.get(context.config.cookie.name)
    if cookie_value:
        unpacked = context.signed_cookie.unpack(cookie_value)
        if unpacked is not None:
            return unpacked
    authorization = request.headers.get("authorization")
    if authorization and authorization.lower().startswith("bearer "):
        return authorization.split(" ", 1)[1].strip()
    return None


async def require_session(request: Request, context: AuthContext) -> SessionContext:
    """Read the request's session or raise ``InvalidCredentialsError`` (HTTP 401).

    Shared by every authenticated endpoint that needs the current ``User`` +
    ``Session``. Keeps endpoint handlers free of the same 5-line boilerplate
    (extract_session_token → strategy.read → None-check → raise).
    """
    from fastauth.exceptions import InvalidCredentialsError

    token = extract_session_token(request, context)
    if token is None:
        raise InvalidCredentialsError()
    session_ctx = await context.session_strategy.read(token)
    if session_ctx is None:
        raise InvalidCredentialsError()
    return session_ctx


def set_session_cookie(
    response: Response,
    context: AuthContext,
    token: str,
    max_age: int,
) -> None:
    response.set_cookie(
        key=context.config.cookie.name,
        value=context.signed_cookie.pack(token),
        max_age=max_age,
        path=context.config.cookie.path,
        domain=context.config.cookie.domain,
        secure=context.config.cookie.secure,
        httponly=context.config.cookie.http_only,
        samesite=context.config.cookie.same_site,
    )


def clear_session_cookie(response: Response, context: AuthContext) -> None:
    response.delete_cookie(
        key=context.config.cookie.name,
        path=context.config.cookie.path,
        domain=context.config.cookie.domain,
    )


def http_status_for(exc: FastAuthError) -> int:
    # Walk the MRO so a subclass entry (e.g. DuplicateError -> 409) wins over
    # its base (AdapterError -> 500) regardless of dict iteration order.
    for cls in type(exc).mro():
        if cls in EXCEPTION_HTTP_STATUS:
            return EXCEPTION_HTTP_STATUS[cls]
    return 500


RAW_JSON_FIELD_NAMES = frozenset({"metadata", "permissions", "event_data", "eventData", "keys"})


def camelize_keys(value: object) -> object:
    """Recursively convert dict keys from ``snake_case`` to ``camelCase``.

    Lists are walked element-wise; primitives pass through unchanged. Known
    raw JSON containers keep their application/spec-defined inner keys.
    Each model in the response tree was already ``model_dump``-ed by FastAPI,
    so the input here is a plain dict tree.
    """
    if isinstance(value, dict):
        dict_value = cast("dict[object, object]", value)
        converted: dict[str, object] = {}
        for key, inner in dict_value.items():
            key_text = str(key)
            converted[to_camel(key_text)] = (
                inner if key_text in RAW_JSON_FIELD_NAMES else camelize_keys(inner)
            )
        return converted
    if isinstance(value, list):
        return [camelize_keys(item) for item in value]  # type: ignore[arg-type]
    return value


class CamelJSONResponse(JSONResponse):
    """JSON response that converts dict keys to ``camelCase`` on render.

    Used as the router-wide ``default_response_class`` when
    ``FastAuthConfig.wire_format`` is :class:`WireFormat.CAMEL`. SNAKE
    deployments use FastAPI's stock ``JSONResponse`` and skip the walk.
    """

    def render(self, content: object) -> bytes:
        return super().render(camelize_keys(content))


class FastAuthRoute(APIRoute):
    """Custom route class that converts ``FastAuthError`` into a JSON response.

    ``APIRouter`` has no ``exception_handler`` decorator (those live on
    ``FastAPI`` apps), so we wrap each route's handler instead. This keeps the
    router self-contained — callers can ``app.include_router(auth.router)``
    without registering anything else.
    """

    def get_route_handler(self) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        original = super().get_route_handler()

        async def custom_route_handler(request: Request) -> Response:
            try:
                return await original(request)
            except FastAuthError as exc:
                headers: dict[str, str] = {}
                if isinstance(exc, RateLimitError):
                    headers["X-Retry-After"] = str(exc.retry_after_seconds)
                if isinstance(exc, AccountLockedError):
                    headers["Retry-After"] = str(exc.retry_after_seconds)
                return JSONResponse(
                    status_code=http_status_for(exc),
                    content={"code": exc.code, "message": exc.message},
                    headers=headers,
                )

        return custom_route_handler


def rate_limit_dependency(
    context: AuthContext,
) -> Callable[[Request], Awaitable[None]]:
    """Return an async FastAPI dependency that enforces the rate limit."""

    async def dependency(request: Request) -> None:
        path = request.url.path.removeprefix(context.config.app.base_path)
        await context.rate_limiter.check(path, client_ip(request, context))

    return dependency


def build_router(context: AuthContext, api: AuthApi) -> APIRouter:
    """Build the fastauth ``APIRouter`` with health + credentials flow endpoints."""
    use_camel = context.config.wire_format is WireFormat.CAMEL
    response_class: type[JSONResponse] = CamelJSONResponse if use_camel else JSONResponse
    router = APIRouter(
        prefix=context.config.app.base_path,
        tags=["fastauth"],
        route_class=FastAuthRoute,
        dependencies=[Depends(rate_limit_dependency(context))],
        default_response_class=response_class,
    )

    @router.get(
        "/health",
        name="fastauth_health",
        response_model=HealthResponse,
        response_model_by_alias=False,
    )
    async def health_handler() -> HealthResponse:  # pyright: ignore[reportUnusedFunction]
        return await api.health()

    @router.post(
        "/sign-up/email",
        name="sign_up_email",
        response_model=SessionResponse,
        response_model_by_alias=False,
    )
    async def sign_up_email_handler(  # pyright: ignore[reportUnusedFunction]
        body: SignUpEmailRequest,
        request: Request,
        response: Response,
    ) -> SessionResponse:
        result, session_context = await api.sign_up_email(
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

    @router.post(
        "/sign-in/email",
        name="sign_in_email",
        response_model=SessionResponse,
        response_model_by_alias=False,
    )
    async def sign_in_email_handler(  # pyright: ignore[reportUnusedFunction]
        body: SignInEmailRequest,
        request: Request,
        response: Response,
    ) -> SessionResponse:
        result, session_context = await api.sign_in_email(
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

    @router.post(
        "/sign-in/username",
        name="sign_in_username",
        response_model=SessionResponse,
        response_model_by_alias=False,
    )
    async def sign_in_username_handler(  # pyright: ignore[reportUnusedFunction]
        body: SignInUsernameRequest,
        request: Request,
        response: Response,
    ) -> SessionResponse:
        result, session_context = await api.sign_in_username(
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

    @router.post(
        "/refresh",
        name="refresh_session",
        response_model=SessionResponse,
        response_model_by_alias=False,
    )
    async def refresh_session_handler(  # pyright: ignore[reportUnusedFunction]
        body: RefreshTokenRequest,
        request: Request,
        response: Response,
    ) -> SessionResponse:
        result, session_context = await api.refresh_session(
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

    @router.post(
        "/sign-out", name="sign_out", response_model=EmptyResponse, response_model_by_alias=False
    )
    async def sign_out_handler(  # pyright: ignore[reportUnusedFunction]
        request: Request,
        response: Response,
    ) -> EmptyResponse:
        token = extract_session_token(request, context)
        await api.sign_out(token)
        clear_session_cookie(response, context)
        return EmptyResponse(success=True)

    @router.get("/get-session", name="get_session")
    async def get_session_handler(  # pyright: ignore[reportUnusedFunction]
        request: Request,
    ) -> Response:
        token = extract_session_token(request, context)
        session_response = await api.get_session(token)
        if session_response is None:
            return Response(status_code=204)
        response = response_class(content=session_response.model_dump(mode="json"))
        for plugin in context.plugins.plugins:
            await plugin.extend_session_response(session_response.user, response)
        return response

    @router.post(
        "/send-verification-email",
        name="send_verification_email",
        response_model=EmptyResponse,
        response_model_by_alias=False,
    )
    async def send_verification_email_handler(  # pyright: ignore[reportUnusedFunction]
        body: SendVerificationEmailRequest,
        request: Request,
    ) -> EmptyResponse:
        return await api.send_verification_email(
            body,
            ip=client_ip(request, context),
            user_agent=request.headers.get("user-agent"),
        )

    @router.post(
        "/verify-email",
        name="verify_email",
        response_model=SessionResponse,
        response_model_by_alias=False,
    )
    async def verify_email_handler(  # pyright: ignore[reportUnusedFunction]
        body: VerifyEmailRequest,
        request: Request,
        response: Response,
    ) -> SessionResponse:
        result, session_context = await api.verify_email(
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

    @router.post(
        "/forgot-password",
        name="forgot_password",
        response_model=EmptyResponse,
        response_model_by_alias=False,
    )
    async def forgot_password_handler(  # pyright: ignore[reportUnusedFunction]
        body: ForgotPasswordRequest,
        request: Request,
    ) -> EmptyResponse:
        return await api.forgot_password(
            body,
            ip=client_ip(request, context),
            user_agent=request.headers.get("user-agent"),
        )

    @router.post(
        "/reset-password",
        name="reset_password",
        response_model=EmptyResponse,
        response_model_by_alias=False,
    )
    async def reset_password_handler(  # pyright: ignore[reportUnusedFunction]
        body: ResetPasswordRequest,
        request: Request,
    ) -> EmptyResponse:
        return await api.reset_password(
            body,
            ip=client_ip(request, context),
            user_agent=request.headers.get("user-agent"),
        )

    @router.post(
        "/change-password",
        name="change_password",
        response_model=EmptyResponse,
        response_model_by_alias=False,
    )
    async def change_password_handler(  # pyright: ignore[reportUnusedFunction]
        body: ChangePasswordRequest,
        request: Request,
    ) -> EmptyResponse:
        session_ctx = await require_session(request, context)
        return await api.change_password(
            session_ctx.user,
            current_session_id=session_ctx.session.id,
            request=body,
            ip=client_ip(request, context),
            user_agent=request.headers.get("user-agent"),
        )

    @router.patch(
        "/user",
        name="update_user",
        response_model=User,
        response_model_by_alias=False,
    )
    async def update_user_handler(  # pyright: ignore[reportUnusedFunction]
        body: UpdateUserRequest,
        request: Request,
    ) -> User:
        session_ctx = await require_session(request, context)
        return await api.update_user(
            session_ctx.user,
            body,
            ip=client_ip(request, context),
            user_agent=request.headers.get("user-agent"),
        )

    @router.post(
        "/set-password",
        name="set_password",
        response_model=EmptyResponse,
        response_model_by_alias=False,
    )
    async def set_password_handler(  # pyright: ignore[reportUnusedFunction]
        body: SetPasswordRequest,
        request: Request,
    ) -> EmptyResponse:
        session_ctx = await require_session(request, context)
        return await api.set_password(
            session_ctx.user,
            current_session_id=session_ctx.session.id,
            request=body,
            ip=client_ip(request, context),
            user_agent=request.headers.get("user-agent"),
        )

    @router.post(
        "/verify-password",
        name="verify_password",
        response_model=VerifyPasswordResponse,
        response_model_by_alias=False,
    )
    async def verify_password_handler(  # pyright: ignore[reportUnusedFunction]
        body: VerifyPasswordRequest,
        request: Request,
    ) -> VerifyPasswordResponse:
        session_ctx = await require_session(request, context)
        return await api.verify_password(
            session_ctx.user,
            body,
            ip=client_ip(request, context),
            user_agent=request.headers.get("user-agent"),
        )

    @router.post(
        "/delete-account",
        name="delete_account_with_password",
        response_model=EmptyResponse,
        response_model_by_alias=False,
    )
    async def delete_account_with_password_handler(  # pyright: ignore[reportUnusedFunction]
        body: DeleteAccountRequest,
        request: Request,
        response: Response,
    ) -> EmptyResponse:
        session_ctx = await require_session(request, context)
        result = await api.delete_account_with_password(
            session_ctx.user,
            body,
            ip=client_ip(request, context),
            user_agent=request.headers.get("user-agent"),
        )
        clear_session_cookie(response, context)
        return result

    @router.post(
        "/delete-account/request",
        name="request_delete_account",
        response_model=EmptyResponse,
        response_model_by_alias=False,
    )
    async def request_delete_account_handler(  # pyright: ignore[reportUnusedFunction]
        request: Request,
    ) -> EmptyResponse:
        session_ctx = await require_session(request, context)
        return await api.request_delete_account(
            session_ctx.user,
            ip=client_ip(request, context),
            user_agent=request.headers.get("user-agent"),
        )

    @router.post(
        "/delete-account/confirm",
        name="confirm_delete_account",
        response_model=EmptyResponse,
        response_model_by_alias=False,
    )
    async def confirm_delete_account_handler(  # pyright: ignore[reportUnusedFunction]
        body: DeleteAccountConfirmRequest,
        request: Request,
        response: Response,
    ) -> EmptyResponse:
        session_ctx = await require_session(request, context)
        result = await api.confirm_delete_account(
            session_ctx.user,
            body,
            ip=client_ip(request, context),
            user_agent=request.headers.get("user-agent"),
        )
        clear_session_cookie(response, context)
        return result

    @router.post(
        "/change-email/request",
        name="request_email_change",
        response_model=EmptyResponse,
        response_model_by_alias=False,
    )
    async def request_email_change_handler(  # pyright: ignore[reportUnusedFunction]
        body: RequestEmailChangeRequest,
        request: Request,
    ) -> EmptyResponse:
        session_ctx = await require_session(request, context)
        return await api.request_email_change(
            session_ctx.user,
            body,
            ip=client_ip(request, context),
            user_agent=request.headers.get("user-agent"),
        )

    @router.post(
        "/change-email/confirm",
        name="confirm_email_change",
        response_model=EmptyResponse,
        response_model_by_alias=False,
    )
    async def confirm_email_change_handler(  # pyright: ignore[reportUnusedFunction]
        body: ConfirmEmailChangeRequest,
        request: Request,
    ) -> EmptyResponse:
        return await api.confirm_email_change(
            body,
            ip=client_ip(request, context),
            user_agent=request.headers.get("user-agent"),
        )

    @router.get(
        "/sessions",
        name="list_sessions",
        response_model=ListSessionsResponse,
        response_model_by_alias=False,
    )
    async def list_sessions_handler(  # pyright: ignore[reportUnusedFunction]
        request: Request,
    ) -> ListSessionsResponse:
        session_ctx = await require_session(request, context)
        return await api.list_sessions(
            session_ctx.user,
            current_session_id=session_ctx.session.id,
        )

    @router.delete(
        "/sessions/{session_id}",
        name="revoke_session",
        response_model=RevokeSessionsResponse,
        response_model_by_alias=False,
    )
    async def revoke_session_handler(  # pyright: ignore[reportUnusedFunction]
        session_id: str,
        request: Request,
    ) -> RevokeSessionsResponse:
        session_ctx = await require_session(request, context)
        return await api.revoke_session(session_ctx.user, session_id=session_id)

    @router.delete(
        "/sessions",
        name="revoke_other_sessions",
        response_model=RevokeSessionsResponse,
        response_model_by_alias=False,
    )
    async def revoke_other_sessions_handler(  # pyright: ignore[reportUnusedFunction]
        request: Request,
    ) -> RevokeSessionsResponse:
        session_ctx = await require_session(request, context)
        return await api.revoke_other_sessions(
            session_ctx.user,
            current_session_id=session_ctx.session.id,
        )

    # Plugin endpoints (Tasks 19+) appended after the core endpoints so the
    # router's path order is preserved.
    for spec in context.plugins.all_endpoints():
        if spec.handler is None:
            continue
        router.add_api_route(
            path=spec.path,
            endpoint=spec.handler,
            methods=[spec.method],
            name=spec.name,
            tags=list(spec.tags),
            response_model=spec.response_model,
            response_model_by_alias=False,
            response_class=response_class,
        )
    return router


def install_csrf(app: FastAPI, context: AuthContext) -> None:
    """Install ``CsrfMiddleware`` on a host FastAPI app that mounts the router.

    Use this when integrating fastauth via ``app.include_router(auth.router)``
    on your own ``FastAPI`` application. ``FastAuth.as_asgi()`` already installs
    the middleware on the standalone app it returns.
    """
    app.add_middleware(
        CsrfMiddleware,
        config=context.config.csrf,
        additional_trusted_origins=context.plugins.all_trusted_origins(),
        cookie_name=context.config.cookie.name,
    )


def install_security_headers(app: FastAPI, context: AuthContext) -> None:
    """Install ``SecurityHeadersMiddleware`` on a host FastAPI app.

    Adds HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and
    optionally Permissions-Policy + Content-Security-Policy headers to every
    response. ``FastAuth.as_asgi()`` already installs this on the standalone
    app it returns; call ``install_security_headers`` from your own app code
    when integrating via ``app.include_router(auth.router)``.
    """
    app.add_middleware(
        SecurityHeadersMiddleware,
        config=context.config.security_headers,
    )
