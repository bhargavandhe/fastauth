"""Glue between FastAuth's plugin/endpoint surface and FastAPI's APIRouter."""

from __future__ import annotations

import ipaddress
from collections.abc import Awaitable, Callable, Coroutine
from ipaddress import IPv4Address, IPv6Address
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, Request, Response
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute

from fastauth.api.commands import CookieCredentialDelivery
from fastauth.api.responses import authentication_response
from fastauth.exceptions import (
    EXCEPTION_HTTP_STATUS,
    AccountLockedError,
    FastAuthError,
    RateLimitError,
)
from fastauth.flows.credentials import (
    EmptyResponse,
    SessionResponse,
)
from fastauth.flows.refresh import RefreshTokenRequest
from fastauth.flows.sessions import (
    ListSessionsResponse,
    RevokeSessionsResponse,
)
from fastauth.plugins.base import EndpointSpec
from fastauth.runtime.api import AuthApi, HealthResponse, RouterAuthApi
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

IpAddress = IPv4Address | IPv6Address


def parse_ip_address(value: str | None) -> IpAddress | None:
    if value is None:
        return None
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def clean_forwarded_for_value(value: str) -> str | None:
    candidate = value.strip().strip('"')
    if not candidate or candidate.lower() == "unknown":
        return None
    if candidate.startswith("["):
        end = candidate.find("]")
        if end == -1:
            return None
        return candidate[1:end]
    if candidate.count(":") == 1 and "." in candidate:
        return candidate.rsplit(":", 1)[0]
    return candidate


def forwarded_header_values(header_name: str, header_value: str) -> list[str]:
    if header_name.lower() != "forwarded":
        return [
            cleaned
            for part in header_value.split(",")
            if (cleaned := clean_forwarded_for_value(part)) is not None
        ]

    values: list[str] = []
    for entry in header_value.split(","):
        for parameter in entry.split(";"):
            name, separator, raw_value = parameter.partition("=")
            if separator and name.strip().lower() == "for":
                cleaned = clean_forwarded_for_value(raw_value)
                if cleaned is not None:
                    values.append(cleaned)
    return values


def is_trusted_proxy(ip_address_value: IpAddress, context: AuthContext) -> bool:
    return any(ip_address_value in network for network in context.config.proxy.trusted_proxies)


def resolve_client_ip(request: Request, context: AuthContext) -> IpAddress | None:
    direct_ip = parse_ip_address(request.client.host if request.client else None)
    if direct_ip is None:
        return None
    if not is_trusted_proxy(direct_ip, context):
        return direct_ip

    header_name = context.config.proxy.forwarded_header
    if header_name is None:
        return direct_ip
    header_value = request.headers.get(header_name)
    if not header_value:
        return direct_ip

    forwarded_ips = [
        parsed
        for value in forwarded_header_values(header_name, header_value)
        if (parsed := parse_ip_address(value)) is not None
    ]
    if not forwarded_ips:
        return direct_ip

    for candidate in reversed([*forwarded_ips, direct_ip]):
        if not is_trusted_proxy(candidate, context):
            return candidate
    return forwarded_ips[0]


def client_ip(request: Request, context: AuthContext) -> str | None:
    resolved = resolve_client_ip(request, context)
    return str(resolved) if resolved is not None else None


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


def prefixed_plugin_path(router: APIRouter, path: str) -> str:
    if not router.prefix:
        return path
    return f"{router.prefix}{path}"


def existing_route_keys(router: APIRouter) -> set[tuple[str, str]]:
    keys: set[tuple[str, str]] = set()
    for route in router.routes:
        if not isinstance(route, APIRoute):
            continue
        for method in route.methods or set():
            keys.add((method, route.path))
    return keys


def add_plugin_route(router: APIRouter, spec: EndpointSpec) -> None:
    if spec.handler is None:
        return
    route_key = (spec.method, prefixed_plugin_path(router, spec.path))
    if route_key in existing_route_keys(router):
        method, path = route_key
        raise ValueError(
            f"plugin endpoint {method} {spec.path} collides with existing auth route {path}",
        )
    router.add_api_route(
        path=spec.path,
        endpoint=spec.handler,
        methods=[spec.method],
        name=spec.name,
        tags=list(spec.tags),
        response_model=spec.response_model,
        response_class=JSONResponse,
    )
    for route in reversed(router.routes):
        if isinstance(route, APIRoute) and route.name == spec.name:
            route.fastauth_source = "plugin"  # type: ignore[attr-defined]
            break


def register_session_routes(router: APIRouter, context: AuthContext) -> None:
    internal_api = RouterAuthApi(context)

    @router.post(
        "/refresh",
        name="refresh_session",
        response_model=SessionResponse,
    )
    async def refresh_session_handler(  # pyright: ignore[reportUnusedFunction]
        body: RefreshTokenRequest,
        request: Request,
        response: Response,
    ) -> SessionResponse:
        result, session_context = await internal_api.internal_refresh_session(
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

    @router.post("/sign-out", name="sign_out", response_model=EmptyResponse)
    async def sign_out_handler(  # pyright: ignore[reportUnusedFunction]
        request: Request,
        response: Response,
    ) -> EmptyResponse:
        token = extract_session_token(request, context)
        await internal_api.internal_sign_out(token)
        clear_session_cookie(response, context)
        return EmptyResponse(success=True)

    @router.get("/get-session", name="get_session", response_model=SessionResponse)
    async def get_session_handler(  # pyright: ignore[reportUnusedFunction]
        request: Request,
        response: Response,
    ) -> SessionResponse | Response:
        token = extract_session_token(request, context)
        if token is None:
            return Response(status_code=204)
        session_context = await context.session_strategy.read(token)
        if session_context is None:
            return Response(status_code=204)
        session_response = authentication_response(
            user=session_context.user,
            session=session_context.session,
        )
        for plugin in context.plugins.plugins:
            await plugin.extend_session_response(session_context.user, response)
        return session_response

    @router.get(
        "/sessions",
        name="list_sessions",
        response_model=ListSessionsResponse,
    )
    async def list_sessions_handler(  # pyright: ignore[reportUnusedFunction]
        request: Request,
    ) -> ListSessionsResponse:
        session_ctx = await require_session(request, context)
        return await internal_api.internal_list_sessions(
            session_ctx.user,
            current_session_id=session_ctx.session.id,
        )

    @router.delete(
        "/sessions/{session_id}",
        name="revoke_session",
        response_model=RevokeSessionsResponse,
    )
    async def revoke_session_handler(  # pyright: ignore[reportUnusedFunction]
        session_id: str,
        request: Request,
    ) -> RevokeSessionsResponse:
        session_ctx = await require_session(request, context)
        return await internal_api.internal_revoke_session(session_ctx.user, session_id=session_id)

    @router.delete(
        "/sessions",
        name="revoke_other_sessions",
        response_model=RevokeSessionsResponse,
    )
    async def revoke_other_sessions_handler(  # pyright: ignore[reportUnusedFunction]
        request: Request,
    ) -> RevokeSessionsResponse:
        session_ctx = await require_session(request, context)
        return await internal_api.internal_revoke_other_sessions(
            session_ctx.user,
            current_session_id=session_ctx.session.id,
        )


def build_router(context: AuthContext, api: AuthApi) -> APIRouter:
    """Build the fastauth ``APIRouter`` with health + credentials flow endpoints."""
    router = APIRouter(
        prefix=context.config.app.base_path,
        tags=["fastauth"],
        route_class=FastAuthRoute,
        dependencies=[Depends(rate_limit_dependency(context))],
        default_response_class=JSONResponse,
    )

    @router.get(
        "/health",
        name="fastauth_health",
        response_model=HealthResponse,
    )
    async def health_handler() -> HealthResponse:  # pyright: ignore[reportUnusedFunction]
        return await api.health()

    register_session_routes(router, context)

    for spec in context.plugins.all_endpoints():
        if spec.handler is None:
            continue
        add_plugin_route(router, spec)
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
