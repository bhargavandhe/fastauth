"""Base URL and callback URL validation helpers."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from fastapi import Request
from pydantic import AnyHttpUrl, TypeAdapter, ValidationError

from fastauth.exceptions import ConfigError, InvalidRequestError
from fastauth.options import DynamicBaseUrlOptions
from fastauth.runtime.context import AuthContext
from fastauth.web.csrf import is_trusted_origin, matches_origin

__all__ = [
    "build_callback_url",
    "resolve_configured_base_url",
    "resolve_request_base_url",
    "trusted_callback_origins",
    "validate_callback_url",
]

HTTP_URL_ADAPTER = TypeAdapter(AnyHttpUrl)


def strip_trailing_slash(value: AnyHttpUrl | str) -> str:
    return str(value).rstrip("/")


def clean_host(value: str | None) -> str | None:
    if value is None:
        return None
    candidate = value.split(",", 1)[0].strip().strip('"').lower()
    if (
        not candidate
        or "://" in candidate
        or "/" in candidate
        or "\\" in candidate
        or "@" in candidate
    ):
        return None
    return candidate


def direct_client_is_trusted(request: Request, context: AuthContext) -> bool:
    if not context.config.proxy.trusted_proxies or request.client is None:
        return False
    try:
        direct_ip = ipaddress.ip_address(request.client.host)
    except ValueError:
        return False
    return any(direct_ip in network for network in context.config.proxy.trusted_proxies)


def forwarded_parameter(header_value: str, name: str) -> str | None:
    for entry in header_value.split(","):
        for parameter in entry.split(";"):
            key, separator, raw_value = parameter.partition("=")
            if separator and key.strip().lower() == name:
                return raw_value.strip().strip('"')
    return None


def forwarded_host(request: Request, context: AuthContext) -> str | None:
    if not direct_client_is_trusted(request, context):
        return None
    if context.config.proxy.forwarded_header is None:
        return None
    host = clean_host(request.headers.get("x-forwarded-host"))
    if host is not None:
        return host
    forwarded = request.headers.get("forwarded")
    if forwarded is None:
        return None
    return clean_host(forwarded_parameter(forwarded, "host"))


def host_allowed(host: str, config: DynamicBaseUrlOptions) -> bool:
    return any(matches_origin(host, pattern) for pattern in config.allowed_hosts)


def resolve_configured_base_url(base_url: AnyHttpUrl | DynamicBaseUrlOptions) -> str:
    """Resolve a configured base URL without request context."""

    if isinstance(base_url, DynamicBaseUrlOptions):
        if base_url.fallback is None:
            raise ConfigError(message="dynamic base_url requires fallback outside request context")
        return strip_trailing_slash(base_url.fallback)
    return strip_trailing_slash(base_url)


def resolve_request_base_url(request: Request, context: AuthContext) -> str:
    """Resolve the base URL for a single request."""

    base_url = context.config.app.base_url
    if not isinstance(base_url, DynamicBaseUrlOptions):
        return strip_trailing_slash(base_url)

    host = forwarded_host(request, context) or clean_host(request.headers.get("host"))
    if host is not None and host_allowed(host, base_url):
        return f"{base_url.protocol}://{host}"

    if base_url.fallback is not None:
        return strip_trailing_slash(base_url.fallback)

    raise InvalidRequestError(message="request host is not allowed")


def trusted_callback_origins(
    context: AuthContext,
    *,
    base_url: str | None = None,
) -> tuple[str, ...]:
    """Return origins trusted for callback and redirect URL validation."""

    trusted: list[str] = [
        *context.config.csrf.trusted_origins,
        *context.plugins.all_trusted_origins(),
    ]
    if base_url is not None:
        parsed = urlparse(base_url)
        if parsed.scheme and parsed.netloc:
            trusted.append(f"{parsed.scheme}://{parsed.netloc}")
    return tuple(trusted)


def validate_callback_url(
    value: object,
    *,
    trusted_origins: tuple[str, ...],
    allow_relative: bool,
    field_name: str,
) -> str | None:
    """Validate a user-supplied callback or redirect URL."""

    if value is None:
        return None
    if not isinstance(value, str):
        raise InvalidRequestError(message=f"{field_name} must be a string")

    candidate = value.strip()
    if not candidate:
        raise InvalidRequestError(message=f"{field_name} is not trusted")
    if candidate.startswith("/"):
        if candidate.startswith("//") or not allow_relative:
            raise InvalidRequestError(message=f"{field_name} is not trusted")
        return candidate

    try:
        HTTP_URL_ADAPTER.validate_python(candidate)
    except ValidationError as exc:
        raise InvalidRequestError(message=f"{field_name} is not a valid URL") from exc

    if trusted_origins and not is_trusted_origin(
        candidate,
        list(trusted_origins),
        allow_relative=False,
    ):
        raise InvalidRequestError(message=f"{field_name} is not trusted")
    return candidate


def build_callback_url(
    *,
    app_base_url: AnyHttpUrl | DynamicBaseUrlOptions | str,
    callback_path: str,
    override: AnyHttpUrl | str | None,
) -> str:
    if override is not None:
        return strip_trailing_slash(override)

    if isinstance(app_base_url, DynamicBaseUrlOptions):
        base_url = resolve_configured_base_url(app_base_url)
    else:
        base_url = strip_trailing_slash(app_base_url)
    return f"{base_url}/{callback_path.lstrip('/')}"
