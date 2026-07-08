from __future__ import annotations

from ipaddress import IPv4Network

import pytest
from fastapi import Request
from pydantic import SecretStr

from fastauth.exceptions import InvalidRequestError
from fastauth.options import AppOptions, CsrfOptions, FastAuthOptions, ProxyOptions
from fastauth.runtime.auth import FastAuth
from fastauth.web.callbacks import resolve_request_base_url, validate_callback_url


def request_with_client(
    *,
    host: str = "api.example.com",
    scheme: str = "http",
    client_host: str = "203.0.113.10",
    headers: list[tuple[bytes, bytes]] | None = None,
) -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "scheme": scheme,
            "headers": headers or [(b"host", host.encode("ascii"))],
            "client": (client_host, 12345),
        },
    )


def test_resolve_request_base_url_uses_allowed_request_host() -> None:
    auth = FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("a" * 64),
            app=AppOptions.model_validate(
                {
                    "base_url": {
                        "allowed_hosts": ("api.example.com",),
                        "fallback": "https://fallback.example.com",
                        "protocol": "https",
                    },
                },
            ),
        ),
    )

    resolved = resolve_request_base_url(request_with_client(host="api.example.com"), auth.context)

    assert resolved == "https://api.example.com"


def test_resolve_request_base_url_supports_allowed_wildcard_hosts() -> None:
    auth = FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("a" * 64),
            app=AppOptions.model_validate(
                {
                    "base_url": {
                        "allowed_hosts": ("*.tenant.example.com",),
                        "fallback": "https://fallback.example.com",
                        "protocol": "https",
                    },
                },
            ),
        ),
    )

    resolved = resolve_request_base_url(
        request_with_client(host="acme.tenant.example.com"),
        auth.context,
    )

    assert resolved == "https://acme.tenant.example.com"


def test_resolve_request_base_url_uses_fallback_for_untrusted_host() -> None:
    auth = FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("a" * 64),
            app=AppOptions.model_validate(
                {
                    "base_url": {
                        "allowed_hosts": ("api.example.com",),
                        "fallback": "https://fallback.example.com",
                    },
                },
            ),
        ),
    )

    resolved = resolve_request_base_url(request_with_client(host="evil.example"), auth.context)

    assert resolved == "https://fallback.example.com"


def test_resolve_request_base_url_uses_forwarded_host_only_from_trusted_proxy() -> None:
    auth = FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("a" * 64),
            app=AppOptions.model_validate(
                {
                    "base_url": {
                        "allowed_hosts": ("public.example.com",),
                        "fallback": "https://fallback.example.com",
                        "protocol": "https",
                    },
                },
            ),
            proxy=ProxyOptions(
                trusted_proxies=(IPv4Network("10.0.0.0/8"),),
                forwarded_header="x-forwarded-for",
            ),
        ),
    )
    request = request_with_client(
        host="internal.local",
        client_host="10.1.2.3",
        headers=[
            (b"host", b"internal.local"),
            (b"x-forwarded-host", b"public.example.com"),
            (b"x-forwarded-proto", b"https"),
            (b"x-forwarded-for", b"198.51.100.42"),
        ],
    )

    resolved = resolve_request_base_url(request, auth.context)

    assert resolved == "https://public.example.com"


@pytest.mark.parametrize("value", [123, {"url": "https://app.example.com"}])
def test_validate_callback_url_rejects_non_string_values(value: object) -> None:
    with pytest.raises(InvalidRequestError, match="redirect_url must be a string"):
        validate_callback_url(
            value,
            trusted_origins=("https://app.example.com",),
            allow_relative=False,
            field_name="redirect_url",
        )


def test_validate_callback_url_allows_relative_paths_only_when_configured() -> None:
    assert (
        validate_callback_url(
            "/welcome",
            trusted_origins=("https://app.example.com",),
            allow_relative=True,
            field_name="redirect_url",
        )
        == "/welcome"
    )
    with pytest.raises(InvalidRequestError, match="redirect_url is not trusted"):
        validate_callback_url(
            "/welcome",
            trusted_origins=("https://app.example.com",),
            allow_relative=False,
            field_name="redirect_url",
        )


def test_validate_callback_url_rejects_untrusted_absolute_origins() -> None:
    with pytest.raises(InvalidRequestError, match="redirect_url is not trusted"):
        validate_callback_url(
            "https://evil.example/welcome",
            trusted_origins=("https://app.example.com",),
            allow_relative=False,
            field_name="redirect_url",
        )


def test_validate_callback_url_allows_trusted_wildcard_origins() -> None:
    assert (
        validate_callback_url(
            "https://acme.app.example.com/welcome",
            trusted_origins=("https://*.app.example.com",),
            allow_relative=False,
            field_name="redirect_url",
        )
        == "https://acme.app.example.com/welcome"
    )


def test_validate_callback_url_uses_csrf_relative_policy_defaults() -> None:
    config = CsrfOptions(allow_relative_paths=False)

    with pytest.raises(InvalidRequestError, match="redirect_url is not trusted"):
        validate_callback_url(
            "/welcome",
            trusted_origins=("https://app.example.com",),
            allow_relative=config.allow_relative_paths,
            field_name="redirect_url",
        )
