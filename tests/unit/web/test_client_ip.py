from __future__ import annotations

from ipaddress import IPv4Network

from fastapi import Request
from pydantic import SecretStr

from fastauth.options import FastAuthOptions, ProxyOptions
from fastauth.runtime.auth import FastAuth
from fastauth.web.fastapi import client_ip


def request_with_client(
    *,
    client_host: str,
    headers: list[tuple[bytes, bytes]] | None = None,
) -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": headers or [],
            "client": (client_host, 12345),
        },
    )


def test_client_ip_ignores_forwarded_headers_by_default() -> None:
    auth = FastAuth(FastAuthOptions(secret_key=SecretStr("a" * 64)))
    request = request_with_client(
        client_host="203.0.113.10",
        headers=[(b"x-forwarded-for", b"198.51.100.99")],
    )

    assert client_ip(request, auth.context) == "203.0.113.10"


def test_client_ip_uses_configured_header_from_trusted_proxy() -> None:
    auth = FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("a" * 64),
            proxy=ProxyOptions(
                trusted_proxies=(IPv4Network("10.0.0.0/8"),),
                forwarded_header="x-forwarded-for",
            ),
        ),
    )
    request = request_with_client(
        client_host="10.1.2.3",
        headers=[(b"x-forwarded-for", b"198.51.100.42, 10.1.2.3")],
    )

    assert client_ip(request, auth.context) == "198.51.100.42"
