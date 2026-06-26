"""Response-header hardening middleware.

Adds a configurable set of security-relevant response headers to every
HTTP response. The default set matches the OWASP Secure Headers Project's
recommendation for a typical SaaS web application:

* ``Strict-Transport-Security`` (HSTS) — forces HTTPS for one year + every
  subdomain. Add ``; preload`` if your domain is enrolled in the preload list.
* ``X-Frame-Options: DENY`` — refuses being framed by any origin (clickjacking
  protection). Pair with a ``Content-Security-Policy: frame-ancestors`` directive
  for modern browsers.
* ``X-Content-Type-Options: nosniff`` — disables MIME-type sniffing.
* ``Referrer-Policy: strict-origin-when-cross-origin`` — sends the full URL as
  the Referer header for same-origin navigations but only the origin for
  cross-origin requests.
* ``Permissions-Policy`` (off by default — application-specific).
* ``Content-Security-Policy`` (off by default — application-specific).

Set any header field to ``None`` in :class:`SecurityHeadersConfig` to omit it.
"""

from __future__ import annotations

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from fastauth.config import SecurityHeadersConfig

__all__ = ["SecurityHeadersMiddleware"]


class SecurityHeadersMiddleware:
    """ASGI middleware that injects configured security headers on every response."""

    def __init__(self, app: ASGIApp, *, config: SecurityHeadersConfig) -> None:
        self.app = app
        self.config = config
        # Pre-compute the header bytes to avoid encoding on every request.
        self.header_bytes: list[tuple[bytes, bytes]] = []
        if config.hsts is not None:
            self.header_bytes.append(
                (b"strict-transport-security", config.hsts.encode("ascii")),
            )
        if config.x_frame_options is not None:
            self.header_bytes.append(
                (b"x-frame-options", config.x_frame_options.encode("ascii")),
            )
        if config.x_content_type_options is not None:
            self.header_bytes.append(
                (b"x-content-type-options", config.x_content_type_options.encode("ascii")),
            )
        if config.referrer_policy is not None:
            self.header_bytes.append(
                (b"referrer-policy", config.referrer_policy.encode("ascii")),
            )
        if config.permissions_policy is not None:
            self.header_bytes.append(
                (b"permissions-policy", config.permissions_policy.encode("ascii")),
            )
        if config.content_security_policy is not None:
            self.header_bytes.append(
                (b"content-security-policy", config.content_security_policy.encode("ascii")),
            )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if not self.config.enabled or scope["type"] != "http" or not self.header_bytes:
            await self.app(scope, receive, send)
            return

        async def wrapped_send(message: Message) -> None:
            if message["type"] == "http.response.start":
                # Append our headers. We don't overwrite any header the app
                # already set — that would clobber a route-specific CSP, for
                # example. The first occurrence wins per HTTP semantics.
                existing: list[tuple[bytes, bytes]] = list(message.get("headers", []))
                existing_names = {name.lower() for name, _value in existing}
                for name, value in self.header_bytes:
                    if name not in existing_names:
                        existing.append((name, value))
                message["headers"] = existing
            await send(message)

        await self.app(scope, receive, wrapped_send)
