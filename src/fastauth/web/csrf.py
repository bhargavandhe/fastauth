"""CSRF middleware and trusted-origin helper.

This middleware blocks cross-origin state-changing requests (POST/PUT/PATCH/
DELETE) by validating the ``Origin`` header (falling back to ``Referer``) against
a configured list of trusted origins. Bearer-token requests bypass the check
because the browser-based CSRF threat model only applies to ambient credentials
(i.e. cookies), and the actual auth check happens inside the endpoint via
``extract_session_token``.
"""

from __future__ import annotations

from urllib.parse import urlparse

from starlette.types import ASGIApp, Receive, Scope, Send

from fastauth.options import CsrfOptions

__all__ = ["SAFE_METHODS", "CsrfMiddleware", "is_trusted_origin", "matches_origin"]


SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def matches_origin(actual_host: str, pattern_host: str) -> bool:
    """Match an actual host against a pattern host.

    Patterns may use a leading ``*.`` wildcard. ``*.app.test`` matches
    ``api.app.test`` but NOT ``app.test`` itself.
    """
    if pattern_host == actual_host:
        return True
    if pattern_host.startswith("*."):
        suffix = pattern_host[1:]  # ".app.test"
        bare = suffix.lstrip(".")  # "app.test"
        return actual_host.endswith(suffix) and actual_host != bare
    return False


def is_trusted_origin(url: str, trusted: list[str], *, allow_relative: bool) -> bool:
    """Return ``True`` when ``url`` matches any entry in ``trusted``.

    Relative paths (starting with ``/``) are allowed iff ``allow_relative`` is
    set. Absolute URLs are matched on ``scheme + netloc`` only; the netloc
    portion of each trusted entry may use ``*.`` wildcards.
    """
    if url.startswith("/"):
        return allow_relative
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return False
    for pattern in trusted:
        parsed_pattern = urlparse(pattern)
        if parsed_pattern.scheme != parsed.scheme:
            continue
        if matches_origin(parsed.netloc, parsed_pattern.netloc):
            return True
    return False


class CsrfMiddleware:
    """ASGI middleware enforcing trusted-origin policy for unsafe methods."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        config: CsrfOptions,
        additional_trusted_origins: list[str],
        cookie_name: str,
    ) -> None:
        self.app = app
        self.config = config
        self.cookie_name = cookie_name
        self.trusted: list[str] = [*config.trusted_origins, *additional_trusted_origins]

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if not self.config.enabled or scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method = str(scope.get("method", "GET")).upper()
        if method in SAFE_METHODS:
            await self.app(scope, receive, send)
            return

        raw_headers: list[tuple[bytes, bytes]] = list(scope.get("headers", []))
        headers: dict[str, str] = {
            name.decode("latin-1").lower(): value.decode("latin-1") for name, value in raw_headers
        }

        # Bearer-only requests bypass CSRF: a request that carries the session
        # via the Authorization header (and not via the session cookie) cannot
        # be the target of a browser-driven CSRF attack, because such an attack
        # depends on ambient cookies. The endpoint itself enforces auth via
        # extract_session_token.
        authorization = headers.get("authorization", "")
        cookie_header = headers.get("cookie", "")
        has_session_cookie = self.cookie_name in cookie_header
        is_bearer_only = not has_session_cookie and authorization.lower().startswith("bearer ")
        if is_bearer_only:
            await self.app(scope, receive, send)
            return

        origin = headers.get("origin") or headers.get("referer", "")
        if not origin and not self.config.require_origin:
            await self.app(scope, receive, send)
            return
        if origin and is_trusted_origin(
            origin,
            self.trusted,
            allow_relative=self.config.allow_relative_paths,
        ):
            await self.app(scope, receive, send)
            return

        body = b'{"code":"CSRF_FORBIDDEN","message":"origin not trusted"}'
        await send(
            {
                "type": "http.response.start",
                "status": 403,
                "headers": [(b"content-type", b"application/json")],
            },
        )
        await send({"type": "http.response.body", "body": body})
