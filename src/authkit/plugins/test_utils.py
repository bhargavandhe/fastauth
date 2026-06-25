"""TestUtilsPlugin: factories, login helpers, and OTP capture for tests.

The plugin contributes no HTTP endpoints. Tests retrieve the helper surface via
``auth.context.plugins.by_id["authkit-test-utils"].helpers``.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict

from authkit.domain.events import OtpGenerated
from authkit.domain.models import User
from authkit.plugins.base import EndpointSpec, Plugin
from authkit.runtime.context import AuthContext

__all__ = ["LoginResult", "TestHelpers", "TestUtilsConfig", "TestUtilsPlugin"]


class TestUtilsConfig(BaseModel):
    """Static configuration for ``TestUtilsPlugin``."""

    model_config = ConfigDict(extra="forbid")
    capture_otp: bool = False


class LoginResult(BaseModel):
    """Result of ``TestHelpers.login`` — token, headers, and cookies prebuilt."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    user: User
    session: Any
    token: str
    headers: dict[str, str]
    cookies: list[dict[str, str]]


class TestHelpers:
    """In-memory test helper surface bound to a single ``AuthContext``."""

    def __init__(self, context: AuthContext) -> None:
        self.context = context
        self.otps: dict[str, str] = {}

    def create_user(self, **overrides: object) -> User:
        """Construct an unsaved ``User`` with sensible defaults plus overrides."""
        defaults: dict[str, Any] = {
            "email": "test@example.com",
            "name": "Test User",
            "email_verified": True,
        }
        defaults.update(overrides)
        return User(**defaults)

    async def save_user(self, user: User) -> User:
        """Persist a ``User`` through the bound ``DatabaseAdapter``."""
        return await self.context.adapter.create_user(user)

    async def delete_user(self, user_id: str) -> None:
        """Remove a ``User`` through the bound ``DatabaseAdapter``."""
        await self.context.adapter.delete_user(user_id)

    async def login(self, user_id: str) -> LoginResult:
        """Create a session for ``user_id`` and return prebuilt auth artefacts."""
        user = await self.context.adapter.get_user_by_id(user_id)
        if user is None:
            raise ValueError(f"user {user_id} not found")
        session_context = await self.context.session_strategy.create(
            user,
            ip=None,
            user_agent=None,
        )
        cookie_name = self.context.config.cookie.name
        cookie_value = self.context.signed_cookie.pack(session_context.token)
        return LoginResult(
            user=user,
            session=session_context.session,
            token=session_context.token,
            headers={"cookie": f"{cookie_name}={cookie_value}"},
            cookies=[
                {
                    "name": cookie_name,
                    "value": cookie_value,
                    "path": "/",
                },
            ],
        )

    async def get_auth_headers(self, user_id: str) -> dict[str, str]:
        """Shortcut returning only the ``headers`` from a fresh ``login`` call.

        **Rule exception — returns a plain ``dict[str, str]``:** HTTP headers
        are a dict by RFC 9110 §5 and every HTTP client library (httpx,
        requests, urllib) accepts them as ``dict[str, str]``. Wrapping in a
        Pydantic ``RootModel`` would add friction with zero gain. One of the
        four documented carve-outs in CONTRIBUTING.md (this is the only one
        that lives outside the JOSE/OpenAPI ecosystem).
        """
        result = await self.login(user_id)
        return result.headers

    def get_otp(self, identifier: str) -> str | None:
        """Return the plaintext OTP captured for ``identifier``, if any."""
        return self.otps.get(identifier)

    def clear_otps(self) -> None:
        """Drop every captured OTP."""
        self.otps.clear()

    async def record_otp(self, event: OtpGenerated) -> None:
        """``EventBus`` subscriber: store the plaintext OTP keyed by identifier."""
        self.otps[event.identifier] = event.plain


class TestUtilsPlugin(Plugin):
    """Plugin contributing the ``TestHelpers`` surface; adds no HTTP routes."""

    id: ClassVar[str] = "authkit-test-utils"

    def __init__(self, config: TestUtilsConfig | None = None) -> None:
        self.config = config or TestUtilsConfig()
        self.context: AuthContext | None = None
        self.helpers: TestHelpers | None = None

    def bind(self, context: AuthContext) -> None:
        """Attach the assembled ``AuthContext`` and instantiate the helpers."""
        self.context = context
        helpers = TestHelpers(context)
        self.helpers = helpers
        if self.config.capture_otp:
            context.event_bus.subscribe(OtpGenerated, helpers.record_otp)

    def endpoints(self) -> Sequence[EndpointSpec]:
        return []
