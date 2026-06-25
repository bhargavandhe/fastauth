"""AuthContext — immutable composition root assembled by AuthKit."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict

from authkit.config import AuthKitConfig
from authkit.messaging.email import EmailSender, TemplateRenderer
from authkit.plugins.base import PluginRegistry
from authkit.runtime.event_bus import EventBus
from authkit.runtime.hooks import DatabaseHooks
from authkit.security.passwords import PasswordHasher
from authkit.security.sessions import SessionStrategy
from authkit.security.tokens import SignedCookieValue, TokenService
from authkit.storage.base import DatabaseAdapter

if TYPE_CHECKING:
    from authkit.security.lockout import AccountLockoutTracker
    from authkit.security.rate_limit import RateLimiter
    from authkit.security.refresh_tokens import RefreshTokenService

__all__ = ["AuthContext"]


class AuthContext(BaseModel):
    """Frozen container holding every dependency assembled by ``AuthKit``."""

    model_config = ConfigDict(arbitrary_types_allowed=True, frozen=True)

    config: AuthKitConfig
    adapter: DatabaseAdapter
    session_strategy: SessionStrategy
    password_hasher: PasswordHasher
    token_service: TokenService
    email_sender: EmailSender
    template_renderer: TemplateRenderer
    hooks: DatabaseHooks
    event_bus: EventBus
    plugins: PluginRegistry
    signed_cookie: SignedCookieValue
    rate_limiter: RateLimiter
    lockout_tracker: AccountLockoutTracker
    refresh_token_service: RefreshTokenService
