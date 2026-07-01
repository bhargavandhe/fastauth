"""AuthContext — immutable composition root assembled by FastAuth."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from fastauth.config import FastAuthConfig
from fastauth.messaging.email import EmailSender, TemplateRenderer
from fastauth.plugins.base import PluginRegistry
from fastauth.runtime.event_bus import EventBus
from fastauth.runtime.hooks import DatabaseHooks
from fastauth.security.passwords import PasswordHasher
from fastauth.security.sessions import SessionStrategy
from fastauth.security.tokens import SignedCookieValue, TokenService
from fastauth.storage.base import DatabaseAdapter

if TYPE_CHECKING:
    from fastauth.security.lockout import AccountLockoutTracker
    from fastauth.security.rate_limit import RateLimiter
    from fastauth.security.refresh_tokens import RefreshTokenService

__all__ = ["AuthContext"]


@dataclass(frozen=True, slots=True)
class AuthContext:
    """Frozen container holding every dependency assembled by ``FastAuth``."""

    config: FastAuthConfig
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
