"""Email/password first-party auth provider plugin."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, ClassVar

from fastauth.plugins.base import Capability, EndpointSpec, Plugin, PluginOptions

if TYPE_CHECKING:
    from fastauth.runtime.context import AuthContext

__all__ = [
    "EmailPasswordOptions",
    "EmailPasswordPlugin",
    "email_password_options",
    "require_email_password",
    "require_username_sign_in",
]


class EmailPasswordOptions(PluginOptions):
    """Static options for the email/password provider."""

    allow_username_sign_in: bool = True
    allow_bearer_tokens: bool = True


class EmailPasswordPlugin(Plugin):
    """Enable built-in email/password routes."""

    id: ClassVar[str] = "fastauth-email-password"

    def __init__(self, options: EmailPasswordOptions | None = None) -> None:
        self.options = options or EmailPasswordOptions()

    def endpoints(self) -> Sequence[EndpointSpec]:
        from fastauth.plugins.email_password_routes import email_password_endpoints

        return email_password_endpoints(self)

    def capabilities(self) -> Sequence[Capability]:
        capabilities = [
            Capability(
                id="email-password",
                description="Email and password sign-up, sign-in, verification, and account flows.",
                plugin_id=self.id,
            )
        ]
        if self.options.allow_username_sign_in:
            capabilities.append(
                Capability(
                    id="username-sign-in",
                    description="Username-based sign-in through the email/password provider.",
                    plugin_id=self.id,
                )
            )
        if self.options.allow_bearer_tokens:
            capabilities.append(
                Capability(
                    id="email-password.bearer-tokens",
                    description="Bearer-token delivery for email/password authentication.",
                    plugin_id=self.id,
                )
            )
        return capabilities


def email_password_options(context: AuthContext) -> EmailPasswordOptions | None:
    for plugin in context.plugins.plugins:
        if isinstance(plugin, EmailPasswordPlugin):
            return plugin.options
    return None


def require_email_password(context: AuthContext) -> EmailPasswordPlugin:
    from fastauth.exceptions import FeatureNotEnabledError

    plugin = context.plugins.by_id.get(EmailPasswordPlugin.id)
    if not isinstance(plugin, EmailPasswordPlugin):
        raise FeatureNotEnabledError(feature="email-password")
    return plugin


def require_username_sign_in(context: AuthContext) -> EmailPasswordPlugin:
    from fastauth.exceptions import FeatureNotEnabledError

    plugin = require_email_password(context)
    if not plugin.options.allow_username_sign_in:
        raise FeatureNotEnabledError(feature="username-sign-in")
    return plugin
