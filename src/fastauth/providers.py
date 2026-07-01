"""First-party auth provider and plugin factories."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastauth.plugins.api_key import ApiKeyOptions, ApiKeyPlugin
    from fastauth.plugins.audit_logs import AuditLogsConfig, AuditLogsPlugin
    from fastauth.plugins.email_otp import EmailOtpOptions, EmailOtpPlugin
    from fastauth.plugins.email_password import EmailPasswordOptions, EmailPasswordPlugin
    from fastauth.plugins.jwt import JwtOptions, JwtPlugin, PayloadBuilder, SignerFactory
    from fastauth.plugins.openapi import OpenApiConfig, OpenApiPlugin
    from fastauth.plugins.test_utils import TestUtilsConfig, TestUtilsPlugin

__all__ = [
    "api_key",
    "audit_logs",
    "email_otp",
    "email_password",
    "jwt",
    "openapi",
    "test_utils",
]


def email_password(options: EmailPasswordOptions | None = None) -> EmailPasswordPlugin:
    from fastauth.plugins.email_password import EmailPasswordPlugin

    return EmailPasswordPlugin(options)


def api_key(options: ApiKeyOptions | None = None) -> ApiKeyPlugin:
    from fastauth.plugins.api_key import ApiKeyPlugin

    return ApiKeyPlugin(options)


def audit_logs(config: AuditLogsConfig | None = None) -> AuditLogsPlugin:
    from fastauth.plugins.audit_logs import AuditLogsPlugin

    return AuditLogsPlugin(config)


def email_otp(options: EmailOtpOptions | None = None) -> EmailOtpPlugin:
    from fastauth.plugins.email_otp import EmailOtpPlugin

    return EmailOtpPlugin(options)


def jwt(
    options: JwtOptions | None = None,
    *,
    payload_builder: PayloadBuilder | None = None,
    signer_factory: SignerFactory | None = None,
) -> JwtPlugin:
    from fastauth.plugins.jwt import JwtPlugin

    return JwtPlugin(
        options,
        payload_builder=payload_builder,
        signer_factory=signer_factory,
    )


def openapi(config: OpenApiConfig | None = None) -> OpenApiPlugin:
    from fastauth.plugins.openapi import OpenApiPlugin

    return OpenApiPlugin(config)


def test_utils(config: TestUtilsConfig | None = None) -> TestUtilsPlugin:
    from fastauth.plugins.test_utils import TestUtilsPlugin

    return TestUtilsPlugin(config)
