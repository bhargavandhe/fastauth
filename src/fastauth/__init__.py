"""fastauth — a modular FastAPI authentication library."""

from __future__ import annotations

from fastauth.api.responses import AuthenticationResponse, SessionView, UserView
from fastauth.deprecations import FastAuthDeprecationWarning
from fastauth.domain.events import AuthEvent
from fastauth.domain.value_objects import ApiKeyId, RefreshTokenId, SessionId, UserId
from fastauth.options import FastAuthOptions, MaintenanceOptions, ProductionSafetyOptions
from fastauth.plugins.migrations import PluginMigrationMode
from fastauth.providers import (
    api_key,
    audit_logs,
    email_otp,
    email_password,
    jwt,
    openapi,
    test_utils,
)
from fastauth.runtime.auth import FastAuth
from fastauth.runtime.capabilities import (
    API_KEYS,
    AUDIT_LOGS,
    BEARER_TOKENS,
    CORE_REFRESH_TOKENS,
    CORE_SESSIONS,
    EMAIL_OTP,
    EMAIL_PASSWORD,
    JWT,
    OPENAPI_REFERENCE,
    TEST_UTILS,
    USERNAME_SIGN_IN,
    Capability,
    CapabilityId,
    CapabilityRegistry,
)
from fastauth.runtime.event_bus import EventBus
from fastauth.runtime.maintenance import MaintenanceError, MaintenanceFailure, MaintenanceResult
from fastauth.runtime.observability import (
    LoggingObservabilitySink,
    ObservabilityManager,
    ObservabilitySink,
    OperationalEvent,
    OperationalEventHandler,
    OperationalOutcome,
)

__all__ = [
    "API_KEYS",
    "AUDIT_LOGS",
    "BEARER_TOKENS",
    "CORE_REFRESH_TOKENS",
    "CORE_SESSIONS",
    "EMAIL_OTP",
    "EMAIL_PASSWORD",
    "JWT",
    "OPENAPI_REFERENCE",
    "TEST_UTILS",
    "USERNAME_SIGN_IN",
    "ApiKeyId",
    "AuthEvent",
    "AuthenticationResponse",
    "Capability",
    "CapabilityId",
    "CapabilityRegistry",
    "EventBus",
    "FastAuth",
    "FastAuthDeprecationWarning",
    "FastAuthOptions",
    "LoggingObservabilitySink",
    "MaintenanceError",
    "MaintenanceFailure",
    "MaintenanceOptions",
    "MaintenanceResult",
    "ObservabilityManager",
    "ObservabilitySink",
    "OperationalEvent",
    "OperationalEventHandler",
    "OperationalOutcome",
    "PluginMigrationMode",
    "ProductionSafetyOptions",
    "RefreshTokenId",
    "SessionId",
    "SessionView",
    "UserId",
    "UserView",
    "__version__",
    "api_key",
    "audit_logs",
    "email_otp",
    "email_password",
    "jwt",
    "openapi",
    "test_utils",
]
__version__ = "0.14.1"
