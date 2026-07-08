"""Public manager namespace exports.

The concrete manager implementations live in focused modules. This module
keeps the stable ``fastauth.runtime.managers`` import path for SDK users.
"""

from __future__ import annotations

from fastauth.runtime.dependency_managers import DependsManager, PluginsManager
from fastauth.runtime.inspection import AuthInspection, AuthInspector, RouteInfo
from fastauth.runtime.manager_inputs import (
    SessionIdInput,
    UserIdInput,
    to_session_id,
    to_user_id,
)
from fastauth.runtime.routes import AuthRoutes, RouteRef, SessionRoutes, SignInRoutes, SignUpRoutes
from fastauth.runtime.sdk_managers import (
    EmailChangesManager,
    PasswordsManager,
    SessionsManager,
    SignInManager,
    SignUpManager,
    UsersManager,
)

__all__ = [
    "AuthInspection",
    "AuthInspector",
    "AuthRoutes",
    "DependsManager",
    "EmailChangesManager",
    "PasswordsManager",
    "PluginsManager",
    "RouteInfo",
    "RouteRef",
    "SessionIdInput",
    "SessionRoutes",
    "SessionsManager",
    "SignInManager",
    "SignInRoutes",
    "SignUpManager",
    "SignUpRoutes",
    "UserIdInput",
    "UsersManager",
    "to_session_id",
    "to_user_id",
]
