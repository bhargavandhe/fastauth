from __future__ import annotations

import importlib
import inspect

import httpx
import pytest
from fastapi import FastAPI
from pydantic import SecretStr, ValidationError

from fastauth import (
    AuthenticationResponse,
    FastAuth,
    FastAuthOptions,
    SessionId,
    SessionView,
    UserId,
    UserView,
    email_password,
    openapi,
)
from fastauth.api.commands import (
    ChangePasswordCommand,
    GetSessionCommand,
    ListSessionsCommand,
    RevokeSessionCommand,
    SessionPrincipal,
    SignInUsernameCommand,
    SignOutCommand,
    SignUpEmailCommand,
    UpdateUserCommand,
    UserPrincipal,
)
from fastauth.database import memory
from fastauth.exceptions import FeatureNotEnabledError, InvalidCredentialsError
from fastauth.messaging.email import EmailMessage
from fastauth.options import CookieOptions, CsrfOptions, RateLimitOptions
from fastauth.plugins.base import EndpointSpec, Plugin
from fastauth.plugins.email_password import EmailPasswordOptions


class FakeEmailSender:
    def __init__(self) -> None:
        self.message: EmailMessage | None = None

    async def send(self, message: EmailMessage) -> None:
        self.message = message


def test_fastauth_class_builds_auth_from_pydantic_options() -> None:
    auth = FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("a" * 64),
            database=memory(),
        ),
        plugins=[email_password()],
    )

    assert auth.options.database.kind == "memory"
    assert auth.router.prefix == ""


def test_fastauth_factory_accepts_dependency_overrides() -> None:
    sender = FakeEmailSender()

    auth = FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("a" * 64),
            database=memory(),
        ),
        plugins=[email_password()],
        email_sender=sender,
    )

    assert auth.context.email_sender is sender


def test_options_reject_old_adapter_style() -> None:
    with pytest.raises(ValidationError):
        FastAuthOptions.model_validate(
            {
                "secret_key": "a" * 64,
                "adapter": object(),
                "database": {"kind": "memory"},
                "plugins": [{"id": "email-password"}],
            },
        )


async def test_explicit_integration_installs_email_password_plugin_routes() -> None:
    auth = FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("b" * 64),
            database=memory(),
            cookie=CookieOptions(secure=False),
            csrf=CsrfOptions(enabled=False),
            rate_limit=RateLimitOptions(enabled=False),
        ),
        plugins=[email_password()],
    )
    app = FastAPI(lifespan=auth.lifespan)
    app.include_router(auth.router, prefix=auth.context.config.app.base_path)
    auth.add_middleware(app)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        response = await client.post(
            "/auth/sign-up/email",
            json={"email": "alice@example.com", "password": "correct-horse-battery"},
        )

    assert response.status_code == 200, response.text
    assert response.json()["user"]["email"] == "alice@example.com"


async def test_email_password_routes_are_not_core_routes() -> None:
    auth = FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("c" * 64),
            database=memory(),
            cookie=CookieOptions(secure=False),
            csrf=CsrfOptions(enabled=False),
            rate_limit=RateLimitOptions(enabled=False),
        ),
    )
    app = FastAPI(lifespan=auth.lifespan)
    app.include_router(auth.router, prefix=auth.context.config.app.base_path)
    auth.add_middleware(app)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        response = await client.post(
            "/auth/sign-up/email",
            json={"email": "alice@example.com", "password": "correct-horse-battery"},
        )

    assert response.status_code == 404


def test_public_plugins_are_factories_with_pydantic_options() -> None:
    import fastauth

    plugin = openapi()

    assert plugin.id == "fastauth-openapi"
    assert hasattr(plugin.options, "model_dump")
    assert not hasattr(plugin, "config")
    assert fastauth.openapi().id == "fastauth-openapi"


def test_old_config_names_are_not_exported() -> None:
    import fastauth

    assert not hasattr(fastauth, "FastAuthConfig")
    assert not hasattr(fastauth, "create_auth")
    assert hasattr(fastauth, "FastAuth")


def test_root_exports_common_safe_response_types() -> None:
    import fastauth

    assert fastauth.AuthenticationResponse is AuthenticationResponse
    assert fastauth.SessionView is SessionView
    assert fastauth.UserView is UserView


def test_fastauth_exposes_single_dependency_namespace() -> None:
    auth = FastAuth(FastAuthOptions(secret_key=SecretStr("f" * 64), database=memory()))

    assert not hasattr(auth, "require_user")
    assert not hasattr(auth, "optional_user")
    assert not hasattr(auth, "require_session")
    assert not hasattr(auth, "optional_session")
    assert callable(auth.depends.user())
    assert callable(auth.depends.session())
    assert callable(auth.depends.optional_user())
    assert callable(auth.depends.optional_session())


def test_fastauth_exposes_pythonic_manager_namespaces() -> None:
    auth = FastAuth(
        FastAuthOptions(secret_key=SecretStr("g" * 64), database=memory()),
        plugins=[email_password()],
    )

    assert callable(auth.users.update)
    assert callable(auth.sessions.list)
    assert callable(auth.passwords.change)
    assert callable(auth.email_changes.request)
    assert callable(auth.sign_up.email)
    assert callable(auth.sign_in.email)
    assert auth.routes.sign_up.email.path == "/sign-up/email"
    inspection = auth.inspect()
    assert inspection.version
    assert inspection.model_dump(mode="json")["routes"]
    assert auth.plugin_info()[0].id == "fastauth-email-password"


def test_auth_inspector_reports_plugin_route_sources_explicitly() -> None:
    class InspectRoutePlugin(Plugin):
        id = "inspect-route-plugin"

        def endpoints(self) -> list[EndpointSpec]:
            async def ping() -> dict[str, bool]:
                return {"ok": True}

            return [
                EndpointSpec.get(
                    "/inspect-plugin/ping",
                    name="inspect_plugin_ping",
                    handler=ping,
                    tags=("InspectRoutePlugin",),
                )
            ]

    auth = FastAuth(
        FastAuthOptions(secret_key=SecretStr("g" * 64), database=memory()),
        plugins=[InspectRoutePlugin()],
    )

    routes = auth.inspect().routes
    health_route = next(route for route in routes if route.name == "fastauth_health")
    plugin_route = next(route for route in routes if route.name == "inspect_plugin_ping")

    assert health_route.source == "core"
    assert plugin_route.path == "/inspect-plugin/ping"
    assert plugin_route.source == "plugin"


def test_auth_api_public_methods_do_not_expose_transport_kwargs_or_tuple_results() -> None:
    auth = FastAuth(
        FastAuthOptions(secret_key=SecretStr("d" * 64), database=memory()),
        plugins=[email_password()],
    )

    for name, member in inspect.getmembers(auth.api, predicate=inspect.ismethod):
        if name.startswith("_"):
            continue
        assert not name.startswith("internal_")
        signature = inspect.signature(member)
        assert "ip" not in signature.parameters
        assert "user_agent" not in signature.parameters
        assert "tuple[" not in str(signature.return_annotation)


def test_auth_api_exposes_namespaced_server_surface() -> None:
    auth = FastAuth(
        FastAuthOptions(secret_key=SecretStr("g" * 64), database=memory()),
        plugins=[email_password()],
    )

    assert callable(auth.api.sign_out)
    assert callable(auth.api.session.get)
    assert callable(auth.api.session.refresh)
    assert callable(auth.api.session.list)
    assert callable(auth.api.session.revoke)
    assert callable(auth.api.session.revoke_other)
    assert callable(auth.api.password.change)
    assert callable(auth.api.password.request_reset)
    assert callable(auth.api.password.reset)
    assert callable(auth.api.user.update)
    assert callable(auth.api.user.change_email)
    assert callable(auth.api.user.delete)


def test_auth_api_commands_are_frozen_pydantic_models() -> None:
    command_classes = [
        SignOutCommand,
        GetSessionCommand,
        ListSessionsCommand,
        ChangePasswordCommand,
        UpdateUserCommand,
    ]

    for command_class in command_classes:
        assert command_class.model_config.get("frozen") is True


async def test_server_api_requires_email_password_provider() -> None:
    auth = FastAuth(
        FastAuthOptions(secret_key=SecretStr("e" * 64), database=memory()),
    )

    with pytest.raises(FeatureNotEnabledError):
        await auth.api.sign_up.email(
            SignUpEmailCommand(
                email="alice@example.com",
                password=SecretStr("correct-horse-battery"),
            ),
        )


async def test_server_api_respects_disabled_username_sign_in() -> None:
    auth = FastAuth(
        FastAuthOptions(secret_key=SecretStr("i" * 64), database=memory()),
        plugins=[
            email_password(
                EmailPasswordOptions(
                    allow_username_sign_in=False,
                )
            )
        ],
    )

    with pytest.raises(FeatureNotEnabledError, match="username-sign-in"):
        await auth.api.sign_in.username(
            SignInUsernameCommand(
                username="alice",
                password=SecretStr("correct-horse-battery"),
            ),
        )


def test_username_commands_use_shared_username_validation() -> None:
    with pytest.raises(ValidationError):
        SignInUsernameCommand(
            username="bad username",
            password=SecretStr("correct-horse-battery"),
        )

    with pytest.raises(ValidationError):
        SignUpEmailCommand(
            email="alice@example.com",
            username="x",
            password=SecretStr("correct-horse-battery"),
        )


async def test_session_api_accepts_immutable_principal() -> None:
    auth = FastAuth(
        FastAuthOptions(secret_key=SecretStr("j" * 64), database=memory()),
        plugins=[email_password()],
    )
    signed_up = await auth.api.sign_up.email(
        SignUpEmailCommand(
            email="alice@example.com",
            username="alice",
            password=SecretStr("correct-horse-battery"),
        )
    )

    result = await auth.api.session.list(
        ListSessionsCommand(
            principal=UserPrincipal(user_id=signed_up.user.id),
        )
    )

    assert len(result.sessions) == 1
    assert isinstance(UserPrincipal(user_id=signed_up.user.id).user_id, UserId)
    with pytest.raises(ValidationError):
        UserPrincipal.model_validate({"user_id": ""})


async def test_pythonic_managers_delegate_to_command_api() -> None:
    auth = FastAuth(
        FastAuthOptions(secret_key=SecretStr("k" * 64), database=memory()),
        plugins=[
            email_password(EmailPasswordOptions(allow_username_change=True)),
        ],
    )
    signed_up = await auth.sign_up.email(
        "manager@example.com",
        SecretStr("correct-horse-battery"),
        username="manager",
    )

    listed = await auth.sessions.list(signed_up.user.id)
    updated = await auth.users.update(
        signed_up.user.id,
        name="Manager",
        username="renamed-manager",
    )

    assert len(listed.sessions) == 1
    assert updated.name == "Manager"
    assert updated.username == "renamed-manager"


def test_principals_use_typed_id_wrappers() -> None:
    user_id = UserId("a" * 24)
    session_id = SessionId("b" * 24)

    principal = SessionPrincipal(user_id=user_id, session_id=session_id)

    assert principal.user_id == user_id
    assert principal.session_id == session_id
    assert RevokeSessionCommand(principal=UserPrincipal(user_id=user_id), session_id=session_id)


def test_canonical_principal_commands_do_not_expose_legacy_identity_fields() -> None:
    assert "user" not in ListSessionsCommand.model_fields
    assert "current_session_id" not in ChangePasswordCommand.model_fields
    assert "principal" in ChangePasswordCommand.model_fields
    assert ChangePasswordCommand.model_fields["principal"].annotation is SessionPrincipal


def test_legacy_user_command_module_is_removed() -> None:
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("fastauth.api.legacy")


async def test_server_api_requires_canonical_principal_commands() -> None:
    auth = FastAuth(
        FastAuthOptions(secret_key=SecretStr("j" * 64), database=memory()),
        plugins=[email_password()],
    )
    signed_up = await auth.api.sign_up.email(
        SignUpEmailCommand(
            email="legacy@example.com",
            password=SecretStr("correct-horse-battery"),
        )
    )
    user = await auth.context.adapter.get_user_by_id(signed_up.user.id.root)
    assert user is not None

    with pytest.raises(ValidationError):
        UpdateUserCommand.model_validate(
            {
                "user": user.model_dump(),
                "name": "Legacy",
            }
        )

    updated = await auth.api.user.update(
        UpdateUserCommand(
            principal=UserPrincipal(user_id=signed_up.user.id),
            name="Canonical",
        )
    )
    assert updated.name == "Canonical"


async def test_session_principal_rejects_mismatched_user_and_session() -> None:
    auth = FastAuth(
        FastAuthOptions(secret_key=SecretStr("j" * 64), database=memory()),
        plugins=[email_password()],
    )
    first = await auth.api.sign_up.email(
        SignUpEmailCommand(
            email="first@example.com",
            password=SecretStr("correct-horse-battery"),
        )
    )
    second = await auth.api.sign_up.email(
        SignUpEmailCommand(
            email="second@example.com",
            password=SecretStr("correct-horse-battery"),
        )
    )

    with pytest.raises(InvalidCredentialsError):
        await auth.api.password.change(
            ChangePasswordCommand(
                principal=SessionPrincipal(
                    user_id=first.user.id,
                    session_id=second.session.id,
                ),
                current_password=SecretStr("correct-horse-battery"),
                new_password=SecretStr("new-correct-horse-battery"),
            )
        )
