"""Pythonic public manager namespaces layered over the command API."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, EmailStr, SecretStr

from fastauth.api.commands import (
    BearerCredentialDelivery,
    ChangePasswordCommand,
    ConfirmEmailChangeCommand,
    ConfirmUserDeletionCommand,
    CookieCredentialDelivery,
    CredentialDelivery,
    DeleteUserCommand,
    GetSessionCommand,
    ListSessionsCommand,
    RefreshSessionCommand,
    RequestContext,
    RequestEmailChangeCommand,
    RequestPasswordResetCommand,
    RequestUserDeletionCommand,
    ResetPasswordCommand,
    RevokeOtherSessionsCommand,
    RevokeSessionCommand,
    SessionPrincipal,
    SetPasswordCommand,
    SignInEmailCommand,
    SignInUsernameCommand,
    SignOutCommand,
    SignUpEmailCommand,
    UpdateUserCommand,
    UserPrincipal,
    VerifyPasswordCommand,
)
from fastauth.api.responses import AuthenticationResponse, UserView
from fastauth.domain.value_objects import SessionId, UserId, UserMetadata, Username
from fastauth.flows.credentials import EmptyResponse
from fastauth.flows.sessions import ListSessionsResponse, RevokeSessionsResponse
from fastauth.flows.user_management import VerifyPasswordResponse
from fastauth.plugins.base import Plugin, PluginApiRegistry, PluginApiT, PluginInfo
from fastauth.runtime.capabilities import Capability

if TYPE_CHECKING:
    from collections.abc import Callable

    from fastauth.runtime.auth import FastAuth


UserIdInput = UserId | str
SessionIdInput = SessionId | str


def to_user_id(value: UserIdInput) -> UserId:
    if isinstance(value, UserId):
        return value
    return UserId(value)


def to_session_id(value: SessionIdInput) -> SessionId:
    if isinstance(value, SessionId):
        return value
    return SessionId(value)


class RouteInfo(BaseModel):
    """Serializable public route metadata."""

    model_config = ConfigDict(frozen=True)

    method: str
    path: str
    name: str
    tags: tuple[str, ...] = ()
    source: str = "core"


class AuthInspection(BaseModel):
    """Serializable runtime inspection payload."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    version: str
    database_backend: str
    session_strategy: str
    plugins: tuple[PluginInfo, ...]
    capabilities: tuple[Capability, ...]
    routes: tuple[RouteInfo, ...]
    production_warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class RouteRef:
    method: str
    path: str
    name: str


@dataclass(frozen=True)
class SignUpRoutes:
    email: RouteRef


@dataclass(frozen=True)
class SignInRoutes:
    email: RouteRef
    username: RouteRef


@dataclass(frozen=True)
class SessionRoutes:
    refresh: RouteRef
    get: RouteRef
    list: RouteRef
    revoke: RouteRef
    revoke_other: RouteRef
    sign_out: RouteRef


@dataclass(frozen=True)
class AuthRoutes:
    """Client-facing constants for first-party route paths."""

    sign_up: SignUpRoutes
    sign_in: SignInRoutes
    sessions: SessionRoutes

    @classmethod
    def from_base_path(cls, base_path: str) -> AuthRoutes:
        def ref(method: str, path: str, name: str) -> RouteRef:
            return RouteRef(method=method, path=f"{base_path}{path}", name=name)

        return cls(
            sign_up=SignUpRoutes(
                email=ref("POST", "/sign-up/email", "sign_up_email"),
            ),
            sign_in=SignInRoutes(
                email=ref("POST", "/sign-in/email", "sign_in_email"),
                username=ref("POST", "/sign-in/username", "sign_in_username"),
            ),
            sessions=SessionRoutes(
                refresh=ref("POST", "/refresh", "refresh_session"),
                get=ref("GET", "/get-session", "get_session"),
                list=ref("GET", "/sessions", "list_sessions"),
                revoke=ref("DELETE", "/sessions/{session_id}", "revoke_session"),
                revoke_other=ref("DELETE", "/sessions", "revoke_other_sessions"),
                sign_out=ref("POST", "/sign-out", "sign_out"),
            ),
        )


class SignUpManager:
    def __init__(self, auth: FastAuth) -> None:
        self._auth = auth

    async def email(
        self,
        email: EmailStr,
        password: SecretStr,
        *,
        name: str | None = None,
        username: Username | None = None,
        context: RequestContext | None = None,
        delivery: CredentialDelivery | None = None,
    ) -> AuthenticationResponse:
        return await self._auth.api.sign_up.email(
            SignUpEmailCommand(
                email=email,
                password=password,
                name=name,
                username=username,
                context=context or RequestContext(),
                delivery=delivery or CookieCredentialDelivery(),
            )
        )


class SignInManager:
    def __init__(self, auth: FastAuth) -> None:
        self._auth = auth

    async def email(
        self,
        email: EmailStr,
        password: SecretStr,
        *,
        context: RequestContext | None = None,
        delivery: CredentialDelivery | None = None,
    ) -> AuthenticationResponse:
        return await self._auth.api.sign_in.email(
            SignInEmailCommand(
                email=email,
                password=password,
                context=context or RequestContext(),
                delivery=delivery or CookieCredentialDelivery(),
            )
        )

    async def username(
        self,
        username: Username,
        password: SecretStr,
        *,
        context: RequestContext | None = None,
        delivery: CredentialDelivery | None = None,
    ) -> AuthenticationResponse:
        return await self._auth.api.sign_in.username(
            SignInUsernameCommand(
                username=username,
                password=password,
                context=context or RequestContext(),
                delivery=delivery or CookieCredentialDelivery(),
            )
        )


class SessionsManager:
    def __init__(self, auth: FastAuth) -> None:
        self._auth = auth

    async def get(self, token: SecretStr | None = None) -> AuthenticationResponse | None:
        return await self._auth.api.session.get(GetSessionCommand(token=token))

    async def refresh(
        self,
        refresh_token: SecretStr,
        *,
        context: RequestContext | None = None,
        delivery: CredentialDelivery | None = None,
    ) -> AuthenticationResponse:
        return await self._auth.api.session.refresh(
            RefreshSessionCommand(
                refresh_token=refresh_token,
                context=context or RequestContext(),
                delivery=delivery or BearerCredentialDelivery(),
            )
        )

    async def list(self, uid: UserIdInput) -> ListSessionsResponse:
        return await self._auth.api.session.list(
            ListSessionsCommand(principal=UserPrincipal(user_id=to_user_id(uid)))
        )

    async def revoke(
        self,
        uid: UserIdInput,
        sid: SessionIdInput,
    ) -> RevokeSessionsResponse:
        return await self._auth.api.session.revoke(
            RevokeSessionCommand(
                principal=UserPrincipal(user_id=to_user_id(uid)),
                session_id=to_session_id(sid),
            )
        )

    async def revoke_other(
        self,
        uid: UserIdInput,
        sid: SessionIdInput,
    ) -> RevokeSessionsResponse:
        return await self._auth.api.session.revoke_other(
            RevokeOtherSessionsCommand(
                principal=SessionPrincipal(user_id=to_user_id(uid), session_id=to_session_id(sid)),
            )
        )

    async def sign_out(self, token: SecretStr | None = None) -> EmptyResponse:
        return await self._auth.api.sign_out(SignOutCommand(token=token))


class UsersManager:
    def __init__(self, auth: FastAuth) -> None:
        self._auth = auth

    async def update(
        self,
        uid: UserIdInput,
        *,
        name: str | None = None,
        image: str | None = None,
        metadata: UserMetadata | None = None,
        context: RequestContext | None = None,
    ) -> UserView:
        return await self._auth.api.user.update(
            UpdateUserCommand(
                principal=UserPrincipal(user_id=to_user_id(uid)),
                name=name,
                image=image,
                metadata=metadata,
                context=context or RequestContext(),
            )
        )

    async def delete(
        self,
        uid: UserIdInput,
        password: SecretStr,
        *,
        context: RequestContext | None = None,
    ) -> EmptyResponse:
        return await self._auth.api.user.delete(
            DeleteUserCommand(
                principal=UserPrincipal(user_id=to_user_id(uid)),
                password=password,
                context=context or RequestContext(),
            )
        )

    async def request_delete(
        self,
        uid: UserIdInput,
        *,
        context: RequestContext | None = None,
    ) -> EmptyResponse:
        return await self._auth.api.user.request_delete(
            RequestUserDeletionCommand(
                principal=UserPrincipal(user_id=to_user_id(uid)),
                context=context or RequestContext(),
            )
        )

    async def confirm_delete(
        self,
        uid: UserIdInput,
        token: SecretStr,
        *,
        context: RequestContext | None = None,
    ) -> EmptyResponse:
        return await self._auth.api.user.confirm_delete(
            ConfirmUserDeletionCommand(
                principal=UserPrincipal(user_id=to_user_id(uid)),
                token=token,
                context=context or RequestContext(),
            )
        )


class PasswordsManager:
    def __init__(self, auth: FastAuth) -> None:
        self._auth = auth

    async def change(
        self,
        *,
        user_id: UserIdInput,
        session_id: SessionIdInput,
        current_password: SecretStr,
        new_password: SecretStr,
        revoke_other_sessions: bool = True,
        context: RequestContext | None = None,
    ) -> EmptyResponse:
        return await self._auth.api.password.change(
            ChangePasswordCommand(
                principal=SessionPrincipal(
                    user_id=to_user_id(user_id),
                    session_id=to_session_id(session_id),
                ),
                current_password=current_password,
                new_password=new_password,
                revoke_other_sessions=revoke_other_sessions,
                context=context or RequestContext(),
            )
        )

    async def request_reset(
        self,
        email: EmailStr,
        *,
        redirect_url: str | None = None,
        context: RequestContext | None = None,
    ) -> EmptyResponse:
        return await self._auth.api.password.request_reset(
            RequestPasswordResetCommand(
                email=email,
                redirect_url=redirect_url,
                context=context or RequestContext(),
            )
        )

    async def reset(
        self,
        email: EmailStr,
        token: SecretStr,
        new_password: SecretStr,
        *,
        context: RequestContext | None = None,
    ) -> EmptyResponse:
        return await self._auth.api.password.reset(
            ResetPasswordCommand(
                email=email,
                token=token,
                new_password=new_password,
                context=context or RequestContext(),
            )
        )

    async def set(
        self,
        *,
        user_id: UserIdInput,
        session_id: SessionIdInput,
        new_password: SecretStr,
        revoke_other_sessions: bool = True,
        context: RequestContext | None = None,
    ) -> EmptyResponse:
        return await self._auth.api.user.set_password(
            SetPasswordCommand(
                principal=SessionPrincipal(
                    user_id=to_user_id(user_id),
                    session_id=to_session_id(session_id),
                ),
                new_password=new_password,
                revoke_other_sessions=revoke_other_sessions,
                context=context or RequestContext(),
            )
        )

    async def verify(
        self,
        uid: UserIdInput,
        password: SecretStr,
        *,
        context: RequestContext | None = None,
    ) -> VerifyPasswordResponse:
        return await self._auth.api.user.verify_password(
            VerifyPasswordCommand(
                principal=UserPrincipal(user_id=to_user_id(uid)),
                password=password,
                context=context or RequestContext(),
            )
        )


class EmailChangesManager:
    def __init__(self, auth: FastAuth) -> None:
        self._auth = auth

    async def request(
        self,
        uid: UserIdInput,
        new_email: EmailStr,
        password: SecretStr,
        *,
        context: RequestContext | None = None,
    ) -> EmptyResponse:
        return await self._auth.api.user.change_email(
            RequestEmailChangeCommand(
                principal=UserPrincipal(user_id=to_user_id(uid)),
                new_email=new_email,
                password=password,
                context=context or RequestContext(),
            )
        )

    async def confirm(
        self,
        new_email: EmailStr,
        token: SecretStr,
        *,
        context: RequestContext | None = None,
    ) -> EmptyResponse:
        return await self._auth.api.user.confirm_email_change(
            ConfirmEmailChangeCommand(
                new_email=new_email,
                token=token,
                context=context or RequestContext(),
            )
        )


class DependsManager:
    def __init__(self, auth: FastAuth) -> None:
        self._auth = auth

    def session(self) -> Callable[..., Any]:
        return self._auth.get_current_session

    def optional_session(self) -> Callable[..., Any]:
        return self._auth.get_optional_current_session

    def user(self) -> Callable[..., Any]:
        return self._auth.get_current_user

    def user_view(self) -> Callable[..., Any]:
        return self._auth.get_current_user_view

    def optional_user(self) -> Callable[..., Any]:
        return self._auth.get_optional_current_user

    def optional_user_view(self) -> Callable[..., Any]:
        return self._auth.get_optional_current_user_view


class PluginsManager:
    """Public plugin lookup surface.

    It exposes installed plugins for introspection while adding typed access
    to plugin-contributed server APIs.
    """

    def __init__(self, plugins: Sequence[Plugin], api_registry: PluginApiRegistry) -> None:
        self.items: tuple[Plugin, ...] = tuple(plugins)
        self.api_registry = api_registry

    def list(self) -> tuple[Plugin, ...]:
        return self.items

    def at(self, index: int) -> Plugin:
        return self.items[index]

    def count(self) -> int:
        return len(self.items)

    def try_get(self, api_type: type[PluginApiT]) -> PluginApiT | None:
        return self.api_registry.try_get(api_type)

    def get(self, api_type: type[PluginApiT]) -> PluginApiT:
        return self.api_registry.get(api_type)


class AuthInspector:
    def __init__(self, auth: FastAuth) -> None:
        self._auth = auth

    def __call__(self) -> AuthInspection:
        from fastauth import __version__

        return AuthInspection(
            version=__version__,
            database_backend=self._auth.options.database.backend_kind().value,
            session_strategy=self._auth.options.session.strategy.value,
            plugins=tuple(self.plugins()),
            capabilities=tuple(self.capabilities()),
            routes=tuple(self.routes()),
        )

    def capabilities(self) -> list[Capability]:
        return self._auth.capabilities.list()

    def plugins(self) -> list[PluginInfo]:
        return self._auth.plugin_info()

    def routes(self) -> list[RouteInfo]:
        routes: list[RouteInfo] = []
        for route in self._auth.router.routes:
            methods = getattr(route, "methods", None)
            path = getattr(route, "path", "")
            name = getattr(route, "name", "")
            tags = tuple(getattr(route, "tags", ()) or ())
            source = getattr(route, "fastauth_source", "core")
            for method in sorted(methods or ()):
                if method in {"HEAD", "OPTIONS"}:
                    continue
                routes.append(
                    RouteInfo(
                        method=method,
                        path=path,
                        name=name,
                        tags=tags,
                        source=source,
                    )
                )
        return routes
