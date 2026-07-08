"""FastAuth — main entrypoint composing every fastauth subsystem."""

from __future__ import annotations

from collections.abc import AsyncGenerator, Awaitable, Callable, Sequence
from contextlib import asynccontextmanager
from typing import TypeVar, cast

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from fastauth.api.responses import UserView, user_view
from fastauth.domain.enums import RateLimitStorageKind, SessionStrategyKind
from fastauth.domain.events import AuthEvent
from fastauth.domain.models import User
from fastauth.exceptions import ConfigError, FastAuthDependencyError, FastAuthError
from fastauth.messaging.email import ConsoleEmailSender, EmailSender, TemplateRenderer
from fastauth.options import (
    CookieOptions,
    FastAuthOptions,
)
from fastauth.plugins.base import Plugin, PluginInfo, PluginRegistry
from fastauth.runtime.api import AuthApi
from fastauth.runtime.capabilities import Capability, CapabilityRegistry
from fastauth.runtime.context import AuthContext
from fastauth.runtime.event_bus import EventBus
from fastauth.runtime.hooks import DatabaseHooks
from fastauth.runtime.managers import (
    AuthInspector,
    AuthRoutes,
    DependsManager,
    EmailChangesManager,
    PasswordsManager,
    PluginsManager,
    SessionsManager,
    SignInManager,
    SignUpManager,
    UsersManager,
)
from fastauth.security.lockout import AccountLockoutTracker
from fastauth.security.passwords import Argon2idHasher, CredentialService, PasswordHasher
from fastauth.security.rate_limit import (
    DatabaseRateLimitStorage,
    MemoryRateLimitStorage,
    RateLimiter,
)
from fastauth.security.refresh_tokens import RefreshTokenService
from fastauth.security.sessions import DatabaseSessionStrategy, SessionContext, SessionStrategy
from fastauth.security.tokens import SignedCookieValue, TokenService
from fastauth.storage.base import JwksKeyStore, RateLimitStore
from fastauth.web.csrf import CsrfMiddleware
from fastauth.web.fastapi import build_router, extract_session_token, http_status_for
from fastauth.web.security_headers import SecurityHeadersMiddleware

__all__ = ["FastAuth", "create_auth"]

EventT = TypeVar("EventT", bound=AuthEvent)


async def fastauth_error_handler(
    request: Request,
    exc: Exception,
) -> Response:
    del request
    if not isinstance(exc, FastAuthError):
        raise exc
    return JSONResponse(
        status_code=http_status_for(exc),
        content={"code": exc.code, "message": exc.message},
    )


class FastAuth:
    """Main entrypoint. Assembles the ``AuthContext``, ``AuthApi``, and router."""

    def __init__(
        self,
        options: FastAuthOptions,
        *,
        plugins: Sequence[Plugin] = (),
        email_sender: EmailSender | None = None,
        password_hasher: PasswordHasher | None = None,
        session_strategy: SessionStrategy | None = None,
        token_service: TokenService | None = None,
    ) -> None:
        self.options = options
        self.installed_plugins = tuple(plugins)
        config = options
        self.database_runtime = options.database.build_runtime()
        adapter = self.database_runtime.adapter

        credential_service = CredentialService(config.password)
        password_hasher = password_hasher or Argon2idHasher(config.password)
        token_service = token_service or TokenService()
        email_sender = email_sender or ConsoleEmailSender()
        if config.deployment == "production" and isinstance(email_sender, ConsoleEmailSender):
            raise ConfigError(
                message=(
                    "FastAuthOptions.deployment='production' requires an explicit "
                    "non-console email_sender"
                ),
            )
        signed_cookie = SignedCookieValue(
            config.secret_key,
            list(config.secret_key_rotation),
        )

        plugin_registry = PluginRegistry(self.installed_plugins)

        if session_strategy is None:
            if config.session.strategy is SessionStrategyKind.DATABASE:
                session_strategy = DatabaseSessionStrategy(
                    adapter,
                    token_service,
                    config.session,
                )
            else:
                # JWT mode: locate the installed JwtPlugin and reuse its
                # JwksRegistry + signer so the /token endpoint, the /jwks
                # endpoint, and the session strategy all share the same kid.
                from fastauth.plugins.jwt import JwtPlugin
                from fastauth.security.jwt import JwtSessionStrategy

                jwt_plugin = next(
                    (p for p in plugin_registry.plugins if isinstance(p, JwtPlugin)),
                    None,
                )
                if jwt_plugin is None:
                    raise ValueError(
                        "SessionOptions.strategy == JWT requires JwtPlugin in the "
                        "plugins list, or pass an explicit 'session_strategy' "
                        "argument.",
                    )
                if not isinstance(adapter, JwksKeyStore):
                    raise ConfigError(
                        message="JWT sessions require an adapter implementing JwksKeyStore",
                    )
                jwks_store = cast(JwksKeyStore, adapter)
                registry, signer = jwt_plugin.ensure_registry_and_signer(
                    adapter=jwks_store,
                    secret_key_value=config.secret_key,
                    secret_key_rotation=list(config.secret_key_rotation),
                )
                session_strategy = JwtSessionStrategy(
                    adapter=adapter,
                    registry=registry,
                    signer=signer,
                    issuer=jwt_plugin.options.issuer or str(config.app.base_url),
                    audience=jwt_plugin.options.audience or str(config.app.base_url),
                    expires_in_seconds=jwt_plugin.options.expires_in_seconds,
                    payload_builder=jwt_plugin.payload_builder,
                )

        if config.rate_limit.storage is RateLimitStorageKind.DATABASE:
            if not isinstance(adapter, RateLimitStore):
                raise ConfigError(
                    message=(
                        "RateLimitOptions.storage == DATABASE requires an adapter "
                        "implementing RateLimitStore"
                    ),
                )
            rate_limit_store = cast(RateLimitStore, adapter)
            rate_storage: DatabaseRateLimitStorage | MemoryRateLimitStorage = (
                DatabaseRateLimitStorage(rate_limit_store)
            )
        else:
            rate_storage = MemoryRateLimitStorage()

        rate_limiter = RateLimiter(
            config=config.rate_limit,
            advanced=config.advanced,
            storage=rate_storage,
            plugin_rules=plugin_registry.all_rate_limit_rules(),
        )

        lockout_tracker = AccountLockoutTracker(
            config=config.lockout,
            storage=rate_storage,
        )

        refresh_token_service = RefreshTokenService(
            adapter=adapter,
            config=config.refresh_token,
            token_service=token_service,
        )
        event_bus = EventBus()

        self.context = AuthContext(
            config=config,
            adapter=adapter,
            session_strategy=session_strategy,
            credential_service=credential_service,
            password_hasher=password_hasher,
            token_service=token_service,
            email_sender=email_sender,
            template_renderer=TemplateRenderer(config.email.template_directory),
            hooks=DatabaseHooks(),
            event_bus=event_bus,
            plugins=plugin_registry,
            signed_cookie=signed_cookie,
            rate_limiter=rate_limiter,
            lockout_tracker=lockout_tracker,
            refresh_token_service=refresh_token_service,
        )

        # Late-bind the context into every plugin before building server API
        # namespaces. Third-party API objects may legitimately need bound
        # context during construction.
        # The context can't be passed via __init__ because the PluginRegistry it
        # owns must already contain the plugin instances.
        self.context.plugins.bind_plugins(self.context)

        for event_type, handler in self.context.plugins.all_event_handlers():
            self.context.event_bus.subscribe(event_type, handler)  # type: ignore[arg-type]

        self.events: EventBus = event_bus
        self.capabilities: CapabilityRegistry = CapabilityRegistry(
            [
                Capability(
                    id="core.sessions",
                    description="Core session creation, reading, listing, and revocation.",
                ),
                Capability(
                    id="core.refresh-tokens",
                    description="Refresh-token rotation, absolute expiry, and family revocation.",
                ),
                *self.context.plugins.all_capabilities(),
            ]
        )
        self.api = AuthApi(self.context)
        self.router = build_router(self.context, self.api)
        self.plugins = PluginsManager(self.context.plugins.plugins, self.api.plugins)
        self.sign_up = SignUpManager(self)
        self.sign_in = SignInManager(self)
        self.sessions = SessionsManager(self)
        self.users = UsersManager(self)
        self.passwords = PasswordsManager(self)
        self.email_changes = EmailChangesManager(self)
        self.depends = DependsManager(self)
        self.routes = AuthRoutes.from_base_path(self.context.config.app.base_path)
        self.inspect = AuthInspector(self)

    @classmethod
    def configure(
        cls,
        *,
        plugins: Sequence[Plugin] = (),
        email_sender: EmailSender | None = None,
        password_hasher: PasswordHasher | None = None,
        session_strategy: SessionStrategy | None = None,
        token_service: TokenService | None = None,
        **options: object,
    ) -> FastAuth:
        """Construct ``FastAuth`` directly from ``FastAuthOptions`` keyword fields."""
        return cls(
            FastAuthOptions.model_validate(options),
            plugins=plugins,
            email_sender=email_sender,
            password_hasher=password_hasher,
            session_strategy=session_strategy,
            token_service=token_service,
        )

    @classmethod
    def local_dev(
        cls,
        *,
        plugins: Sequence[Plugin] = (),
        email_sender: EmailSender | None = None,
        **options: object,
    ) -> FastAuth:
        """Construct a local HTTP development instance with insecure cookies."""
        options.setdefault("cookie", CookieOptions(secure=False))
        options.setdefault("deployment", "development")
        return cls(
            FastAuthOptions.model_validate(options),
            plugins=plugins,
            email_sender=email_sender,
        )

    @classmethod
    def production(
        cls,
        *,
        plugins: Sequence[Plugin] = (),
        email_sender: EmailSender | None = None,
        **options: object,
    ) -> FastAuth:
        """Construct a production instance and apply production validators."""
        options["deployment"] = "production"
        return cls(
            FastAuthOptions.model_validate(options),
            plugins=plugins,
            email_sender=email_sender,
        )

    def on_event(
        self,
        event_type: type[EventT],
        handler: Callable[[EventT], Awaitable[None]],
    ) -> None:
        """Subscribe an async handler to structured FastAuth security events."""
        self.events.subscribe(event_type, handler)

    def plugin_info(self) -> list[PluginInfo]:
        """Return serializable metadata for installed plugins."""
        return self.context.plugins.plugin_info()

    def as_asgi(self) -> FastAPI:
        """Return a standalone ``FastAPI`` app wrapping the fastauth router."""
        app = FastAPI(title="fastauth", lifespan=self.lifespan)
        self.mount(app)
        return app

    def mount(self, app: FastAPI) -> None:
        """Mount fastauth routes and middleware on an existing ``FastAPI`` app."""
        if FastAuthError not in app.exception_handlers:
            app.add_exception_handler(FastAuthError, fastauth_error_handler)
        app.include_router(self.router)
        app.add_middleware(
            CsrfMiddleware,
            config=self.context.config.csrf,
            additional_trusted_origins=self.context.plugins.all_trusted_origins(),
            cookie_name=self.context.config.cookie.name,
        )
        app.add_middleware(
            SecurityHeadersMiddleware,
            config=self.context.config.security_headers,
        )

    @asynccontextmanager
    async def lifespan(self, app: FastAPI | None = None) -> AsyncGenerator[None, None]:
        """ASGI lifespan for storage bootstrap plus plugin startup/shutdown hooks."""
        app_instance = app or FastAPI()
        database_context = self.database_runtime.lifespan(self, app_instance)
        await database_context.__aenter__()
        body_error: BaseException | None = None
        try:
            async with self.plugin_lifespan():
                yield
        except BaseException as exc:
            body_error = exc
            suppressed = False
            try:
                suppressed = bool(
                    await database_context.__aexit__(
                        type(exc),
                        exc,
                        exc.__traceback__,
                    )
                )
            except BaseException as shutdown_error:
                raise BaseExceptionGroup(
                    "fastauth lifespan failed",
                    [exc, shutdown_error],
                ) from shutdown_error
            if not suppressed:
                raise
        finally:
            if body_error is None:
                await database_context.__aexit__(None, None, None)

    @asynccontextmanager
    async def plugin_lifespan(self) -> AsyncGenerator[None, None]:
        started: list[Plugin] = []
        primary_error: BaseException | None = None
        shutdown_errors: list[BaseException] = []

        try:
            for plugin in self.context.plugins.plugins:
                await plugin.lifespan_startup()
                started.append(plugin)
            yield
        except BaseException as exc:
            primary_error = exc

        for plugin in reversed(started):
            try:
                await plugin.lifespan_shutdown()
            except BaseException as exc:
                shutdown_errors.append(exc)

        if primary_error is not None and shutdown_errors:
            raise BaseExceptionGroup(
                "plugin lifespan failed",
                [primary_error, *shutdown_errors],
            ) from primary_error
        if primary_error is not None:
            raise primary_error
        if shutdown_errors:
            raise BaseExceptionGroup("plugin shutdown failed", shutdown_errors)

    # --- FastAPI dependency callables ---
    #
    # These are bound methods on the ``FastAuth`` instance so they capture the
    # built ``AuthContext`` (signed-cookie unpacker, session strategy, adapter)
    # automatically. Users compose them with ``Annotated[T, Depends(...)]`` at
    # their callsite — e.g.::
    #
    #     CurrentUser = Annotated[UserView, Depends(auth.get_current_user_view)]
    #     async def me(user: CurrentUser) -> UserView: ...
    #
    # Cookie and ``Authorization: Bearer`` transports are both honoured via
    # the same ``extract_session_token`` helper used by the core endpoints.

    async def get_current_session(self, request: Request) -> SessionContext:
        """Return the active ``SessionContext`` or raise HTTP 401.

        Use as a FastAPI dependency with
        ``Annotated[SessionContext, Depends(auth.get_current_session)]``. Raises
        ``FastAuthDependencyError`` so mounted applications get the canonical
        FastAuth error DTO without replacing their own HTTPException handler.
        """
        session = await self.get_optional_current_session(request)
        if session is None:
            raise FastAuthDependencyError()
        return session

    async def get_optional_current_session(
        self,
        request: Request,
    ) -> SessionContext | None:
        """Return the active ``SessionContext`` or ``None`` for anonymous requests.

        Never raises. Use when an endpoint should work for both signed-in and
        anonymous callers but customise its response based on session presence.
        """
        token = extract_session_token(request, self.context)
        if token is None:
            return None
        return await self.context.session_strategy.read(token)

    async def get_current_user(self, request: Request) -> User:
        """Return the active ``User`` or raise 401.

        Prefer ``get_current_user_view`` for application routes. Use this
        lower-level dependency only when domain/session internals are required:
        ``Annotated[User, Depends(auth.get_current_user)]``.
        """
        session = await self.get_current_session(request)
        return session.user

    async def get_current_user_view(self, request: Request) -> UserView:
        """Return the active user as a safe public DTO or raise 401."""
        return user_view(await self.get_current_user(request))

    async def get_optional_current_user(self, request: Request) -> User | None:
        """Return the active ``User`` or ``None`` for anonymous requests.

        Never raises. Companion to ``get_optional_current_session``.
        """
        session = await self.get_optional_current_session(request)
        return session.user if session else None

    async def get_optional_current_user_view(self, request: Request) -> UserView | None:
        """Return the active user as a safe public DTO, or ``None`` for anonymous requests."""
        user = await self.get_optional_current_user(request)
        return user_view(user) if user is not None else None

    async def require_session(self, request: Request) -> SessionContext:
        """Alias for ``get_current_session``."""
        return await self.get_current_session(request)

    async def optional_session(self, request: Request) -> SessionContext | None:
        """Alias for ``get_optional_current_session``."""
        return await self.get_optional_current_session(request)

    async def require_user(self, request: Request) -> UserView:
        """Alias for ``get_current_user_view``."""
        return await self.get_current_user_view(request)

    async def optional_user(self, request: Request) -> UserView | None:
        """Alias for ``get_optional_current_user_view``."""
        return await self.get_optional_current_user_view(request)


def create_auth(
    *,
    plugins: Sequence[Plugin] = (),
    email_sender: EmailSender | None = None,
    password_hasher: PasswordHasher | None = None,
    session_strategy: SessionStrategy | None = None,
    token_service: TokenService | None = None,
    **options: object,
) -> FastAuth:
    """Construct ``FastAuth`` from ``FastAuthOptions`` keyword fields."""
    return FastAuth.configure(
        plugins=plugins,
        email_sender=email_sender,
        password_hasher=password_hasher,
        session_strategy=session_strategy,
        token_service=token_service,
        **options,
    )
