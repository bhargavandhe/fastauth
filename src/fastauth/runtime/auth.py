"""FastAuth — main entrypoint composing every fastauth subsystem."""

from __future__ import annotations

from collections.abc import AsyncGenerator, Sequence
from contextlib import asynccontextmanager
from typing import cast

from fastapi import FastAPI, HTTPException, Request, status

from fastauth.domain.enums import RateLimitStorageKind, SessionStrategyKind
from fastauth.domain.models import User
from fastauth.exceptions import ConfigError, InvalidCredentialsError
from fastauth.messaging.email import ConsoleEmailSender, EmailSender, TemplateRenderer
from fastauth.options import (
    CustomDatabaseOptions,
    FastAuthOptions,
    MongoDatabaseOptions,
    PostgresDatabaseOptions,
)
from fastauth.plugins.base import Plugin, PluginRegistry
from fastauth.runtime.api import AuthApi
from fastauth.runtime.context import AuthContext
from fastauth.runtime.event_bus import EventBus
from fastauth.runtime.hooks import DatabaseHooks
from fastauth.security.lockout import AccountLockoutTracker
from fastauth.security.passwords import Argon2idHasher, PasswordHasher
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
from fastauth.web.fastapi import build_router, extract_session_token
from fastauth.web.security_headers import SecurityHeadersMiddleware

__all__ = ["FastAuth"]


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
        self.plugins = tuple(plugins)
        config = options
        adapter = options.database.build_adapter()

        password_hasher = password_hasher or Argon2idHasher(config.password)
        token_service = token_service or TokenService()
        email_sender = email_sender or ConsoleEmailSender()
        signed_cookie = SignedCookieValue(
            config.secret_key,
            list(config.secret_key_rotation),
        )

        plugin_registry = PluginRegistry(self.plugins)

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

        self.context = AuthContext(
            config=config,
            adapter=adapter,
            session_strategy=session_strategy,
            password_hasher=password_hasher,
            token_service=token_service,
            email_sender=email_sender,
            template_renderer=TemplateRenderer(config.email.template_directory),
            hooks=DatabaseHooks(),
            event_bus=EventBus(),
            plugins=plugin_registry,
            signed_cookie=signed_cookie,
            rate_limiter=rate_limiter,
            lockout_tracker=lockout_tracker,
            refresh_token_service=refresh_token_service,
        )

        for event_type, handler in self.context.plugins.all_event_handlers():
            self.context.event_bus.subscribe(event_type, handler)  # type: ignore[arg-type]

        # Late-bind the context into every plugin that declares a ``bind`` hook.
        # The context can't be passed via __init__ because the PluginRegistry it
        # owns must already contain the plugin instances.
        for plugin in self.context.plugins.plugins:
            bind = getattr(plugin, "bind", None)
            if callable(bind):
                bind(self.context)

        self.api = AuthApi(self.context)
        self.router = build_router(self.context, self.api)

    def as_asgi(self) -> FastAPI:
        """Return a standalone ``FastAPI`` app wrapping the fastauth router."""
        app = FastAPI(title="fastauth", lifespan=self.lifespan)
        self.mount(app)
        return app

    def mount(self, app: FastAPI) -> None:
        """Mount fastauth routes and middleware on an existing ``FastAPI`` app."""
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
        if isinstance(self.options.database, MongoDatabaseOptions):
            from fastauth.storage.beanie.documents import init_beanie_documents

            await init_beanie_documents(
                self.options.database.database,  # type: ignore[arg-type]
                collection_prefix=self.options.database.collection_prefix,
                collection_suffix=self.options.database.collection_suffix,
            )
        if isinstance(self.options.database, PostgresDatabaseOptions):
            adapter = self.context.adapter
            if self.options.database.migration_mode == "apply":
                await adapter.apply_migrations()  # type: ignore[attr-defined]
            elif self.options.database.migration_mode == "check":
                await adapter.assert_schema_current()  # type: ignore[attr-defined]
        if (
            isinstance(self.options.database, CustomDatabaseOptions)
            and self.options.database.lifespan
        ):
            async with self.options.database.lifespan(self)(app or FastAPI()):
                async with self.plugin_lifespan():
                    yield
            return
        async with self.plugin_lifespan():
            yield

    @asynccontextmanager
    async def plugin_lifespan(self) -> AsyncGenerator[None, None]:
        for plugin in self.context.plugins.plugins:
            await plugin.lifespan_startup()
        try:
            yield
        finally:
            for plugin in self.context.plugins.plugins:
                await plugin.lifespan_shutdown()

    # --- FastAPI dependency callables ---
    #
    # These are bound methods on the ``FastAuth`` instance so they capture the
    # built ``AuthContext`` (signed-cookie unpacker, session strategy, adapter)
    # automatically. Users compose them with ``Annotated[T, Depends(...)]`` at
    # their callsite — e.g.::
    #
    #     CurrentUser = Annotated[User, Depends(auth.get_current_user)]
    #     async def me(user: CurrentUser) -> User: ...
    #
    # Cookie and ``Authorization: Bearer`` transports are both honoured via
    # the same ``extract_session_token`` helper used by the core endpoints.

    async def get_current_session(self, request: Request) -> SessionContext:
        """Return the active ``SessionContext`` or raise HTTP 401.

        Use as a FastAPI dependency with
        ``Annotated[SessionContext, Depends(auth.get_current_session)]``. Raises
        ``fastapi.HTTPException(401)`` with the
        ``InvalidCredentialsError.default_code`` (``"INVALID_CREDENTIALS"``) so
        the response shape matches the rest of the library.
        """
        session = await self.get_optional_current_session(request)
        if session is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "code": InvalidCredentialsError.default_code,
                    "message": "authentication required",
                },
            )
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

        Use as a FastAPI dependency with
        ``Annotated[User, Depends(auth.get_current_user)]``.
        """
        session = await self.get_current_session(request)
        return session.user

    async def get_optional_current_user(self, request: Request) -> User | None:
        """Return the active ``User`` or ``None`` for anonymous requests.

        Never raises. Companion to ``get_optional_current_session``.
        """
        session = await self.get_optional_current_session(request)
        return session.user if session else None
