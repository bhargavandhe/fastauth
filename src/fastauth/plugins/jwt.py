"""JwtPlugin: ``/token`` and ``/jwks`` endpoints + optional ``set-auth-jwt`` response header.

Wraps the JWT primitives from ``fastauth.security.jwt`` (``JwksRegistry``, ``LocalKmsSigner``)
into a ``Plugin`` that contributes two HTTP endpoints to the FastAuth router:

* ``POST {token_path}`` — exchange the current session for a freshly-issued JWT.
* ``GET {jwks_path}`` — public JWKS document used to verify those tokens.

When this plugin is installed, the ``GET /auth/get-session`` handler also returns a
``set-auth-jwt`` response header containing a JWT for the active user (unless
``disable_setting_jwt_header`` is set).
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar

from fastapi import Request, Response
from pydantic import Field, SecretStr

from fastauth.domain.enums import JwtAlgorithm
from fastauth.domain.models import User, WireModel
from fastauth.exceptions import ConfigError, InvalidCredentialsError
from fastauth.plugins.base import EndpointSpec, Plugin, PluginOptions
from fastauth.runtime.context import AuthContext
from fastauth.security.jwt import JwksDocument, JwksRegistry, KmsSigner, LocalKmsSigner
from fastauth.storage.base import JwksKeyStore

__all__ = [
    "JwtOptions",
    "JwtPlugin",
    "TokenResponse",
    "default_payload_builder",
]


PayloadBuilder = Callable[[User], dict[str, Any]]
SignerFactory = Callable[[JwksRegistry], KmsSigner]


class JwtOptions(PluginOptions):
    """Static configuration for ``JwtPlugin``."""

    alg: JwtAlgorithm = JwtAlgorithm.EDDSA
    expires_in: timedelta = Field(default=timedelta(minutes=15), gt=timedelta(0))
    issuer: str | None = None
    audience: str | None = None
    rotation_interval: timedelta | None = Field(default=None, gt=timedelta(0))
    grace_period: timedelta = Field(default=timedelta(days=1), gt=timedelta(0))
    disable_setting_jwt_header: bool = False
    disable_private_key_encryption: bool = False
    jwks_path: str = Field(default="/jwks", pattern=r"^/")
    token_path: str = Field(default="/token", pattern=r"^/")

    @property
    def expires_in_seconds(self) -> int:
        return int(self.expires_in.total_seconds())

    @property
    def rotation_interval_seconds(self) -> int | None:
        if self.rotation_interval is None:
            return None
        return int(self.rotation_interval.total_seconds())

    @property
    def grace_period_seconds(self) -> int:
        return int(self.grace_period.total_seconds())


class TokenResponse(WireModel):
    """Body shape returned by ``POST /auth/token``."""

    token: str


def default_payload_builder(user: User) -> dict[str, Any]:
    """Default subset of user fields embedded in JWT claims.

    **Rule exception — returns a plain ``dict``:** JWT payloads are
    deliberately open-ended (RFC 7519 §4): each application defines its own
    custom claims on top of the registered ones, so the return value has to
    remain ``dict[str, Any]``. Downstream signers consume it as JSON. One of
    the four documented carve-outs in CONTRIBUTING.md.
    """
    return {
        "email": user.email,
        "email_verified": user.email_verified,
        "name": user.name,
    }


class JwtPlugin(Plugin):
    """Plugin exposing ``/token`` and ``/jwks`` and optionally injecting a JWT header."""

    id: ClassVar[str] = "fastauth-jwt"

    def __init__(
        self,
        options: JwtOptions | None = None,
        *,
        payload_builder: PayloadBuilder | None = None,
        signer_factory: SignerFactory | None = None,
    ) -> None:
        self.options = options or JwtOptions()
        self.payload_builder: PayloadBuilder = payload_builder or default_payload_builder
        self.signer_factory: SignerFactory = signer_factory or LocalKmsSigner
        self.context: AuthContext | None = None
        self.registry: JwksRegistry | None = None
        self.signer: KmsSigner | None = None

    def endpoints(self) -> Sequence[EndpointSpec]:
        return [
            EndpointSpec(
                method="POST",
                path=self.options.token_path,
                name="auth_token",
                tags=["Jwt"],
                handler=self.token_handler,
                response_model=TokenResponse,
            ),
            EndpointSpec(
                method="GET",
                path=self.options.jwks_path,
                name="auth_jwks",
                tags=["Jwt"],
                handler=self.jwks_handler,
                response_model=JwksDocument,
            ),
        ]

    def bind(self, context: AuthContext) -> None:
        """Attach the assembled ``AuthContext``.

        The JWKS registry and signer may have already been built ahead of
        ``bind`` (specifically, by ``FastAuth.__init__`` when
        ``SessionConfig.strategy == JWT`` and a ``JwtSessionStrategy`` is
        constructed before plugin binding). In that case we reuse them so
        the plugin's ``/token``/``/jwks`` endpoints and the session strategy
        share the same registry and produce the same kid space.
        """
        self.context = context
        if not isinstance(context.adapter, JwksKeyStore):
            raise ConfigError(message="JwtPlugin requires an adapter implementing JwksKeyStore")
        if self.registry is None or self.signer is None:
            self.ensure_registry_and_signer(
                adapter=context.adapter,
                secret_key_value=context.config.secret_key,
                secret_key_rotation=list(context.config.secret_key_rotation),
            )

    def ensure_registry_and_signer(
        self,
        *,
        adapter: JwksKeyStore,
        secret_key_value: SecretStr,
        secret_key_rotation: list[SecretStr],
    ) -> tuple[JwksRegistry, KmsSigner]:
        """Idempotently construct ``self.registry`` + ``self.signer``.

        Called by ``bind`` in normal usage, OR by ``FastAuth.__init__`` ahead
        of plugin binding when the JwtPlugin is also the session strategy.
        """
        if self.registry is None:
            self.registry = JwksRegistry(
                adapter=adapter,
                secret_key=secret_key_value,
                secret_key_rotation=secret_key_rotation,
                alg=self.options.alg,
                rotation_interval_seconds=self.options.rotation_interval_seconds,
                grace_period_seconds=self.options.grace_period_seconds,
                encrypt_private_keys=not self.options.disable_private_key_encryption,
            )
        if self.signer is None:
            self.signer = self.signer_factory(self.registry)
        return self.registry, self.signer

    async def lifespan_startup(self) -> None:
        registry = self.assert_bound()[1]
        await registry.ensure_key()
        await registry.rotate_if_due()

    def assert_bound(self) -> tuple[AuthContext, JwksRegistry, KmsSigner]:
        """Return the bound trio or raise if ``bind`` was never invoked."""
        if self.context is None or self.registry is None or self.signer is None:
            raise RuntimeError("JwtPlugin is not bound to an AuthContext")
        return self.context, self.registry, self.signer

    async def issue_token_for(self, user: User) -> str:
        """Sign a JWT for ``user`` using the plugin's configured signer."""
        context, _registry, signer = self.assert_bound()
        now = datetime.now(UTC)
        issuer = self.options.issuer or context.config.app.base_url
        audience = self.options.audience or context.config.app.base_url
        payload: dict[str, Any] = {
            "iss": issuer,
            "aud": audience,
            "sub": user.id,
            "iat": int(now.timestamp()),
            "exp": int((now + self.options.expires_in).timestamp()),
            **self.payload_builder(user),
        }
        return await signer.sign(
            header={"alg": self.options.alg.value, "typ": "JWT"},
            payload=payload,
        )

    async def extend_session_response(self, user: User, response: Response) -> None:
        if self.options.disable_setting_jwt_header:
            return
        response.headers["set-auth-jwt"] = await self.issue_token_for(user)

    async def token_handler(self, request: Request) -> TokenResponse:
        """``POST /auth/token`` — issue a JWT for the user attached to the current session."""
        from fastauth.web.fastapi import extract_session_token

        context, _registry, _signer = self.assert_bound()
        token = extract_session_token(request, context)
        if token is None:
            raise InvalidCredentialsError()
        session_context = await context.session_strategy.read(token)
        if session_context is None:
            raise InvalidCredentialsError()
        return TokenResponse(token=await self.issue_token_for(session_context.user))

    async def jwks_handler(self) -> JwksDocument:
        """``GET /auth/jwks`` — public JWKS document for verifying issued tokens."""
        _context, registry, _signer = self.assert_bound()
        return await registry.as_jwks_json()
