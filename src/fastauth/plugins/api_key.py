"""ApiKeyPlugin: create/verify/manage API keys.

First concrete ``Plugin`` subclass contributing endpoints to the FastAuth router.
Provides the ``/auth/api-key/*`` family of routes for issuing, verifying, listing,
updating, and revoking API keys backed by the ``ApiKey`` model.
"""

from __future__ import annotations

import secrets
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar

from fastapi import Request
from pydantic import BaseModel, ConfigDict, Field

from fastauth.domain.events import ApiKeyCreated, ApiKeyRevoked, ApiKeyVerifyFailed
from fastauth.domain.models import ApiKey, WireModel
from fastauth.exceptions import ConfigError, InvalidCredentialsError, NotFoundError
from fastauth.flows.credentials import EmptyResponse
from fastauth.plugins.base import EndpointSpec, Plugin
from fastauth.runtime.context import AuthContext
from fastauth.security.tokens import TokenService
from fastauth.storage.base import ApiKeyStore

__all__ = [
    "ApiKeyConfig",
    "ApiKeyPlugin",
    "CreateApiKeyRequest",
    "CreateApiKeyResponse",
    "DeleteApiKeyRequest",
    "DeleteExpiredApiKeysResponse",
    "ListApiKeysResponse",
    "UpdateApiKeyRequest",
    "VerifyApiKeyError",
    "VerifyApiKeyRequest",
    "VerifyApiKeyResponse",
    "encode_api_key",
    "split_api_key",
]


class ApiKeyConfig(BaseModel):
    """Static configuration for ``ApiKeyPlugin``.

    All fields are defaults applied when the create request omits the
    corresponding value.
    """

    model_config = ConfigDict(extra="forbid")
    default_prefix: str = "ak_"
    default_remaining: int | None = None
    default_rate_limit_max: int | None = None
    default_rate_limit_window_ms: int | None = None
    default_expires_in_seconds: int | None = None


class CreateApiKeyRequest(WireModel):
    """Request body for ``POST /auth/api-key/create``.

    All numeric quota/interval fields are ``Field(ge=1)`` — a value of ``0``
    on, say, ``expires_in_seconds`` would create a key that's expired-on-arrival,
    and ``remaining=0`` would create a key that's exhausted on first verify. Both
    are user-experience traps when API explorers (Scalar, Swagger UI) prefill
    every numeric field with ``0``. Pass ``null`` or omit the field to opt out
    of the corresponding limit; positive integers are otherwise required.
    """

    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=128)
    remaining: int | None = Field(default=None, ge=1)
    expires_in_seconds: int | None = Field(default=None, ge=1)
    refill_amount: int | None = Field(default=None, ge=1)
    refill_interval_ms: int | None = Field(default=None, ge=1)
    rate_limit_max: int | None = Field(default=None, ge=1)
    rate_limit_window_ms: int | None = Field(default=None, ge=1)
    metadata: dict[str, Any] = Field(default_factory=dict)
    permissions: dict[str, list[str]] = Field(default_factory=dict)


class CreateApiKeyResponse(WireModel):
    api_key: ApiKey
    key: str


class VerifyApiKeyRequest(WireModel):
    model_config = ConfigDict(extra="forbid")
    key: str
    permissions: dict[str, list[str]] | None = None


class VerifyApiKeyError(WireModel):
    code: str
    message: str


class VerifyApiKeyResponse(WireModel):
    valid: bool
    api_key: ApiKey | None = None
    error: VerifyApiKeyError | None = None


class UpdateApiKeyRequest(WireModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    name: str | None = None
    enabled: bool | None = None
    metadata: dict[str, Any] | None = None
    permissions: dict[str, list[str]] | None = None


class DeleteApiKeyRequest(WireModel):
    model_config = ConfigDict(extra="forbid")
    id: str


class ListApiKeysResponse(WireModel):
    items: list[ApiKey]
    total: int
    limit: int
    offset: int


class DeleteExpiredApiKeysResponse(WireModel):
    """Response payload for ``POST /auth/api-key/delete-all-expired``."""

    model_config = ConfigDict(extra="forbid")
    deleted: int


def encode_api_key(prefix: str, plain: str) -> str:
    """Compose a user-facing API key by prepending ``prefix`` to ``plain``."""
    return f"{prefix}{plain}"


def split_api_key(value: str, prefix: str) -> str | None:
    """Return the plain portion of an API key, or ``None`` if the prefix mismatches."""
    if not value.startswith(prefix):
        return None
    return value[len(prefix) :]


class ApiKeyPlugin(Plugin):
    """Plugin contributing endpoints for issuing and verifying API keys."""

    id: ClassVar[str] = "fastauth-api-key"

    def __init__(self, config: ApiKeyConfig | None = None) -> None:
        self.config = config or ApiKeyConfig()
        self.context: AuthContext | None = None
        self.store: ApiKeyStore | None = None

    def bind(self, context: AuthContext) -> None:
        """Attach the assembled ``AuthContext``. Called by ``FastAuth.__init__``."""
        if not isinstance(context.adapter, ApiKeyStore):
            raise ConfigError(message="ApiKeyPlugin requires an adapter implementing ApiKeyStore")
        self.context = context
        self.store = context.adapter

    def assert_bound(self) -> AuthContext:
        """Return the bound ``AuthContext`` or raise if ``bind`` was never invoked."""
        if self.context is None:
            raise RuntimeError("ApiKeyPlugin is not bound to an AuthContext")
        return self.context

    def assert_store(self) -> ApiKeyStore:
        """Return the bound API-key store or raise if ``bind`` was never invoked."""
        if self.store is None:
            raise RuntimeError("ApiKeyPlugin is not bound to an ApiKeyStore")
        return self.store

    async def current_user_id(self, request: Request) -> str:
        """Resolve the authenticated user via the session strategy.

        The import is local to avoid a circular dependency between
        ``fastauth.web.fastapi`` and ``fastauth.plugins.api_key``.
        """
        from fastauth.web.fastapi import extract_session_token

        context = self.assert_bound()
        token = extract_session_token(request, context)
        if token is None:
            raise InvalidCredentialsError()
        session_context = await context.session_strategy.read(token)
        if session_context is None:
            raise InvalidCredentialsError()
        return session_context.user.id

    def endpoints(self) -> Sequence[EndpointSpec]:
        return [
            EndpointSpec(
                method="POST",
                path="/api-key/create",
                name="api_key_create",
                tags=["ApiKey"],
                handler=self.create_handler,
                response_model=CreateApiKeyResponse,
            ),
            EndpointSpec(
                method="POST",
                path="/api-key/verify",
                name="api_key_verify",
                tags=["ApiKey"],
                handler=self.verify_handler,
                response_model=VerifyApiKeyResponse,
            ),
            EndpointSpec(
                method="GET",
                path="/api-key/list",
                name="api_key_list",
                tags=["ApiKey"],
                handler=self.list_handler,
                response_model=ListApiKeysResponse,
            ),
            EndpointSpec(
                method="POST",
                path="/api-key/update",
                name="api_key_update",
                tags=["ApiKey"],
                handler=self.update_handler,
                response_model=ApiKey,
            ),
            EndpointSpec(
                method="POST",
                path="/api-key/delete",
                name="api_key_delete",
                tags=["ApiKey"],
                handler=self.delete_handler,
                response_model=EmptyResponse,
            ),
            EndpointSpec(
                method="POST",
                path="/api-key/delete-all-expired",
                name="api_key_delete_expired",
                tags=["ApiKey"],
                handler=self.delete_expired_handler,
                response_model=DeleteExpiredApiKeysResponse,
            ),
        ]

    # ----- handlers -----
    async def create_handler(
        self,
        body: CreateApiKeyRequest,
        request: Request,
    ) -> CreateApiKeyResponse:
        context = self.assert_bound()
        store = self.assert_store()
        user_id = await self.current_user_id(request)
        plain = secrets.token_urlsafe(32)
        prefix = self.config.default_prefix
        full_key = encode_api_key(prefix, plain)
        rate_limit_max = body.rate_limit_max or self.config.default_rate_limit_max
        rate_limit_window_ms = body.rate_limit_window_ms or self.config.default_rate_limit_window_ms
        expires_in_seconds = (
            body.expires_in_seconds
            if body.expires_in_seconds is not None
            else self.config.default_expires_in_seconds
        )
        api_key = ApiKey(
            user_id=user_id,
            name=body.name,
            key_hash=TokenService().hash_only(plain),
            key_prefix=prefix,
            remaining=(
                body.remaining if body.remaining is not None else self.config.default_remaining
            ),
            refill_amount=body.refill_amount,
            refill_interval_ms=body.refill_interval_ms,
            rate_limit_max=rate_limit_max,
            rate_limit_window_ms=rate_limit_window_ms,
            rate_limit_enabled=bool(rate_limit_max),
            expires_at=(
                datetime.now(UTC) + timedelta(seconds=expires_in_seconds)
                if expires_in_seconds
                else None
            ),
            metadata=body.metadata,
            permissions=body.permissions,
        )
        await store.create_api_key(api_key)
        await context.event_bus.publish(
            ApiKeyCreated(user_id=user_id, api_key_id=api_key.id),
        )
        return CreateApiKeyResponse(api_key=api_key, key=full_key)

    async def verify_handler(self, body: VerifyApiKeyRequest) -> VerifyApiKeyResponse:
        context = self.assert_bound()
        store = self.assert_store()
        plain = split_api_key(body.key, self.config.default_prefix)
        if plain is None:
            await context.event_bus.publish(
                ApiKeyVerifyFailed(identifier=body.key[:8]),
            )
            return VerifyApiKeyResponse(
                valid=False,
                error=VerifyApiKeyError(code="INVALID_KEY", message="prefix mismatch"),
            )

        api_key = await store.get_api_key_by_hash(TokenService().hash_only(plain))
        if api_key is None or not api_key.enabled:
            await context.event_bus.publish(
                ApiKeyVerifyFailed(identifier=body.key[:8]),
            )
            return VerifyApiKeyResponse(
                valid=False,
                error=VerifyApiKeyError(code="INVALID_KEY", message="unknown key"),
            )

        now = datetime.now(UTC)

        if api_key.expires_at is not None and api_key.expires_at < now:
            await context.event_bus.publish(
                ApiKeyVerifyFailed(identifier=body.key[:8]),
            )
            return VerifyApiKeyResponse(
                valid=False,
                error=VerifyApiKeyError(code="API_KEY_EXPIRED", message="expired"),
            )

        # Refill remaining quota if the refill interval has elapsed.
        if (
            api_key.refill_amount is not None
            and api_key.refill_interval_ms is not None
            and api_key.last_refill_at is not None
        ):
            elapsed_ms = (now - api_key.last_refill_at).total_seconds() * 1000
            if elapsed_ms >= api_key.refill_interval_ms:
                api_key.remaining = api_key.refill_amount
                api_key.last_refill_at = now

        if api_key.remaining is not None:
            if api_key.remaining <= 0:
                api_key.request_count += 1
                api_key.last_request_at = now
                await store.update_api_key(api_key)
                await context.event_bus.publish(
                    ApiKeyVerifyFailed(identifier=body.key[:8]),
                )
                return VerifyApiKeyResponse(
                    valid=False,
                    error=VerifyApiKeyError(
                        code="API_KEY_EXHAUSTED",
                        message="no quota left",
                    ),
                )
            api_key.remaining -= 1

        api_key.request_count += 1
        api_key.last_request_at = now
        await store.update_api_key(api_key)

        if body.permissions:
            missing: dict[str, list[str]] = {}
            for resource, actions in body.permissions.items():
                granted = set(api_key.permissions.get(resource, []))
                missing_actions = [action for action in actions if action not in granted]
                if missing_actions:
                    missing[resource] = missing_actions
            if missing:
                await context.event_bus.publish(
                    ApiKeyVerifyFailed(identifier=body.key[:8]),
                )
                return VerifyApiKeyResponse(
                    valid=False,
                    error=VerifyApiKeyError(
                        code="INSUFFICIENT_PERMISSIONS",
                        message=str(missing),
                    ),
                )

        return VerifyApiKeyResponse(valid=True, api_key=api_key)

    async def list_handler(
        self,
        request: Request,
        limit: int = 50,
        offset: int = 0,
    ) -> ListApiKeysResponse:
        self.assert_bound()
        store = self.assert_store()
        user_id = await self.current_user_id(request)
        items, total = await store.list_api_keys_for_user(
            user_id,
            limit=limit,
            offset=offset,
        )
        return ListApiKeysResponse(items=items, total=total, limit=limit, offset=offset)

    async def update_handler(
        self,
        body: UpdateApiKeyRequest,
        request: Request,
    ) -> ApiKey:
        self.assert_bound()
        store = self.assert_store()
        user_id = await self.current_user_id(request)
        api_key = await store.get_api_key_by_id(body.id)
        if api_key is None or api_key.user_id != user_id:
            raise NotFoundError(resource="api_key")
        if body.name is not None:
            api_key.name = body.name
        if body.enabled is not None:
            api_key.enabled = body.enabled
        if body.metadata is not None:
            api_key.metadata = body.metadata
        if body.permissions is not None:
            api_key.permissions = body.permissions
        await store.update_api_key(api_key)
        return api_key

    async def delete_handler(
        self,
        body: DeleteApiKeyRequest,
        request: Request,
    ) -> EmptyResponse:
        context = self.assert_bound()
        store = self.assert_store()
        user_id = await self.current_user_id(request)
        api_key = await store.get_api_key_by_id(body.id)
        if api_key is None or api_key.user_id != user_id:
            raise NotFoundError(resource="api_key")
        await store.delete_api_key(api_key.id)
        await context.event_bus.publish(
            ApiKeyRevoked(user_id=user_id, api_key_id=api_key.id),
        )
        return EmptyResponse(success=True)

    async def delete_expired_handler(self) -> DeleteExpiredApiKeysResponse:
        self.assert_bound()
        count = await self.assert_store().delete_expired_api_keys()
        return DeleteExpiredApiKeysResponse(deleted=count)
