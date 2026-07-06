from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, cast

import pytest
from pydantic import SecretStr, ValidationError

from fastauth import FastAuth, FastAuthOptions
from fastauth.api.commands import (
    BearerCredentialDelivery,
    RequestContext,
    SignInEmailCommand,
    SignUpEmailCommand,
)
from fastauth.api.responses import CredentialsView, SessionView, UserView
from fastauth.domain.models import Session, User
from fastauth.domain.value_objects import (
    ApiKeyId,
    ApiKeyMetadata,
    PermissionSet,
    RawToken,
    SessionId,
    TokenHash,
    UserId,
    UserMetadata,
)
from fastauth.options import (
    AppOptions,
    CookieOptions,
    MemoryDatabaseOptions,
    PostgresDatabaseOptions,
    SessionOptions,
)
from fastauth.plugins.api_key import (
    CreateApiKeyRequest,
    UpdateApiKeyRequest,
    VerifyApiKeyRequest,
)
from fastauth.plugins.base import PluginOptions
from fastauth.plugins.email_password import (
    EmailPasswordOptions,
    EmailPasswordPlugin,
    PasswordPolicy,
)


def test_fastauth_class_is_primary_entrypoint_with_explicit_options() -> None:
    auth = FastAuth(
        options=FastAuthOptions(
            secret_key=SecretStr("a" * 64),
            app=AppOptions.model_validate({"base_url": "https://api.example.com"}),
            database=MemoryDatabaseOptions(),
            session=SessionOptions(expires_in=timedelta(days=7)),
            cookie=CookieOptions(secure=False),
        ),
        plugins=(
            EmailPasswordPlugin(
                options=EmailPasswordOptions(
                    require_email_verification=True,
                    allow_username_sign_in=False,
                    password=PasswordPolicy(min_length=12, max_length=128),
                ),
            ),
        ),
    )

    assert auth.options.database.kind == "memory"
    plugin = cast(EmailPasswordPlugin, auth.plugins[0])
    assert plugin.options.password.min_length == 12


def test_fastauth_options_reject_plugins_and_database_factories_are_not_primary() -> None:
    with pytest.raises(ValidationError):
        FastAuthOptions.model_validate(
            {
                "secret_key": SecretStr("a" * 64),
                "database": {"kind": "memory"},
                "plugins": [],
            },
        )


def test_database_options_are_explicit_discriminated_models() -> None:
    options = FastAuthOptions(
        secret_key=SecretStr("a" * 64),
        database=PostgresDatabaseOptions.model_validate(
            {
                "url": "postgresql+asyncpg://user:pass@localhost:5432/app",
                "table_prefix": "auth_",
                "migration_mode": "check",
            },
        ),
    )

    assert options.database.kind == "postgres"
    assert options.database.table_prefix == "auth_"

    with pytest.raises(ValidationError):
        FastAuthOptions.model_validate(
            {
                "secret_key": SecretStr("a" * 64),
                "database": {
                    "kind": "postgres",
                    "table_prefix": "auth_",
                },
            },
        )


def test_plugin_options_share_enabled_and_are_frozen() -> None:
    options = EmailPasswordOptions()

    assert isinstance(options, PluginOptions)
    assert options.enabled is True

    with pytest.raises(ValidationError):
        options.allow_username_sign_in = False


def test_security_sensitive_value_objects_validate_and_serialize() -> None:
    user_id = UserId("a" * 24)
    session_id = SessionId("b" * 32)
    token_hash = TokenHash("c" * 64)

    assert user_id.root == "a" * 24
    assert user_id.model_dump() == "a" * 24
    assert session_id.model_dump() == "b" * 32
    assert token_hash.model_dump() == "c" * 64

    with pytest.raises(ValidationError):
        UserId("not-an-id")
    with pytest.raises(ValidationError):
        TokenHash("not-a-hash")


def test_domain_models_reject_empty_security_identifiers() -> None:
    with pytest.raises(ValidationError):
        User(id="", email="alice@example.com")

    with pytest.raises(ValidationError):
        Session(user_id="", token_hash="hash", expires_at=datetime.now(UTC))

    with pytest.raises(ValidationError):
        Session(user_id="user", token_hash="", expires_at=datetime.now(UTC))


def test_json_metadata_and_permissions_reject_unserializable_values() -> None:
    metadata = UserMetadata({"theme": "dark", "flags": ["a", "b"]})
    api_key_metadata = ApiKeyMetadata({"billing": {"plan": "pro"}})
    permissions = PermissionSet({"project": frozenset({"read", "write"})})

    assert metadata.root["theme"] == "dark"
    assert api_key_metadata.root["billing"] == {"plan": "pro"}
    assert permissions.root["project"] == frozenset({"read", "write"})

    with pytest.raises(ValidationError):
        UserMetadata({"callback": cast(Any, lambda: None)})


def test_public_response_dtos_use_semantic_value_objects_but_emit_plain_json() -> None:
    created_at = datetime(2029, 1, 1, tzinfo=UTC)
    expires_at = datetime(2030, 1, 1, tzinfo=UTC)
    response = SessionView(
        id=SessionId("b" * 32),
        user_id=UserId("a" * 32),
        expires_at=expires_at,
        created_at=created_at,
        updated_at=created_at,
    )
    user = UserView(
        id=UserId("a" * 32),
        email="alice@example.com",
        email_verified=True,
        metadata=UserMetadata({"theme": "dark"}),
        created_at=created_at,
        updated_at=created_at,
    )
    credentials = CredentialsView(token=RawToken("access-token"))

    assert response.model_dump(mode="json", by_alias=True)["userId"] == "a" * 32
    assert user.model_dump(mode="json")["metadata"] == {"theme": "dark"}
    assert credentials.model_dump(mode="json")["token"] == "access-token"


def test_nested_server_api_shape_is_command_result_based() -> None:
    command = SignInEmailCommand(
        email="alice@example.com",
        password=SecretStr("correct horse battery staple"),
        context=RequestContext(ip_address="127.0.0.1", user_agent="pytest"),
        delivery=BearerCredentialDelivery(include_refresh_token=True),
    )

    assert command.context.ip_address == "127.0.0.1"
    assert command.delivery.kind == "bearer"


def test_auth_api_does_not_expose_flat_email_tuple_methods() -> None:
    auth = FastAuth(
        options=FastAuthOptions(secret_key=SecretStr("a" * 64)),
        plugins=(EmailPasswordPlugin(),),
    )

    assert not hasattr(auth.api, "sign_up_email")
    assert not hasattr(auth.api, "sign_in_email")


def test_api_key_request_models_use_typed_metadata_permissions_and_ids() -> None:
    create = CreateApiKeyRequest(
        name="Deploy key",
        metadata=ApiKeyMetadata({"env": "prod"}),
        permissions=PermissionSet({"deploy": frozenset({"read"})}),
    )
    verify = VerifyApiKeyRequest(
        key=SecretStr("ak_plain"),
        permissions=PermissionSet({"deploy": frozenset({"read"})}),
    )
    update = UpdateApiKeyRequest(
        id=ApiKeyId("a" * 32),
        metadata=ApiKeyMetadata({"rotated": True}),
        permissions=PermissionSet({"deploy": frozenset({"read"})}),
    )

    assert isinstance(create.metadata, ApiKeyMetadata)
    assert isinstance(create.permissions, PermissionSet)
    assert isinstance(verify.permissions, PermissionSet)
    assert update.id.root == "a" * 32
    assert create.model_dump(mode="json")["permissions"] == {"deploy": ["read"]}

    with pytest.raises(ValidationError):
        CreateApiKeyRequest.model_validate(
            {
                "name": "bad",
                "metadata": {"callback": cast(Any, lambda: None)},
            }
        )


async def test_nested_server_api_executes_email_commands() -> None:
    auth = FastAuth(
        options=FastAuthOptions(
            secret_key=SecretStr("a" * 64),
            app=AppOptions.model_validate({"base_url": "https://api.example.com"}),
            database=MemoryDatabaseOptions(),
        ),
        plugins=(EmailPasswordPlugin(),),
    )

    sign_up = await auth.api.sign_up.email(
        SignUpEmailCommand(
            email="alice@example.com",
            password=SecretStr("correct horse battery staple"),
            delivery=BearerCredentialDelivery(),
        ),
    )
    sign_in = await auth.api.sign_in.email(
        SignInEmailCommand(
            email="alice@example.com",
            password=SecretStr("correct horse battery staple"),
            delivery=BearerCredentialDelivery(),
        ),
    )

    assert sign_up.user.email == "alice@example.com"
    assert sign_up.credentials is not None
    assert sign_in.user.id == sign_up.user.id
    assert sign_in.credentials is not None
