from __future__ import annotations

from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock

import pytest
from pymongo.asynchronous.database import AsyncDatabase

from fastauth.storage.beanie import documents, migrations


def collection_name(model: Any) -> str:
    return str(model.Settings.name)


def test_default_beanie_document_model_names_remain_unchanged() -> None:
    documents.build_beanie_document_models()

    assert [collection_name(model) for model in documents.DOCUMENT_MODELS] == [
        "users",
        "sessions",
        "refresh_tokens",
        "accounts",
        "verifications",
        "api_keys",
        "jwks_keys",
        "audit_logs",
        "rate_limits",
    ]


def test_build_beanie_document_models_applies_collection_prefix_and_suffix() -> None:
    assert hasattr(documents, "BeanieDocumentModels")
    assert hasattr(documents, "build_beanie_document_models")

    models = documents.build_beanie_document_models(
        collection_prefix="tenant_",
        collection_suffix="_auth",
    )

    assert isinstance(models, documents.BeanieDocumentModels)
    assert collection_name(models.user) == "tenant_users_auth"
    assert collection_name(models.session) == "tenant_sessions_auth"
    assert collection_name(models.refresh_token) == "tenant_refresh_tokens_auth"
    assert collection_name(models.account) == "tenant_accounts_auth"
    assert collection_name(models.verification) == "tenant_verifications_auth"
    assert collection_name(models.api_key) == "tenant_api_keys_auth"
    assert collection_name(models.jwks_key) == "tenant_jwks_keys_auth"
    assert collection_name(models.audit_log) == "tenant_audit_logs_auth"
    assert collection_name(models.rate_limit) == "tenant_rate_limits_auth"


def test_build_beanie_document_models_keeps_public_document_classes() -> None:
    models = documents.build_beanie_document_models(
        collection_prefix="tenant_",
        collection_suffix="_auth",
    )

    assert models.user is documents.UserDoc
    assert models.session is documents.SessionDoc
    assert models.refresh_token is documents.RefreshTokenDoc
    assert models.account is documents.AccountDoc
    assert models.verification is documents.VerificationDoc
    assert models.api_key is documents.ApiKeyDoc
    assert models.jwks_key is documents.JwksKeyDoc
    assert models.audit_log is documents.AuditLogDoc
    assert models.rate_limit is documents.RateLimitDoc


@pytest.mark.anyio
async def test_init_beanie_documents_initializes_public_document_classes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    initialized_models: list[type[Any]] = []

    async def fake_init_beanie(
        *,
        database: AsyncDatabase[Any],
        document_models: list[type[Any]],
    ) -> None:
        del database
        initialized_models.extend(document_models)

    async def fake_preflight(
        database: AsyncDatabase[Any],
        *,
        collection_prefix: str,
        collection_suffix: str,
    ) -> None:
        del database
        assert collection_prefix == "auth_"
        assert collection_suffix == ""

    monkeypatch.setattr(migrations, "preflight_mongo_storage_v015", fake_preflight)
    monkeypatch.setattr(documents, "init_beanie", fake_init_beanie)

    database = MagicMock()
    database.__getitem__.return_value.create_index = AsyncMock()
    await documents.init_beanie_documents(
        cast(AsyncDatabase[Any], database),
        collection_prefix="auth_",
    )

    assert initialized_models == documents.DOCUMENT_MODELS
    assert collection_name(documents.UserDoc) == "auth_users"
    database.__getitem__.assert_called_once_with("auth_refresh_tokens_families")
    assert database.__getitem__.return_value.create_index.await_count == 2


@pytest.mark.parametrize(
    ("prefix", "suffix"),
    [
        ("tenant$", ""),
        ("", "\x00auth"),
        ("system.", ""),
    ],
)
def test_build_beanie_document_models_rejects_invalid_collection_names(
    prefix: str,
    suffix: str,
) -> None:
    with pytest.raises(ValueError, match="Invalid MongoDB collection name"):
        documents.build_beanie_document_models(
            collection_prefix=prefix,
            collection_suffix=suffix,
        )
