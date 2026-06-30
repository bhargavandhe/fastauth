from __future__ import annotations

from typing import Any

import pytest

from fastauth.storage.beanie import documents


def collection_name(model: Any) -> str:
    return str(model.Settings.name)


def test_default_beanie_document_model_names_remain_unchanged() -> None:
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
