"""Beanie/MongoDB storage backend for fastauth.

Three submodules:

* :mod:`.adapter` — the :class:`BeanieAdapter` class.
* :mod:`.documents` — :class:`beanie.Document` subclasses + Doc→domain
  converters + ``init_beanie_documents`` startup helper.
* :mod:`.helpers` — datetime/ObjectId conversion utilities shared between
  the adapter and the document layer.

The public API of this package is re-exported here. End users typically
only need :class:`BeanieAdapter` and :func:`init_beanie_documents`; the
document subclasses are useful when extending the schema (e.g. registering
your own Document with the same PyMongo async database).
"""

from __future__ import annotations

from fastauth.storage.beanie.adapter import BeanieAdapter
from fastauth.storage.beanie.documents import (
    DOCUMENT_MODELS,
    AccountDoc,
    ApiKeyDoc,
    AuditLogDoc,
    JwksKeyDoc,
    RateLimitDoc,
    RefreshTokenDoc,
    SessionDoc,
    UserDoc,
    VerificationDoc,
    init_beanie_documents,
    to_account,
    to_api_key,
    to_audit_log,
    to_jwks_key,
    to_rate_limit,
    to_refresh_token,
    to_session,
    to_user,
    to_verification,
)
from fastauth.storage.beanie.helpers import (
    normalise_datetimes,
    to_object_id_or_none,
    truncate_to_millis,
)

__all__ = [
    "DOCUMENT_MODELS",
    "AccountDoc",
    "ApiKeyDoc",
    "AuditLogDoc",
    "BeanieAdapter",
    "JwksKeyDoc",
    "RateLimitDoc",
    "RefreshTokenDoc",
    "SessionDoc",
    "UserDoc",
    "VerificationDoc",
    "init_beanie_documents",
    "normalise_datetimes",
    "to_account",
    "to_api_key",
    "to_audit_log",
    "to_jwks_key",
    "to_object_id_or_none",
    "to_rate_limit",
    "to_refresh_token",
    "to_session",
    "to_user",
    "to_verification",
    "truncate_to_millis",
]
