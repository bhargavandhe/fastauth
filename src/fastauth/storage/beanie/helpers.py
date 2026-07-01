"""Format-conversion helpers shared between the Beanie adapter and its docs.

These functions are pure utilities — they don't reference any of the
:class:`beanie.Document` classes defined in :mod:`.documents`. Keeping
them here lets `documents` and `adapter` both import without forming a
cycle.
"""

from __future__ import annotations

from datetime import datetime
from typing import get_args

from beanie import Document, PydanticObjectId
from bson import ObjectId
from bson.errors import InvalidId
from pydantic import BaseModel

__all__ = [
    "apply_model_updates",
    "normalise_datetimes",
    "require_object_id",
    "to_object_id_or_none",
    "to_pydantic_object_id_or_none",
    "truncate_to_millis",
]


def truncate_to_millis(value: datetime) -> datetime:
    """Round a datetime to the millisecond, matching BSON's storage resolution."""
    return value.replace(microsecond=(value.microsecond // 1000) * 1000)


def normalise_datetimes(model: BaseModel) -> None:
    """Mutate every datetime field of ``model`` to ms precision.

    BSON stores datetimes at millisecond resolution and strips microseconds.
    Without this normalisation the in-memory model instance passed to
    ``create_*`` no longer equals the document subsequently fetched from
    MongoDB. Pydantic ``validate_assignment=True`` makes the mutation safe.
    """
    for field_name in type(model).model_fields:
        value = getattr(model, field_name)
        if isinstance(value, datetime):
            setattr(model, field_name, truncate_to_millis(value))


def apply_model_updates(doc: Document, model: BaseModel) -> None:
    """Copy validated values from a domain model into a Beanie document.

    Field assignment on the Document re-runs Pydantic validation, so Mongo-owned
    ids declared as ``PydanticObjectId`` stay BSON ObjectIds instead of being
    written back as plain strings.
    """
    data = model.model_dump(exclude={"id"})
    for field_name, value in data.items():
        if field_name in type(doc).model_fields:
            setattr(doc, field_name, coerce_document_value(doc, field_name, value))


def coerce_document_value(doc: Document, field_name: str, value: object) -> object:
    if value is None or not field_stores_object_id(doc, field_name):
        return value
    if isinstance(value, ObjectId):
        return value
    if not isinstance(value, str):
        raise ValueError("expected a Mongo ObjectId hex string")
    return require_object_id(value)


def field_stores_object_id(doc: Document, field_name: str) -> bool:
    current_value = getattr(doc, field_name, None)
    if isinstance(current_value, ObjectId):
        return True
    field = type(doc).model_fields[field_name]
    return annotation_contains(field.annotation, PydanticObjectId)


def annotation_contains(annotation: object, target: type[object]) -> bool:
    if annotation is target:
        return True
    return any(annotation_contains(arg, target) for arg in get_args(annotation))


def to_object_id_or_none(value: str | None) -> ObjectId | None:
    """Return ``ObjectId(value)`` if the string is a valid 24-char hex, else ``None``.

    Used at every adapter boundary that accepts a caller-supplied id string.
    Returning ``None`` for invalid input matches the InMemoryAdapter contract
    (which returns ``None`` for unknown ids rather than raising), keeping the
    two adapters behaviourally interchangeable for the contract tests.
    """
    if value is None:
        return None
    try:
        return ObjectId(value)
    except (InvalidId, TypeError):
        return None


def to_pydantic_object_id_or_none(value: str | None) -> PydanticObjectId | None:
    """Return ``PydanticObjectId(value)`` if valid, else ``None``."""
    oid = to_object_id_or_none(value)
    return PydanticObjectId(str(oid)) if oid is not None else None


def require_object_id(value: str | None) -> ObjectId:
    """Return ``ObjectId(value)`` and raise if the value is missing or invalid."""
    oid = to_object_id_or_none(value)
    if oid is None:
        raise ValueError("expected a Mongo ObjectId hex string")
    return oid
