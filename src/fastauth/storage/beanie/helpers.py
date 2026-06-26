"""Format-conversion helpers shared between the Beanie adapter and its docs.

These functions are pure utilities — they don't reference any of the
:class:`beanie.Document` subclasses defined in :mod:`.documents`. Keeping
them here lets `documents` and `adapter` both import without forming a
cycle.
"""

from __future__ import annotations

from datetime import datetime

from bson import ObjectId
from bson.errors import InvalidId
from pydantic import BaseModel

__all__ = ["normalise_datetimes", "to_object_id_or_none", "truncate_to_millis"]


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
