"""Shared input coercion helpers for public SDK managers."""

from __future__ import annotations

from fastauth.domain.value_objects import SessionId, UserId

__all__ = [
    "SessionIdInput",
    "UserIdInput",
    "to_session_id",
    "to_user_id",
]

UserIdInput = UserId | str
SessionIdInput = SessionId | str


def to_user_id(value: UserIdInput) -> UserId:
    if isinstance(value, UserId):
        return value
    return UserId(value)


def to_session_id(value: SessionIdInput) -> SessionId:
    if isinstance(value, SessionId):
        return value
    return SessionId(value)
