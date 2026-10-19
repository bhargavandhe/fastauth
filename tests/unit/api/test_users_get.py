from __future__ import annotations

import pytest
from pydantic import SecretStr, ValidationError

from fastauth import FastAuth, FastAuthOptions
from fastauth.api.responses import UserView
from fastauth.database import memory
from fastauth.exceptions import InvalidRequestError


def make_auth() -> FastAuth:
    return FastAuth(FastAuthOptions(secret_key=SecretStr("a" * 64), database=memory()))


async def test_users_get_returns_safe_view_for_each_selector() -> None:
    auth = make_auth()
    created = await auth.api.create_user(
        email="member@example.com", username="member", password="correct-horse-battery"
    )
    for found in (
        await auth.users.get(by_id=created.id),
        await auth.users.get(by_id=created.id.root),
        await auth.users.get(by_email="MEMBER@EXAMPLE.COM"),
        await auth.users.get(by_username="member"),
    ):
        assert isinstance(found, UserView)
        assert found == created
        assert set(found.model_dump()) == {
            "id",
            "email",
            "username",
            "name",
            "image",
            "emailVerified",
            "active",
            "metadata",
            "createdAt",
            "updatedAt",
        }
    assert await auth.users.get(by_email="member@example.com") == await auth.api.get_user(
        by_email="member@example.com"
    )
    assert await auth.context.adapter.list_sessions_for_user(created.id.root) == []


async def test_users_get_returns_none_for_missing_users() -> None:
    auth = make_auth()
    assert await auth.users.get(by_id="00000000000000000000000000000000") is None
    assert await auth.users.get(by_email="missing@example.com") is None
    assert await auth.users.get(by_username="missing") is None


async def test_users_get_requires_exactly_one_selector() -> None:
    auth = make_auth()
    with pytest.raises(InvalidRequestError, match="get_user requires exactly one selector"):
        await auth.users.get()
    with pytest.raises(InvalidRequestError, match="get_user requires exactly one selector"):
        await auth.users.get(by_id="member", by_email="member@example.com")


@pytest.mark.parametrize("email", ["", "not-an-email"])
async def test_users_get_validates_email(email: str) -> None:
    with pytest.raises(ValidationError):
        await make_auth().users.get(by_email=email)
