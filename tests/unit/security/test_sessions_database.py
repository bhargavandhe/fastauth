from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from fastauth.domain.models import User
from fastauth.options import SessionOptions
from fastauth.security.sessions import DatabaseSessionStrategy, SessionContext
from fastauth.security.tokens import TokenService
from fastauth.storage.memory import InMemoryAdapter


@pytest.fixture
async def strategy() -> DatabaseSessionStrategy:
    adapter = InMemoryAdapter()
    return DatabaseSessionStrategy(adapter, TokenService(), SessionOptions())


@pytest.fixture
async def user(strategy: DatabaseSessionStrategy) -> User:
    return await strategy.adapter.create_user(User(email="alice@example.com"))


async def test_create_and_read_round_trip(
    strategy: DatabaseSessionStrategy,
    user: User,
) -> None:
    context = await strategy.create(user, ip="127.0.0.1", user_agent="pytest")
    assert isinstance(context, SessionContext)
    assert context.session.user_id == user.id
    assert context.session.token_hash != context.token  # stored hashed, not plain

    fetched = await strategy.read(context.token)
    assert fetched is not None
    assert fetched.session.id == context.session.id
    assert fetched.user.id == user.id


async def test_read_returns_none_for_unknown(strategy: DatabaseSessionStrategy) -> None:
    assert await strategy.read("does-not-exist") is None


async def test_read_returns_none_when_expired(
    strategy: DatabaseSessionStrategy,
    user: User,
) -> None:
    context = await strategy.create(user, ip=None, user_agent=None)
    context.session.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    await strategy.adapter.update_session(context.session)
    assert await strategy.read(context.token) is None


async def test_read_returns_none_when_idle_timeout_elapsed() -> None:
    adapter = InMemoryAdapter()
    strategy = DatabaseSessionStrategy(
        adapter,
        TokenService(),
        SessionOptions(idle_timeout=timedelta(minutes=5)),
    )
    user = await adapter.create_user(User(email="idle@example.com"))
    context = await strategy.create(user, ip=None, user_agent=None)
    adapter.sessions[context.session.id].updated_at = datetime.now(UTC) - timedelta(minutes=6)

    assert await strategy.read(context.token) is None


async def test_read_refreshes_idle_activity_timestamp() -> None:
    adapter = InMemoryAdapter()
    strategy = DatabaseSessionStrategy(
        adapter,
        TokenService(),
        SessionOptions(idle_timeout=timedelta(minutes=5)),
    )
    user = await adapter.create_user(User(email="active@example.com"))
    context = await strategy.create(user, ip=None, user_agent=None)
    adapter.sessions[context.session.id].updated_at = datetime.now(UTC) - timedelta(minutes=2)

    read = await strategy.read(context.token)

    assert read is not None
    assert read.session.updated_at > context.session.created_at


async def test_revoke_and_revoke_all(
    strategy: DatabaseSessionStrategy,
    user: User,
) -> None:
    one = await strategy.create(user, ip=None, user_agent=None)
    two = await strategy.create(user, ip=None, user_agent=None)
    await strategy.revoke(one.token)
    assert await strategy.read(one.token) is None
    assert await strategy.read(two.token) is not None
    revoked = await strategy.revoke_all(user.id)
    assert revoked == 1
    assert await strategy.read(two.token) is None


async def test_rotate_issues_new_token(
    strategy: DatabaseSessionStrategy,
    user: User,
) -> None:
    context = await strategy.create(user, ip=None, user_agent=None)
    rotated = await strategy.rotate(context.token)
    assert rotated is not None
    assert rotated.token != context.token
    assert await strategy.read(context.token) is None
    assert await strategy.read(rotated.token) is not None
