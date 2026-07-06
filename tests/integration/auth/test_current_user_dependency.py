"""Integration tests for FastAuth.get_current_user / get_current_session dependencies.

The dependencies live on the FastAuth instance so they can capture the bound
``AuthContext`` (its adapter, session strategy, signed-cookie unpacker, etc.)
without forcing the user to wire a factory at every route.

Two compatible call styles for users:

1. ``Depends`` as a default value (works under ``from __future__ import annotations``;
   the ``Depends(...)`` instance is a runtime default, not an annotation):

       async def me(user: User = Depends(auth.get_current_user)) -> User: ...

2. ``Annotated[T, Depends(...)]`` (the modern syntax; works when the route is
   defined in a scope where ``auth`` is a module-level name, OR when
   ``from __future__ import annotations`` is NOT in effect, OR when
   ``Depends(...)`` is wrapped in a module-level type alias):

       CurrentUser = Annotated[User, Depends(auth.get_current_user)]
       async def me(user: CurrentUser) -> User: ...

This test file deliberately uses style (1) because the test file uses
``from __future__ import annotations`` at the top and defines routes inside
a fixture closure (the classical pytest pattern).
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
from fastapi import Depends, FastAPI

from fastauth.domain.models import User
from fastauth.runtime.auth import FastAuth
from fastauth.security.sessions import SessionContext
from fastauth.storage.memory import InMemoryAdapter


@pytest.fixture
async def authed_client(auth: FastAuth) -> AsyncIterator[httpx.AsyncClient]:
    """A FastAPI app with three protected routes + an httpx client."""
    app = FastAPI()
    app.include_router(auth.router)

    @app.get("/me")
    async def me_required(  # pyright: ignore[reportUnusedFunction]
        user: User = Depends(auth.get_current_user),  # noqa: B008
    ) -> dict[str, str]:
        return {"id": user.id, "email": user.email}

    @app.get("/maybe-me")
    async def me_optional(  # pyright: ignore[reportUnusedFunction]
        user: User | None = Depends(auth.get_optional_current_user),  # noqa: B008
    ) -> dict[str, str | None]:
        return {"id": user.id if user else None}

    @app.get("/my-session")
    async def my_session(  # pyright: ignore[reportUnusedFunction]
        session: SessionContext = Depends(auth.get_current_session),  # noqa: B008
    ) -> dict[str, str]:
        return {"user_id": session.user.id, "session_id": session.session.id}

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as http:
        yield http


async def test_current_user_returns_user_when_authenticated(
    authed_client: httpx.AsyncClient,
) -> None:
    sign_up = await authed_client.post(
        "/auth/sign-up/email",
        json={"email": "alice@example.com", "password": "correct-horse-battery"},
    )
    assert sign_up.status_code == 200
    response = await authed_client.get("/me")
    assert response.status_code == 200
    body = response.json()
    assert body["email"] == "alice@example.com"
    assert body["id"] == sign_up.json()["user"]["id"]


async def test_current_user_returns_401_when_anonymous(
    authed_client: httpx.AsyncClient,
) -> None:
    response = await authed_client.get("/me")
    assert response.status_code == 401
    # FastAPI HTTPException wraps the detail under "detail".
    assert response.json()["detail"]["code"] == "INVALID_CREDENTIALS"


async def test_optional_current_user_returns_user_when_authenticated(
    authed_client: httpx.AsyncClient,
) -> None:
    await authed_client.post(
        "/auth/sign-up/email",
        json={"email": "bob@example.com", "password": "correct-horse-battery"},
    )
    response = await authed_client.get("/maybe-me")
    assert response.status_code == 200
    assert response.json()["id"] is not None


async def test_optional_current_user_returns_null_when_anonymous(
    authed_client: httpx.AsyncClient,
) -> None:
    response = await authed_client.get("/maybe-me")
    assert response.status_code == 200
    assert response.json() == {"id": None}


async def test_current_session_exposes_session_context(
    authed_client: httpx.AsyncClient,
) -> None:
    sign_up = await authed_client.post(
        "/auth/sign-up/email",
        json={"email": "carol@example.com", "password": "correct-horse-battery"},
    )
    response = await authed_client.get("/my-session")
    assert response.status_code == 200
    body = response.json()
    assert body["user_id"] == sign_up.json()["user"]["id"]
    assert body["session_id"] == sign_up.json()["session"]["id"]


async def test_current_user_accepts_bearer_token(
    authed_client: httpx.AsyncClient, auth: FastAuth, adapter: InMemoryAdapter
) -> None:
    """Dependency works with Authorization: Bearer in addition to cookies."""
    await authed_client.post(
        "/auth/sign-up/email",
        json={"email": "dan@example.com", "password": "correct-horse-battery"},
    )
    # Re-mint a session against the adapter to get the plain token directly.
    user = await adapter.get_user_by_email("dan@example.com")
    assert user is not None
    session_ctx = await auth.context.session_strategy.create(user, ip=None, user_agent=None)
    authed_client.cookies.clear()
    response = await authed_client.get(
        "/me", headers={"authorization": f"Bearer {session_ctx.token}"}
    )
    assert response.status_code == 200
    assert response.json()["id"] == user.id
