from typing import cast

import httpx
from fastapi import FastAPI

from fastauth.api.responses import UserView
from fastauth.runtime.auth import FastAuth
from fastauth.security.sessions import SessionContext


async def test_current_user_alias_resolves_authenticated_user(auth: FastAuth) -> None:
    app = FastAPI()
    app.include_router(auth.router, prefix=auth.context.config.app.base_path)
    auth.add_middleware(app)

    @app.get("/me")
    async def me(  # pyright: ignore[reportUnusedFunction]
        user: auth.CurrentUser,  # pyright: ignore[reportInvalidTypeForm, reportUnknownMemberType, reportUnknownParameterType]
    ) -> UserView:
        return cast(UserView, user)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        sign_up = await client.post(
            "/auth/sign-up/email",
            json={
                "email": "alias-user@app.com",
                "password": "correct-horse-battery",
            },
        )
        response = await client.get("/me")

    assert response.status_code == 200
    assert response.json()["id"] == sign_up.json()["user"]["id"]


async def test_current_user_alias_rejects_anonymous_request(auth: FastAuth) -> None:
    app = FastAPI()
    app.include_router(auth.router, prefix=auth.context.config.app.base_path)
    auth.add_middleware(app)

    @app.get("/me")
    async def me(  # pyright: ignore[reportUnusedFunction]
        user: auth.CurrentUser,  # pyright: ignore[reportInvalidTypeForm, reportUnknownMemberType, reportUnknownParameterType]
    ) -> UserView:
        return cast(UserView, user)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        response = await client.get("/me")

    assert response.status_code == 401
    assert response.json() == {
        "code": "INVALID_CREDENTIALS",
        "message": "authentication required",
    }


async def test_current_session_alias_resolves_authenticated_session(auth: FastAuth) -> None:
    app = FastAPI()
    app.include_router(auth.router, prefix=auth.context.config.app.base_path)
    auth.add_middleware(app)

    @app.get("/my-session")
    async def my_session(  # pyright: ignore[reportUnusedFunction]
        session: auth.CurrentSession,  # pyright: ignore[reportInvalidTypeForm, reportUnknownMemberType, reportUnknownParameterType]
    ) -> dict[str, str]:
        session_context = cast(SessionContext, session)
        return {
            "session_id": session_context.session.id,
            "user_id": session_context.user.id,
        }

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        sign_up = await client.post(
            "/auth/sign-up/email",
            json={
                "email": "alias-session@app.com",
                "password": "correct-horse-battery",
            },
        )
        response = await client.get("/my-session")

    assert response.status_code == 200
    assert response.json()["session_id"] == sign_up.json()["session"]["id"]
    assert response.json()["user_id"] == sign_up.json()["user"]["id"]


async def test_current_session_alias_rejects_anonymous_request(auth: FastAuth) -> None:
    app = FastAPI()
    app.include_router(auth.router, prefix=auth.context.config.app.base_path)
    auth.add_middleware(app)

    @app.get("/my-session")
    async def my_session(  # pyright: ignore[reportUnusedFunction]
        session: auth.CurrentSession,  # pyright: ignore[reportInvalidTypeForm, reportUnknownMemberType, reportUnknownParameterType]
    ) -> dict[str, str]:
        session_context = cast(SessionContext, session)
        return {
            "session_id": session_context.session.id,
            "user_id": session_context.user.id,
        }

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        response = await client.get("/my-session")

    assert response.status_code == 401
    assert response.json() == {
        "code": "INVALID_CREDENTIALS",
        "message": "authentication required",
    }
