"""An already-authorized HTTP profile write cannot undo completed suspension."""

import asyncio

import httpx
from fastapi import FastAPI
from pydantic import SecretStr

from fastauth import FastAuth, email_password
from fastauth.database import custom
from fastauth.domain.models import User
from fastauth.domain.value_objects import UserId
from fastauth.options import CsrfOptions, FastAuthOptions, PasswordOptions, RateLimitOptions
from fastauth.storage.memory import InMemoryAdapter


class PausedProfileAdapter(InMemoryAdapter):
    """Pause only the actual profile write, leaving status storage unmodified."""

    def __init__(self) -> None:
        super().__init__()
        self.profile_ready = asyncio.Event()
        self.resume_profile = asyncio.Event()

    async def update_user(self, user: User) -> User:
        if user.name == "racing profile":
            assert user.active is True  # The request captured the pre-suspension user.
            self.profile_ready.set()
            await self.resume_profile.wait()
        return await super().update_user(user)


async def test_http_stale_profile_cannot_reactivate_suspended_user() -> None:
    adapter = PausedProfileAdapter()
    auth = FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("r" * 64),
            database=custom(adapter=adapter),
            password=PasswordOptions(argon2_time_cost=1, argon2_memory_cost_kib=8192),
            rate_limit=RateLimitOptions(enabled=False),
            csrf=CsrfOptions(enabled=False),
        ),
        plugins=[email_password()],
    )
    app = FastAPI()
    app.include_router(auth.router, prefix="/auth")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        signup = await client.post(
            "/auth/sign-up/email",
            json={
                "email": "race@example.com",
                "password": "Password123!",
                "delivery": {"kind": "bearer"},
            },
        )
        assert signup.status_code == 200
        body = signup.json()
        uid = UserId(body["user"]["id"])
        token = body["credentials"]["token"]
        profile = asyncio.create_task(
            client.patch(
                "/auth/user",
                headers={"Authorization": f"Bearer {token}"},
                json={"name": "racing profile"},
            )
        )
        try:
            await asyncio.wait_for(adapter.profile_ready.wait(), timeout=5)
            suspended = await auth.policy.set_active(uid, active=False, reason="admin suspension")
            assert suspended.active is False
            stored = await adapter.get_user_by_id(uid.root)
            assert stored is not None and stored.active is False
        finally:
            adapter.resume_profile.set()
        response = await asyncio.wait_for(profile, timeout=5)
        assert response.status_code == 200
        assert response.json()["name"] == "racing profile"
        assert response.json()["active"] is False
        stored = await adapter.get_user_by_id(uid.root)
        assert stored is not None and stored.active is False
        assert stored.name == "racing profile"
        login = await client.post(
            "/auth/sign-in/email", json={"email": "race@example.com", "password": "Password123!"}
        )
        assert login.status_code == 403
        assert login.json()["code"] == "POLICY_DENIED"
        assert (
            await client.patch(
                "/auth/user",
                headers={"Authorization": f"Bearer {token}"},
                json={"name": "later request"},
            )
        ).status_code == 401
