"""Logout must revoke a refresh successor created while session policy awaits."""

import asyncio

from pydantic import SecretStr

from fastauth import FastAuth, FastAuthOptions, email_password
from fastauth.api.commands import BearerCredentialDelivery
from fastauth.database import custom
from fastauth.flows.credentials import SignUpEmailRequest, sign_out, sign_up_email
from fastauth.flows.refresh import RefreshTokenRequest, refresh_session
from fastauth.options import RefreshTokenOptions
from fastauth.security.policy import PolicyDecision, PolicyRequest
from fastauth.storage.memory import InMemoryAdapter


async def test_logout_revokes_database_session_created_by_concurrent_refresh() -> None:
    entered, release = asyncio.Event(), asyncio.Event()

    async def policy(request: PolicyRequest) -> PolicyDecision:
        if request.action == "session.read" and not release.is_set():
            entered.set()
            await release.wait()
        return PolicyDecision()

    adapter = InMemoryAdapter()
    auth = FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("a" * 64),
            database=custom(adapter=adapter),
            refresh_token=RefreshTokenOptions(enabled=True),
        ),
        plugins=[email_password()],
        policy_hook=policy,
    )
    response, initial = await sign_up_email(
        auth.context,
        SignUpEmailRequest(
            email="logout-race@example.com",
            password=SecretStr("correct-horse-battery"),
            delivery=BearerCredentialDelivery(),
        ),
        ip=None,
        user_agent=None,
    )
    assert response.credentials is not None and response.credentials.refresh_token is not None
    logout = asyncio.create_task(sign_out(auth.context, initial.token))
    try:
        await asyncio.wait_for(entered.wait(), timeout=10)
        refreshed, replacement = await refresh_session(
            auth.context,
            RefreshTokenRequest(refresh_token=SecretStr(response.credentials.refresh_token.root)),
            ip=None,
            user_agent=None,
        )
        assert refreshed.credentials is not None
        assert replacement.session.id != initial.session.id
        assert await adapter.get_session_by_token_hash(initial.session.token_hash) is None
        assert await adapter.get_session_by_token_hash(replacement.session.token_hash) is not None
    finally:
        release.set()
        result = await asyncio.wait_for(logout, timeout=10)

    assert result.success
    assert await auth.context.session_strategy.read(replacement.token) is None
    assert not adapter.refresh_tokens
    assert not await adapter.list_sessions_for_user(initial.user.id)
