from __future__ import annotations

import asyncio
from typing import cast

import pytest
from pydantic import SecretStr

from fastauth import FastAuth, FastAuthOptions, email_password
from fastauth.database import custom
from fastauth.domain.enums import HookPhase, ProviderId
from fastauth.domain.models import Account, Session, User
from fastauth.exceptions import InvalidRequestError
from fastauth.flows.credentials import SignUpEmailRequest, sign_up_email
from fastauth.runtime.hooks import HookContext
from fastauth.storage.memory import InMemoryAdapter


class FailingCreationAdapter(InMemoryAdapter):
    fail_user_after_write = False
    fail_account = False
    fail_session = False
    pause_account = False

    def __init__(self) -> None:
        super().__init__()
        self.account_started = asyncio.Event()
        self.account_release = asyncio.Event()

    async def create_user(self, user: User) -> User:
        created = await super().create_user(user)
        if self.fail_user_after_write:
            raise RuntimeError("user write acknowledged late")
        return created

    async def create_account(self, account: Account) -> Account:
        self.account_started.set()
        if self.pause_account:
            await self.account_release.wait()
        if self.fail_account:
            raise RuntimeError("account write failed")
        return await super().create_account(account)

    async def create_session(self, session: Session) -> Session:
        if self.fail_session:
            raise RuntimeError("session write failed")
        return await super().create_session(session)


def make_auth(adapter: InMemoryAdapter) -> FastAuth:
    return FastAuth(
        FastAuthOptions(secret_key=SecretStr("a" * 64), database=custom(adapter=adapter)),
        plugins=[email_password()],
    )


async def create(auth: FastAuth, path: str, password: str = "correct-horse-battery") -> None:
    if path == "server":
        await auth.api.create_user(email="create@example.com", password=password)
    else:
        await sign_up_email(
            auth.context,
            SignUpEmailRequest(email="create@example.com", password=SecretStr(password)),
            ip=None,
            user_agent=None,
        )


@pytest.mark.parametrize("path", ["server", "signup"])
async def test_invalid_password_leaves_no_identity_and_corrected_retry_succeeds(path: str) -> None:
    adapter = InMemoryAdapter()
    auth = make_auth(adapter)
    with pytest.raises(InvalidRequestError):
        await create(auth, path, "short")
    assert await adapter.get_user_by_email("create@example.com") is None
    assert not adapter.accounts
    assert not adapter.sessions
    await create(auth, path)
    assert await adapter.get_user_by_email("create@example.com") is not None


@pytest.mark.parametrize("path", ["server", "signup"])
async def test_account_failure_compensates_identity_before_corrected_retry(path: str) -> None:
    adapter = FailingCreationAdapter()
    adapter.fail_account = True
    auth = make_auth(adapter)
    with pytest.raises(RuntimeError, match="account write failed"):
        await create(auth, path)
    assert await adapter.get_user_by_email("create@example.com") is None
    adapter.fail_account = False
    await create(auth, path)


async def test_after_create_hook_observes_committed_credential() -> None:
    adapter = InMemoryAdapter()
    auth = make_auth(adapter)
    seen: list[bool] = []

    @auth.hook(HookPhase.AFTER_CREATE, target="user")
    async def observe(hook: HookContext) -> None:
        user = cast(User, hook.payload)
        seen.append(await adapter.get_account_for_user(user.id, ProviderId.CREDENTIAL) is not None)

    await create(auth, "signup")
    assert seen == [True]


async def test_session_failure_preserves_credentialed_identity_for_sign_in() -> None:
    adapter = FailingCreationAdapter()
    adapter.fail_session = True
    auth = make_auth(adapter)
    with pytest.raises(RuntimeError, match="session write failed"):
        await create(auth, "signup")
    user = await adapter.get_user_by_email("create@example.com")
    assert user is not None
    account = await adapter.get_account_for_user(user.id, ProviderId.CREDENTIAL)
    assert account is not None and account.password is not None
    assert not adapter.sessions


@pytest.mark.parametrize("path", ["server", "signup"])
async def test_cancellation_never_strands_identity_without_credential(path: str) -> None:
    adapter = FailingCreationAdapter()
    adapter.pause_account = True
    auth = make_auth(adapter)
    task = asyncio.create_task(create(auth, path))
    await adapter.account_started.wait()
    task.cancel()
    adapter.account_release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    user = await adapter.get_user_by_email("create@example.com")
    assert (
        user is None
        or await adapter.get_account_for_user(user.id, ProviderId.CREDENTIAL) is not None
    )


@pytest.mark.parametrize("path", ["server", "signup"])
async def test_failed_user_insert_acknowledgement_can_be_retried(path: str) -> None:
    adapter = FailingCreationAdapter()
    adapter.fail_user_after_write = True
    auth = make_auth(adapter)
    with pytest.raises(RuntimeError, match="user write acknowledged late"):
        await create(auth, path)
    assert await adapter.get_user_by_email("create@example.com") is None
    adapter.fail_user_after_write = False
    await create(auth, path)
