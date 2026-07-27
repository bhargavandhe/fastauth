from __future__ import annotations

from typing import cast

import pytest
from pydantic import SecretStr

from fastauth import FastAuth, FastAuthOptions, email_password
from fastauth.api.commands import SignInEmailCommand
from fastauth.database import memory
from fastauth.domain.enums import HookPhase, ProviderId
from fastauth.domain.events import UserCreated
from fastauth.domain.models import User
from fastauth.exceptions import DuplicateError
from fastauth.messaging.email import EmailMessage
from fastauth.runtime.hooks import HookContext
from fastauth.storage.memory import InMemoryAdapter


class RecordingEmailSender:
    def __init__(self) -> None:
        self.messages: list[EmailMessage] = []

    async def send(self, message: EmailMessage) -> None:
        self.messages.append(message)


def make_auth(*, email_sender: RecordingEmailSender | None = None) -> FastAuth:
    return FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("a" * 64),
            database=memory(),
        ),
        plugins=[email_password()],
        email_sender=email_sender,
    )


async def test_create_user_persists_hashed_credential_without_interactive_side_effects() -> (
    None
):
    sender = RecordingEmailSender()
    auth = make_auth(email_sender=sender)
    adapter = cast(InMemoryAdapter, auth.context.adapter)

    user = await auth.api.create_user(
        email="ADMIN@APP.COM",
        password="correct-horse-battery",
        name="Admin",
        metadata={"role": "admin"},
    )

    stored_user = await adapter.get_user_by_id(user.id.root)
    account = await adapter.get_account_for_user(user.id.root, ProviderId.CREDENTIAL)
    assert stored_user is not None
    assert str(stored_user.email) == "admin@app.com"
    assert stored_user.metadata == {"role": "admin"}
    assert account is not None
    assert account.password is not None
    assert account.password != "correct-horse-battery"
    assert auth.context.password_hasher.verify(
        "correct-horse-battery",
        account.password,
    )
    assert await adapter.list_sessions_for_user(user.id.root) == []
    assert adapter.refresh_tokens == {}
    assert adapter.verifications == {}
    assert sender.messages == []


async def test_create_user_runs_before_and_after_user_hooks() -> None:
    auth = make_auth()
    after_payloads: list[str] = []

    async def add_seed_metadata(hook: HookContext) -> User:
        user = cast(User, hook.payload)
        return user.model_copy(update={"metadata": {"source": "seed"}})

    async def record_created_user(hook: HookContext) -> None:
        after_payloads.append(cast(User, hook.payload).id)

    auth.context.hooks.register(HookPhase.BEFORE_CREATE, "user", add_seed_metadata)
    auth.context.hooks.register(HookPhase.AFTER_CREATE, "user", record_created_user)

    user = await auth.api.create_user(
        email="seed@app.com",
        password="correct-horse-battery",
    )

    assert user.metadata.root == {"source": "seed"}
    assert after_payloads == [user.id.root]


async def test_create_user_publishes_user_created_event() -> None:
    auth = make_auth()
    received: list[UserCreated] = []

    async def record_event(event: UserCreated) -> None:
        received.append(event)

    auth.events.subscribe(UserCreated, record_event)

    user = await auth.api.create_user(
        email="event@app.com",
        password="correct-horse-battery",
    )

    assert [(event.user_id, event.identifier) for event in received] == [
        (user.id.root, "event@app.com")
    ]


async def test_create_user_rejects_duplicate_email_and_username() -> None:
    auth = make_auth()
    await auth.api.create_user(
        email="first@app.com",
        username="same-name",
        password="correct-horse-battery",
    )

    with pytest.raises(DuplicateError):
        await auth.api.create_user(
            email="FIRST@app.com",
            password="correct-horse-battery",
        )
    with pytest.raises(DuplicateError):
        await auth.api.create_user(
            email="second@app.com",
            username="same-name",
            password="correct-horse-battery",
        )


async def test_server_created_user_can_sign_in_normally() -> None:
    auth = make_auth()
    adapter = cast(InMemoryAdapter, auth.context.adapter)
    await auth.api.create_user(
        email="worker@app.com",
        password="correct-horse-battery",
    )
    assert adapter.sessions == {}

    response = await auth.api.sign_in.email(
        SignInEmailCommand(
            email="worker@app.com",
            password=SecretStr("correct-horse-battery"),
        )
    )

    assert str(response.user.email) == "worker@app.com"
