from __future__ import annotations

from typing import cast

import pytest
from pydantic import SecretStr, ValidationError

from fastauth import FastAuth, FastAuthOptions, email_password
from fastauth.api.commands import SignInEmailCommand, SignUpEmailCommand
from fastauth.database import memory
from fastauth.domain.enums import HookPhase, ProviderId
from fastauth.domain.events import UserCreated
from fastauth.domain.models import User
from fastauth.exceptions import DuplicateError, InvalidRequestError
from fastauth.flows.user_management import UpdateUserRequest, update_user
from fastauth.messaging.email import EmailMessage
from fastauth.plugins.email_password import EmailPasswordOptions
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


async def test_create_user_persists_hashed_credential_without_interactive_side_effects() -> None:
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

    @auth.hook(HookPhase.BEFORE_CREATE, target="user")
    async def add_seed_metadata(  # pyright: ignore[reportUnusedFunction]
        hook: HookContext,
    ) -> User:
        user = cast(User, hook.payload)
        return user.model_copy(update={"metadata": {"source": "seed"}})

    @auth.hook(HookPhase.AFTER_CREATE, target="user")
    async def record_created_user(  # pyright: ignore[reportUnusedFunction]
        hook: HookContext,
    ) -> None:
        after_payloads.append(cast(User, hook.payload).id)

    user = await auth.api.create_user(
        email="seed@app.com",
        password="correct-horse-battery",
    )

    assert user.metadata.root == {"source": "seed"}
    assert after_payloads == [user.id.root]


async def test_create_user_publishes_user_created_event() -> None:
    auth = make_auth()
    received: list[UserCreated] = []

    @auth.on(UserCreated)
    async def record_event(  # pyright: ignore[reportUnusedFunction]
        event: UserCreated,
    ) -> None:
        received.append(event)

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


async def test_get_user_supports_exactly_one_safe_selector() -> None:
    auth = make_auth()
    created = await auth.api.create_user(
        email="LOOKUP@app.com",
        username="lookup-user",
        password="correct-horse-battery",
    )

    assert await auth.api.get_user(by_id=created.id) == created
    assert await auth.api.get_user(by_email="lookup@app.com") == created
    assert await auth.api.get_user(by_username="lookup-user") == created
    assert await auth.api.get_user(by_email="missing@app.com") is None

    with pytest.raises(
        InvalidRequestError,
        match="get_user requires exactly one selector",
    ):
        await auth.api.get_user()
    with pytest.raises(
        InvalidRequestError,
        match="get_user requires exactly one selector",
    ):
        await auth.api.get_user(
            by_id=created.id,
            by_email="lookup@app.com",
        )


async def test_email_signup_can_require_username() -> None:
    auth = FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("a" * 64),
            database=memory(),
        ),
        plugins=[
            email_password(EmailPasswordOptions(require_username=True)),
        ],
    )

    with pytest.raises(InvalidRequestError, match="username is required"):
        await auth.api.sign_up.email(
            SignUpEmailCommand(
                email="missing-username@app.com",
                password=SecretStr("correct-horse-battery"),
            )
        )

    response = await auth.api.sign_up.email(
        SignUpEmailCommand(
            email="named@app.com",
            username="named-user",
            password=SecretStr("correct-horse-battery"),
        )
    )
    assert response.user.username == "named-user"


async def test_user_update_can_change_username_and_rekey_lockout() -> None:
    auth = FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("a" * 64),
            database=memory(),
        ),
        plugins=[
            email_password(EmailPasswordOptions(allow_username_change=True)),
        ],
    )
    created = await auth.api.create_user(
        email="rename@app.com",
        username="old-name",
        password="correct-horse-battery",
    )
    adapter = cast(InMemoryAdapter, auth.context.adapter)
    user = await adapter.get_user_by_id(created.id.root)
    assert user is not None
    for _ in range(3):
        await auth.context.lockout_tracker.record_failure("old-name")

    updated = await update_user(
        auth.context,
        user,
        UpdateUserRequest(username="new-name"),
        ip=None,
        user_agent=None,
    )

    assert updated.username == "new-name"
    assert await adapter.get_user_by_username("old-name") is None
    assert await adapter.get_user_by_username("new-name") is not None
    assert await auth.context.lockout_tracker.storage.get("lockout:old-name") is None
    destination = await auth.context.lockout_tracker.storage.get("lockout:new-name")
    assert destination is not None
    assert destination.count == 3


def test_user_update_rejects_explicit_null_username() -> None:
    with pytest.raises(ValidationError, match="username must not be null"):
        UpdateUserRequest.model_validate({"username": None})
