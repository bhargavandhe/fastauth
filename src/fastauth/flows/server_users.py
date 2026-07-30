"""Trusted server-side user provisioning without interactive auth side effects."""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

from pydantic import EmailStr, JsonValue, SecretStr, TypeAdapter

from fastauth.api.responses import UserView, user_view
from fastauth.domain.enums import HookPhase, ProviderId
from fastauth.domain.events import UserCreated
from fastauth.domain.models import Account, User
from fastauth.domain.value_objects import UserId, UserMetadata, Username, normalize_email
from fastauth.exceptions import InvalidRequestError
from fastauth.flows.credentials import validate_password_policy
from fastauth.runtime.context import AuthContext

__all__ = ["create_user", "get_user"]


async def get_user(
    context: AuthContext,
    *,
    by_id: UserId | str | None = None,
    by_email: EmailStr | str | None = None,
    by_username: Username | str | None = None,
) -> UserView | None:
    """Read one user by exactly one selector from trusted server code."""
    selectors = (by_id, by_email, by_username)
    if sum(value is not None for value in selectors) != 1:
        raise InvalidRequestError(message="get_user requires exactly one selector")

    if by_id is not None:
        user_id = by_id if isinstance(by_id, UserId) else UserId.model_validate(by_id)
        user = await context.adapter.get_user_by_id(user_id.root)
    elif by_email is not None:
        email = cast(str, TypeAdapter(EmailStr).validate_python(normalize_email(by_email)))
        user = await context.adapter.get_user_by_email(email)
    else:
        assert by_username is not None
        username = cast(str, TypeAdapter(Username).validate_python(by_username))
        user = await context.adapter.get_user_by_username(username)
    return user_view(user) if user is not None else None


async def create_user(
    context: AuthContext,
    *,
    email: EmailStr | str,
    password: SecretStr | str,
    name: str | None = None,
    username: Username | str | None = None,
    metadata: UserMetadata | Mapping[str, JsonValue] | None = None,
) -> UserView:
    """Provision a credential user without creating a session or sending email."""
    secret = password if isinstance(password, SecretStr) else SecretStr(password)
    metadata_value = metadata.root if isinstance(metadata, UserMetadata) else dict(metadata or {})
    user = User.model_validate(
        {
            "email": email,
            "name": name,
            "username": username,
            "metadata": metadata_value,
        }
    )
    user = await context.hooks.run(
        HookPhase.BEFORE_CREATE,
        "user",
        user,
        actor_user_id=None,
    )
    user = await context.adapter.create_user(user)
    account = Account(
        user_id=user.id,
        provider_id=ProviderId.CREDENTIAL,
        account_id=user.id,
        password=context.password_hasher.hash(
            validate_password_policy(context, secret),
        ),
    )
    await context.adapter.create_account(account)
    await context.hooks.run(
        HookPhase.AFTER_CREATE,
        "user",
        user,
        actor_user_id=user.id,
    )
    await context.event_bus.publish(
        UserCreated(
            user_id=user.id,
            identifier=str(user.email),
        )
    )
    return user_view(user)
