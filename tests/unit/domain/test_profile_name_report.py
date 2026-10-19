from __future__ import annotations

import pytest
from pydantic import ValidationError

from fastauth.api.commands import SignUpEmailCommand, UpdateUserCommand
from fastauth.flows.credentials import SignUpEmailRequest
from fastauth.flows.user_management import UpdateUserRequest


@pytest.mark.parametrize(
    "model", [SignUpEmailRequest, SignUpEmailCommand, UpdateUserRequest, UpdateUserCommand]
)
@pytest.mark.parametrize(
    "value,expected",
    [("  Alice  ", "Alice"), (" \t\n", None), (None, None), ("x" * 100, "x" * 100)],
)
def test_profile_names_normalize_at_input_boundary(
    model: type[SignUpEmailRequest | SignUpEmailCommand | UpdateUserRequest | UpdateUserCommand],
    value: str | None,
    expected: str | None,
) -> None:
    data: dict[str, object] = {"name": value}
    if model is UpdateUserCommand:
        data["principal"] = {"userId": "a" * 32}
    if model in (SignUpEmailRequest, SignUpEmailCommand):
        data.update(email="a@example.com", password="password123")
    assert model.model_validate(data).name == expected


@pytest.mark.parametrize(
    "model", [SignUpEmailRequest, SignUpEmailCommand, UpdateUserRequest, UpdateUserCommand]
)
@pytest.mark.parametrize("size", [101, 20_000])
def test_profile_names_reject_oversize(
    model: type[SignUpEmailRequest | SignUpEmailCommand | UpdateUserRequest | UpdateUserCommand],
    size: int,
) -> None:
    data: dict[str, object] = {"name": "x" * size}
    if model is UpdateUserCommand:
        data["principal"] = {"userId": "a" * 32}
    if model in (SignUpEmailRequest, SignUpEmailCommand):
        data.update(email="a@example.com", password="password123")
    with pytest.raises(ValidationError):
        model.model_validate(data)
