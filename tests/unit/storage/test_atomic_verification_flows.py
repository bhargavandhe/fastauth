from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import SecretStr

from fastauth import FastAuth, FastAuthOptions, email_password
from fastauth.database import custom
from fastauth.domain.enums import ProviderId, VerificationPurpose
from fastauth.domain.models import Account, User, Verification
from fastauth.exceptions import ConfigError, TokenInvalidError
from fastauth.flows.change_email import ConfirmEmailChangeRequest, confirm_email_change
from fastauth.flows.email_otp import CheckOtpRequest, EmailOtpPurpose, check_otp, consume_otp
from fastauth.flows.password_reset import ResetPasswordRequest, reset_password
from fastauth.flows.user_management import DeleteAccountConfirmRequest, confirm_delete_account
from fastauth.flows.verification import VerifyEmailRequest, verify_email
from fastauth.plugins.email_otp_options import EmailOtpOptions
from fastauth.security.otp import OtpService
from fastauth.storage.base import BaseDatabaseAdapter
from fastauth.storage.memory import InMemoryAdapter


class IndependentReadAdapter(InMemoryAdapter):
    def __init__(self, participants: int) -> None:
        super().__init__()
        self.read_barrier = asyncio.Barrier(participants)

    async def get_active_verification(
        self,
        identifier: str,
        purpose: VerificationPurpose,
    ) -> Verification | None:
        row = await super().get_active_verification(identifier, purpose)
        copy = row.model_copy(deep=True) if row is not None else None
        await self.read_barrier.wait()
        return copy

    async def get_verification(
        self,
        identifier: str,
        purpose: VerificationPurpose,
        value_hash: str,
    ) -> Verification | None:
        row = await super().get_verification(identifier, purpose, value_hash)
        copy = row.model_copy(deep=True) if row is not None else None
        await self.read_barrier.wait()
        return copy


def make_auth(adapter: InMemoryAdapter) -> FastAuth:
    return FastAuth(
        FastAuthOptions(
            secret_key=SecretStr("a" * 64),
            database=custom(adapter=adapter),
        ),
        plugins=[email_password()],
    )


async def test_otp_flow_consumes_once_despite_independent_concurrent_reads() -> None:
    adapter = IndependentReadAdapter(2)
    auth = make_auth(adapter)
    otp = OtpService()
    await adapter.create_verification(
        Verification(
            identifier="otp@example.com",
            purpose=VerificationPurpose.EMAIL_OTP_SIGN_IN,
            value_hash=otp.hash_only("123456"),
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )
    )
    results = await asyncio.gather(
        *(
            consume_otp(
                auth.context,
                config=EmailOtpOptions(max_attempts=3),
                otp_service=otp,
                identifier="otp@example.com",
                purpose=VerificationPurpose.EMAIL_OTP_SIGN_IN,
                plain_otp=submitted,
                feed_lockout=False,
            )
            for submitted in ["123456"] * 2
        ),
        return_exceptions=True,
    )
    assert sum(isinstance(result, Verification) for result in results) == 1
    assert sum(isinstance(result, TokenInvalidError) for result in results) == 1


async def test_check_otp_flow_never_loses_failed_attempts() -> None:
    adapter = IndependentReadAdapter(3)
    auth = make_auth(adapter)
    otp = OtpService()
    await adapter.create_verification(
        Verification(
            identifier="check@example.com",
            purpose=VerificationPurpose.EMAIL_OTP_SIGN_IN,
            value_hash=otp.hash_only("123456"),
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )
    )
    results = await asyncio.gather(
        *(
            check_otp(
                auth.context,
                CheckOtpRequest(
                    email="check@example.com",
                    purpose=EmailOtpPurpose.SIGN_IN,
                    otp=SecretStr(submitted),
                ),
                config=EmailOtpOptions(max_attempts=3),
                otp_service=otp,
            )
            for submitted in ["wrong"] * 3
        ),
        return_exceptions=True,
    )
    assert all(isinstance(result, TokenInvalidError) for result in results)
    assert (
        await InMemoryAdapter.get_active_verification(
            adapter,
            "check@example.com",
            VerificationPurpose.EMAIL_OTP_SIGN_IN,
        )
        is None
    )


@pytest.mark.parametrize(
    "purpose",
    [
        VerificationPurpose.EMAIL_VERIFICATION,
        VerificationPurpose.PASSWORD_RESET,
        VerificationPurpose.EMAIL_CHANGE,
        VerificationPurpose.ACCOUNT_DELETION,
    ],
)
async def test_token_flow_has_only_one_concurrent_success(purpose: VerificationPurpose) -> None:
    adapter = IndependentReadAdapter(2)
    auth = make_auth(adapter)
    user = await adapter.create_user(User(email="links@example.com"))
    await adapter.create_account(
        Account(
            user_id=user.id,
            provider_id=ProviderId.CREDENTIAL,
            account_id=user.id,
            password="unused",
        )
    )
    identifier = user.email
    if purpose == VerificationPurpose.EMAIL_CHANGE:
        identifier = "new@example.com"
        user.pending_email_change = identifier
        await adapter.update_user(user)
    pair = auth.context.token_service.generate_pair()
    await adapter.create_verification(
        Verification(
            identifier=identifier,
            purpose=purpose,
            value_hash=pair.hashed,
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )
    )

    async def submit() -> None:
        if purpose == VerificationPurpose.EMAIL_VERIFICATION:
            await verify_email(
                auth.context,
                VerifyEmailRequest(email=identifier, token=SecretStr(pair.plain)),
                ip=None,
                user_agent=None,
            )
        elif purpose == VerificationPurpose.PASSWORD_RESET:
            await reset_password(
                auth.context,
                ResetPasswordRequest(
                    email=identifier,
                    token=SecretStr(pair.plain),
                    new_password=SecretStr("correct-horse-battery"),
                ),
                ip=None,
                user_agent=None,
            )
        elif purpose == VerificationPurpose.EMAIL_CHANGE:
            await confirm_email_change(
                auth.context,
                ConfirmEmailChangeRequest(new_email=identifier, token=SecretStr(pair.plain)),
                ip=None,
                user_agent=None,
            )
        else:
            await confirm_delete_account(
                auth.context,
                user,
                DeleteAccountConfirmRequest(token=SecretStr(pair.plain)),
                ip=None,
                user_agent=None,
            )

    results = await asyncio.gather(submit(), submit(), return_exceptions=True)
    assert sum(result is None for result in results) == 1
    assert sum(isinstance(result, TokenInvalidError) for result in results) == 1


def test_legacy_adapter_rejected_before_serving_authentication() -> None:
    with pytest.raises(ConfigError, match="atomic verification"):
        FastAuth(
            FastAuthOptions(
                secret_key=SecretStr("a" * 64), database=custom(adapter=BaseDatabaseAdapter())
            )
        )


async def test_invalid_reset_password_does_not_burn_link_before_corrected_retry() -> None:
    from fastauth.exceptions import InvalidRequestError

    adapter = InMemoryAdapter()
    auth = make_auth(adapter)
    user = await adapter.create_user(User(email="reset-validation@example.com"))
    await adapter.create_account(
        Account(
            user_id=user.id,
            provider_id=ProviderId.CREDENTIAL,
            account_id=user.id,
            password="unused",
        )
    )
    pair = auth.context.token_service.generate_pair()
    await adapter.create_verification(
        Verification(
            identifier=user.email,
            purpose=VerificationPurpose.PASSWORD_RESET,
            value_hash=pair.hashed,
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )
    )
    with pytest.raises(InvalidRequestError):
        await reset_password(
            auth.context,
            ResetPasswordRequest(
                email=user.email,
                token=SecretStr(pair.plain),
                new_password=SecretStr("short"),
            ),
            ip=None,
            user_agent=None,
        )
    await reset_password(
        auth.context,
        ResetPasswordRequest(
            email=user.email,
            token=SecretStr(pair.plain),
            new_password=SecretStr("correct-horse-battery"),
        ),
        ip=None,
        user_agent=None,
    )


async def test_invalid_reset_password_does_not_burn_otp_before_corrected_retry() -> None:
    from fastauth.exceptions import InvalidRequestError
    from fastauth.flows.email_otp import ResetPasswordOtpRequest, reset_password_with_otp

    adapter = InMemoryAdapter()
    auth = make_auth(adapter)
    user = await adapter.create_user(User(email="otp-validation@example.com"))
    otp = OtpService()
    pair = otp.generate_pair()
    await adapter.create_verification(
        Verification(
            identifier=user.email,
            purpose=VerificationPurpose.EMAIL_OTP_PASSWORD_RESET,
            value_hash=pair.hashed,
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )
    )
    with pytest.raises(InvalidRequestError):
        await reset_password_with_otp(
            auth.context,
            ResetPasswordOtpRequest(
                email=user.email,
                otp=SecretStr(pair.plain),
                password=SecretStr("short"),
            ),
            config=EmailOtpOptions(),
            otp_service=otp,
            ip=None,
            user_agent=None,
        )
    await reset_password_with_otp(
        auth.context,
        ResetPasswordOtpRequest(
            email=user.email,
            otp=SecretStr(pair.plain),
            password=SecretStr("correct-horse-battery"),
        ),
        config=EmailOtpOptions(),
        otp_service=otp,
        ip=None,
        user_agent=None,
    )
