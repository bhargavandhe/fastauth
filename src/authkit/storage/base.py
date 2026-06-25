"""Storage adapter protocols and reusable base class."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol, runtime_checkable

from authkit.domain.enums import AuditEventType, ProviderId, VerificationPurpose
from authkit.domain.models import (
    Account,
    ApiKey,
    AuditLog,
    JwksKey,
    RateLimit,
    RefreshToken,
    Session,
    User,
    Verification,
)
from authkit.exceptions import AdapterFeatureUnsupportedError

__all__ = [
    "AccountStore",
    "ApiKeyStore",
    "AuditLogStore",
    "BaseDatabaseAdapter",
    "CoreAuthAdapter",
    "DatabaseAdapter",
    "JwksKeyStore",
    "RateLimitStore",
    "RefreshTokenStore",
    "SessionStore",
    "UserStore",
    "VerificationStore",
]


@runtime_checkable
class UserStore(Protocol):
    async def create_user(self, user: User) -> User: ...
    async def get_user_by_id(self, user_id: str) -> User | None: ...
    async def get_user_by_email(self, email: str) -> User | None: ...
    async def get_user_by_username(self, username: str) -> User | None: ...
    async def find_user_by_pending_email_change(self, new_email: str) -> User | None: ...
    async def update_user(self, user: User) -> User: ...
    async def delete_user(self, user_id: str) -> None: ...


@runtime_checkable
class SessionStore(Protocol):
    async def create_session(self, session: Session) -> Session: ...
    async def get_session_by_token_hash(self, token_hash: str) -> Session | None: ...
    async def list_sessions_for_user(self, user_id: str) -> list[Session]: ...
    async def update_session(self, session: Session) -> Session: ...
    async def delete_session(self, session_id: str) -> None: ...
    async def delete_sessions_for_user(
        self,
        user_id: str,
        *,
        except_session_id: str | None = None,
    ) -> int: ...


@runtime_checkable
class RefreshTokenStore(Protocol):
    async def create_refresh_token(self, token: RefreshToken) -> RefreshToken: ...
    async def get_refresh_token_by_hash(self, token_hash: str) -> RefreshToken | None: ...
    async def update_refresh_token(self, token: RefreshToken) -> RefreshToken: ...
    async def rotate_refresh_token(
        self,
        *,
        current_token_id: str,
        new_token: RefreshToken,
        consumed_at: datetime,
    ) -> RefreshToken | None: ...
    async def delete_refresh_token(self, token_id: str) -> None: ...
    async def delete_refresh_tokens_for_user(self, user_id: str) -> int: ...
    async def delete_refresh_tokens_in_family(self, family_id: str) -> int: ...


@runtime_checkable
class AccountStore(Protocol):
    async def create_account(self, account: Account) -> Account: ...
    async def get_account_for_user(
        self,
        user_id: str,
        provider_id: ProviderId,
    ) -> Account | None: ...
    async def list_accounts_for_user(self, user_id: str) -> list[Account]: ...
    async def update_account(self, account: Account) -> Account: ...
    async def delete_account(self, account_id: str) -> None: ...


@runtime_checkable
class VerificationStore(Protocol):
    async def create_verification(self, verification: Verification) -> Verification: ...
    async def get_verification(
        self,
        identifier: str,
        purpose: VerificationPurpose,
        value_hash: str,
    ) -> Verification | None: ...
    async def get_active_verification(
        self,
        identifier: str,
        purpose: VerificationPurpose,
    ) -> Verification | None: ...
    async def update_verification(self, verification: Verification) -> Verification: ...
    async def delete_verification(self, verification_id: str) -> None: ...
    async def delete_verifications_for_identifier(
        self,
        identifier: str,
        purpose: VerificationPurpose,
    ) -> int: ...


@runtime_checkable
class CoreAuthAdapter(
    UserStore,
    SessionStore,
    RefreshTokenStore,
    AccountStore,
    VerificationStore,
    Protocol,
):
    """Minimum storage surface used by authkit's built-in auth flows."""


@runtime_checkable
class ApiKeyStore(Protocol):
    async def create_api_key(self, api_key: ApiKey) -> ApiKey: ...
    async def get_api_key_by_hash(self, key_hash: str) -> ApiKey | None: ...
    async def get_api_key_by_id(self, api_key_id: str) -> ApiKey | None: ...
    async def list_api_keys_for_user(
        self,
        user_id: str,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[ApiKey], int]: ...
    async def update_api_key(self, api_key: ApiKey) -> ApiKey: ...
    async def delete_api_key(self, api_key_id: str) -> None: ...
    async def delete_expired_api_keys(self) -> int: ...


@runtime_checkable
class JwksKeyStore(Protocol):
    async def create_jwks_key(self, key: JwksKey) -> JwksKey: ...
    async def list_jwks_keys(self) -> list[JwksKey]: ...
    async def update_jwks_key(self, key: JwksKey) -> JwksKey: ...
    async def delete_jwks_key(self, key_id: str) -> None: ...


@runtime_checkable
class AuditLogStore(Protocol):
    async def create_audit_log(self, row: AuditLog) -> AuditLog: ...
    async def list_audit_logs(
        self,
        *,
        user_id: str | None,
        event_type: AuditEventType | None,
        identifier: str | None,
        limit: int,
        offset: int,
    ) -> tuple[list[AuditLog], int]: ...


@runtime_checkable
class RateLimitStore(Protocol):
    async def get_rate_limit(self, key: str) -> RateLimit | None: ...
    async def upsert_rate_limit(self, rate_limit: RateLimit) -> RateLimit: ...
    async def delete_rate_limit(self, key: str) -> None: ...


@runtime_checkable
class DatabaseAdapter(
    CoreAuthAdapter,
    Protocol,
):
    """Core storage adapter required by authkit's built-in auth flows.

    Plugin and optional infrastructure storage is expressed through separate
    protocols: ``ApiKeyStore``, ``JwksKeyStore``, ``AuditLogStore``, and
    ``RateLimitStore``. Implement only the capabilities your configuration
    enables.
    """


class BaseDatabaseAdapter:
    """Reusable adapter base with explicit unsupported-feature defaults.

    Subclass this when implementing a backend. Override the core auth methods
    here, then add optional store protocol methods only for the plugins or
    database-backed features your adapter supports.
    """

    def unsupported(self, feature: str) -> AdapterFeatureUnsupportedError:
        return AdapterFeatureUnsupportedError(feature=feature)

    async def create_user(self, user: User) -> User:
        raise self.unsupported("users")

    async def get_user_by_id(self, user_id: str) -> User | None:
        raise self.unsupported("users")

    async def get_user_by_email(self, email: str) -> User | None:
        raise self.unsupported("users")

    async def get_user_by_username(self, username: str) -> User | None:
        raise self.unsupported("users")

    async def find_user_by_pending_email_change(self, new_email: str) -> User | None:
        raise self.unsupported("users")

    async def update_user(self, user: User) -> User:
        raise self.unsupported("users")

    async def delete_user(self, user_id: str) -> None:
        raise self.unsupported("users")

    async def create_session(self, session: Session) -> Session:
        raise self.unsupported("sessions")

    async def get_session_by_token_hash(self, token_hash: str) -> Session | None:
        raise self.unsupported("sessions")

    async def list_sessions_for_user(self, user_id: str) -> list[Session]:
        raise self.unsupported("sessions")

    async def update_session(self, session: Session) -> Session:
        raise self.unsupported("sessions")

    async def delete_session(self, session_id: str) -> None:
        raise self.unsupported("sessions")

    async def delete_sessions_for_user(
        self,
        user_id: str,
        *,
        except_session_id: str | None = None,
    ) -> int:
        raise self.unsupported("sessions")

    async def create_refresh_token(self, token: RefreshToken) -> RefreshToken:
        raise self.unsupported("refresh tokens")

    async def get_refresh_token_by_hash(self, token_hash: str) -> RefreshToken | None:
        raise self.unsupported("refresh tokens")

    async def update_refresh_token(self, token: RefreshToken) -> RefreshToken:
        raise self.unsupported("refresh tokens")

    async def rotate_refresh_token(
        self,
        *,
        current_token_id: str,
        new_token: RefreshToken,
        consumed_at: datetime,
    ) -> RefreshToken | None:
        raise self.unsupported("refresh tokens")

    async def delete_refresh_token(self, token_id: str) -> None:
        raise self.unsupported("refresh tokens")

    async def delete_refresh_tokens_for_user(self, user_id: str) -> int:
        raise self.unsupported("refresh tokens")

    async def delete_refresh_tokens_in_family(self, family_id: str) -> int:
        raise self.unsupported("refresh tokens")

    async def create_account(self, account: Account) -> Account:
        raise self.unsupported("accounts")

    async def get_account_for_user(
        self,
        user_id: str,
        provider_id: ProviderId,
    ) -> Account | None:
        raise self.unsupported("accounts")

    async def list_accounts_for_user(self, user_id: str) -> list[Account]:
        raise self.unsupported("accounts")

    async def update_account(self, account: Account) -> Account:
        raise self.unsupported("accounts")

    async def delete_account(self, account_id: str) -> None:
        raise self.unsupported("accounts")

    async def create_verification(self, verification: Verification) -> Verification:
        raise self.unsupported("verifications")

    async def get_verification(
        self,
        identifier: str,
        purpose: VerificationPurpose,
        value_hash: str,
    ) -> Verification | None:
        raise self.unsupported("verifications")

    async def get_active_verification(
        self,
        identifier: str,
        purpose: VerificationPurpose,
    ) -> Verification | None:
        raise self.unsupported("verifications")

    async def update_verification(self, verification: Verification) -> Verification:
        raise self.unsupported("verifications")

    async def delete_verification(self, verification_id: str) -> None:
        raise self.unsupported("verifications")

    async def delete_verifications_for_identifier(
        self,
        identifier: str,
        purpose: VerificationPurpose,
    ) -> int:
        raise self.unsupported("verifications")
