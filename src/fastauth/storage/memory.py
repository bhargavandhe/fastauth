"""In-memory DatabaseAdapter — for unit tests and small demos."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from fastauth.domain.enums import AuditEventType, ProviderId, VerificationPurpose
from fastauth.domain.models import (
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
from fastauth.exceptions import DuplicateError, NotFoundError

__all__ = ["InMemoryAdapter"]


class InMemoryAdapter:
    def __init__(self) -> None:
        self.users: dict[str, User] = {}
        self.sessions: dict[str, Session] = {}
        self.accounts: dict[str, Account] = {}
        self.verifications: dict[str, Verification] = {}
        self.api_keys: dict[str, ApiKey] = {}
        self.jwks_keys: dict[str, JwksKey] = {}
        self.audit_logs: list[AuditLog] = []
        self.rate_limits: dict[str, RateLimit] = {}
        self.refresh_tokens: dict[str, RefreshToken] = {}
        self.lock = asyncio.Lock()

    # ----- User -----
    async def create_user(self, user: User) -> User:
        async with self.lock:
            if any(existing.email == user.email for existing in self.users.values()):
                raise DuplicateError(resource="user", field="email")
            self.users[user.id] = user
            return user

    async def get_user_by_id(self, user_id: str) -> User | None:
        return self.users.get(user_id)

    async def get_user_by_email(self, email: str) -> User | None:
        for user in self.users.values():
            if user.email.lower() == email.lower():
                return user
        return None

    async def get_user_by_username(self, username: str) -> User | None:
        for user in self.users.values():
            if user.username == username:
                return user
        return None

    async def find_user_by_pending_email_change(self, new_email: str) -> User | None:
        for user in self.users.values():
            if user.pending_email_change is not None and user.pending_email_change == new_email:
                return user
        return None

    async def update_user(self, user: User) -> User:
        async with self.lock:
            if user.id not in self.users:
                raise NotFoundError(resource="user")
            user.updated_at = datetime.now(UTC)
            self.users[user.id] = user
            return user

    async def delete_user(self, user_id: str) -> None:
        async with self.lock:
            user = self.users.pop(user_id, None)
            identifiers: set[str] = set()
            if user is not None:
                identifiers.add(user.email)
                if user.pending_email_change is not None:
                    identifiers.add(user.pending_email_change)
            for account_id, account in list(self.accounts.items()):
                if account.user_id == user_id:
                    del self.accounts[account_id]
            for session_id, session in list(self.sessions.items()):
                if session.user_id == user_id:
                    del self.sessions[session_id]
            for token_id, token in list(self.refresh_tokens.items()):
                if token.user_id == user_id:
                    del self.refresh_tokens[token_id]
            for key_id, key in list(self.api_keys.items()):
                if key.user_id == user_id:
                    del self.api_keys[key_id]
            for verification_id, verification in list(self.verifications.items()):
                if verification.identifier in identifiers:
                    del self.verifications[verification_id]

    # ----- Session -----
    async def create_session(self, session: Session) -> Session:
        async with self.lock:
            self.sessions[session.id] = session
            return session

    async def get_session_by_token_hash(self, token_hash: str) -> Session | None:
        for session in self.sessions.values():
            if session.token_hash == token_hash:
                return session
        return None

    async def list_sessions_for_user(self, user_id: str) -> list[Session]:
        return [session for session in self.sessions.values() if session.user_id == user_id]

    async def update_session(self, session: Session) -> Session:
        async with self.lock:
            if session.id not in self.sessions:
                raise NotFoundError(resource="session")
            session.updated_at = datetime.now(UTC)
            self.sessions[session.id] = session
            return session

    async def delete_session(self, session_id: str) -> None:
        async with self.lock:
            self.sessions.pop(session_id, None)

    async def delete_sessions_for_user(
        self,
        user_id: str,
        *,
        except_session_id: str | None = None,
    ) -> int:
        async with self.lock:
            doomed = [
                sid
                for sid, session in self.sessions.items()
                if session.user_id == user_id and sid != except_session_id
            ]
            for sid in doomed:
                del self.sessions[sid]
            return len(doomed)

    # ----- RefreshToken -----
    async def create_refresh_token(self, token: RefreshToken) -> RefreshToken:
        async with self.lock:
            self.refresh_tokens[token.id] = token
            return token

    async def get_refresh_token_by_hash(self, token_hash: str) -> RefreshToken | None:
        for token in self.refresh_tokens.values():
            if token.token_hash == token_hash:
                return token
        return None

    async def update_refresh_token(self, token: RefreshToken) -> RefreshToken:
        async with self.lock:
            if token.id not in self.refresh_tokens:
                raise NotFoundError(resource="refresh_token")
            token.updated_at = datetime.now(UTC)
            self.refresh_tokens[token.id] = token
            return token

    async def rotate_refresh_token(
        self,
        *,
        current_token_id: str,
        new_token: RefreshToken,
        consumed_at: datetime,
    ) -> RefreshToken | None:
        async with self.lock:
            current = self.refresh_tokens.get(current_token_id)
            if current is None or current.consumed_at is not None:
                return None
            now = datetime.now(UTC)
            new_token.updated_at = now
            self.refresh_tokens[new_token.id] = new_token
            current.consumed_at = consumed_at
            current.replaced_by = new_token.id
            current.updated_at = now
            return new_token

    async def delete_refresh_token(self, token_id: str) -> None:
        async with self.lock:
            self.refresh_tokens.pop(token_id, None)

    async def delete_refresh_tokens_for_user(self, user_id: str) -> int:
        async with self.lock:
            doomed = [tid for tid, tok in self.refresh_tokens.items() if tok.user_id == user_id]
            for tid in doomed:
                del self.refresh_tokens[tid]
            return len(doomed)

    async def delete_refresh_tokens_in_family(self, family_id: str) -> int:
        async with self.lock:
            doomed = [tid for tid, tok in self.refresh_tokens.items() if tok.family_id == family_id]
            for tid in doomed:
                del self.refresh_tokens[tid]
            return len(doomed)

    # ----- Account -----
    async def create_account(self, account: Account) -> Account:
        async with self.lock:
            self.accounts[account.id] = account
            return account

    async def get_account_for_user(
        self,
        user_id: str,
        provider_id: ProviderId,
    ) -> Account | None:
        for account in self.accounts.values():
            if account.user_id == user_id and account.provider_id is provider_id:
                return account
        return None

    async def list_accounts_for_user(self, user_id: str) -> list[Account]:
        return [account for account in self.accounts.values() if account.user_id == user_id]

    async def update_account(self, account: Account) -> Account:
        async with self.lock:
            if account.id not in self.accounts:
                raise NotFoundError(resource="account")
            account.updated_at = datetime.now(UTC)
            self.accounts[account.id] = account
            return account

    async def delete_account(self, account_id: str) -> None:
        async with self.lock:
            self.accounts.pop(account_id, None)

    # ----- Verification -----
    async def create_verification(self, verification: Verification) -> Verification:
        async with self.lock:
            self.verifications[verification.id] = verification
            return verification

    async def get_verification(
        self,
        identifier: str,
        purpose: VerificationPurpose,
        value_hash: str,
    ) -> Verification | None:
        for verification in self.verifications.values():
            if (
                verification.identifier == identifier
                and verification.purpose is purpose
                and verification.value_hash == value_hash
            ):
                return verification
        return None

    async def get_active_verification(
        self,
        identifier: str,
        purpose: VerificationPurpose,
    ) -> Verification | None:
        # Used by OTP flows: find the row to verify against without knowing the
        # value yet. Returns the most-recently-created row for the (identifier,
        # purpose) pair so a freshly-rotated OTP wins over a stale one.
        candidates = [
            v
            for v in self.verifications.values()
            if v.identifier == identifier and v.purpose is purpose
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda v: v.created_at)

    async def update_verification(self, verification: Verification) -> Verification:
        async with self.lock:
            if verification.id not in self.verifications:
                raise NotFoundError(resource="verification")
            verification.updated_at = datetime.now(UTC)
            self.verifications[verification.id] = verification
            return verification

    async def delete_verification(self, verification_id: str) -> None:
        async with self.lock:
            self.verifications.pop(verification_id, None)

    async def delete_verifications_for_identifier(
        self,
        identifier: str,
        purpose: VerificationPurpose,
    ) -> int:
        async with self.lock:
            doomed = [
                vid
                for vid, verification in self.verifications.items()
                if verification.identifier == identifier and verification.purpose is purpose
            ]
            for vid in doomed:
                del self.verifications[vid]
            return len(doomed)

    # ----- ApiKey -----
    async def create_api_key(self, api_key: ApiKey) -> ApiKey:
        async with self.lock:
            self.api_keys[api_key.id] = api_key
            return api_key

    async def get_api_key_by_hash(self, key_hash: str) -> ApiKey | None:
        for api_key in self.api_keys.values():
            if api_key.key_hash == key_hash:
                return api_key
        return None

    async def get_api_key_by_id(self, api_key_id: str) -> ApiKey | None:
        return self.api_keys.get(api_key_id)

    async def list_api_keys_for_user(
        self,
        user_id: str,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[ApiKey], int]:
        all_keys = [key for key in self.api_keys.values() if key.user_id == user_id]
        return all_keys[offset : offset + limit], len(all_keys)

    async def update_api_key(self, api_key: ApiKey) -> ApiKey:
        async with self.lock:
            if api_key.id not in self.api_keys:
                raise NotFoundError(resource="api_key")
            api_key.updated_at = datetime.now(UTC)
            self.api_keys[api_key.id] = api_key
            return api_key

    async def delete_api_key(self, api_key_id: str) -> None:
        async with self.lock:
            self.api_keys.pop(api_key_id, None)

    async def delete_expired_api_keys(self) -> int:
        async with self.lock:
            now = datetime.now(UTC)
            doomed = [
                kid
                for kid, key in self.api_keys.items()
                if key.expires_at is not None and key.expires_at < now
            ]
            for kid in doomed:
                del self.api_keys[kid]
            return len(doomed)

    # ----- JwksKey -----
    async def create_jwks_key(self, key: JwksKey) -> JwksKey:
        async with self.lock:
            self.jwks_keys[key.id] = key
            return key

    async def list_jwks_keys(self) -> list[JwksKey]:
        return list(self.jwks_keys.values())

    async def update_jwks_key(self, key: JwksKey) -> JwksKey:
        async with self.lock:
            if key.id not in self.jwks_keys:
                raise NotFoundError(resource="jwks_key")
            self.jwks_keys[key.id] = key
            return key

    async def delete_jwks_key(self, key_id: str) -> None:
        async with self.lock:
            self.jwks_keys.pop(key_id, None)

    # ----- AuditLog -----
    async def create_audit_log(self, row: AuditLog) -> AuditLog:
        async with self.lock:
            self.audit_logs.append(row)
            return row

    async def list_audit_logs(
        self,
        *,
        user_id: str | None,
        event_type: AuditEventType | None,
        identifier: str | None,
        limit: int,
        offset: int,
    ) -> tuple[list[AuditLog], int]:
        filtered = [
            row
            for row in self.audit_logs
            if (user_id is None or row.user_id == user_id)
            and (event_type is None or row.event_type is event_type)
            and (identifier is None or row.identifier == identifier)
        ]
        return filtered[offset : offset + limit], len(filtered)

    # ----- RateLimit -----
    async def increment_rate_limit(
        self,
        key: str,
        *,
        window_ms: int,
        now_ms: int,
    ) -> tuple[int, int]:
        async with self.lock:
            existing = self.rate_limits.get(key)
            if existing is None or existing.last_request_ms <= now_ms - window_ms:
                updated = RateLimit(key=key, count=1, last_request_ms=now_ms)
            else:
                updated = RateLimit(
                    key=key,
                    count=existing.count + 1,
                    last_request_ms=now_ms,
                )
            self.rate_limits[key] = updated
            return updated.count, updated.last_request_ms - window_ms

    async def get_rate_limit(self, key: str) -> RateLimit | None:
        return self.rate_limits.get(key)

    async def upsert_rate_limit(self, rate_limit: RateLimit) -> RateLimit:
        async with self.lock:
            existing = self.rate_limits.get(rate_limit.key)
            if existing is None:
                self.rate_limits[rate_limit.key] = rate_limit
            else:
                existing.count = rate_limit.count
                existing.last_request_ms = rate_limit.last_request_ms
                self.rate_limits[rate_limit.key] = existing
            return self.rate_limits[rate_limit.key]

    async def delete_rate_limit(self, key: str) -> None:
        async with self.lock:
            self.rate_limits.pop(key, None)
