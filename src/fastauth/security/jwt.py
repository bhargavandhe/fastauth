"""JWT signing/verification, JWKS registry, KMS-pluggable signer."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
from collections.abc import Callable
from collections.abc import Sequence as TypingSequence
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, cast, runtime_checkable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from joserfc import jwk, jwt
from joserfc.errors import JoseError
from pydantic import BaseModel, ConfigDict, SecretStr

from fastauth.domain.enums import JwtAlgorithm
from fastauth.domain.models import JwksKey, Session, User, new_id
from fastauth.exceptions import JwksDecryptionError, TokenInvalidError
from fastauth.security.sessions import SessionContext
from fastauth.storage.base import JwksKeyStore, UserStore

LOGGER = logging.getLogger("fastauth.jwt")

__all__ = [
    "JwksDocument",
    "JwksRegistry",
    "JwtSessionStrategy",
    "KmsSigner",
    "LocalKmsSigner",
    "algorithm_to_jwk_type",
    "decrypt_private_key",
    "derive_kek",
    "encrypt_private_key",
]


def derive_kek(secret_key: SecretStr) -> bytes:
    """Derive a 32-byte KEK from the configured secret via SHA-256."""
    return hashlib.sha256(secret_key.get_secret_value().encode("utf-8")).digest()


def encrypt_private_key(plain: bytes, kek: bytes) -> bytes:
    """AES-256-GCM encrypt with a fresh 12-byte nonce prepended to the ciphertext."""
    nonce = os.urandom(12)
    cipher = AESGCM(kek)
    return nonce + cipher.encrypt(nonce, plain, associated_data=None)


def decrypt_private_key(blob: bytes, kek: bytes) -> bytes:
    """Inverse of ``encrypt_private_key`` — strip the 12-byte nonce, then decrypt."""
    nonce, body = blob[:12], blob[12:]
    cipher = AESGCM(kek)
    return cipher.decrypt(nonce, body, associated_data=None)


def algorithm_to_jwk_type(alg: JwtAlgorithm) -> str:
    """Map a ``JwtAlgorithm`` to its corresponding JWK ``kty`` value."""
    return {
        JwtAlgorithm.ED25519: "OKP",
        JwtAlgorithm.ES256: "EC",
        JwtAlgorithm.ES512: "EC",
        JwtAlgorithm.RS256: "RSA",
        JwtAlgorithm.PS256: "RSA",
    }[alg]


@runtime_checkable
class KmsSigner(Protocol):
    """Protocol implemented by anything that can sign a JWT header+payload pair."""

    async def sign(self, *, header: dict[str, Any], payload: dict[str, Any]) -> str: ...


class JwksRegistry:
    """Manages JWKS keys: creation, rotation, persistence, and JWKS-JSON exposure."""

    def __init__(
        self,
        adapter: JwksKeyStore,
        *,
        secret_key: SecretStr,
        alg: JwtAlgorithm,
        rotation_interval_seconds: int | None,
        grace_period_seconds: int,
        encrypt_private_keys: bool,
        secret_key_rotation: TypingSequence[SecretStr] = (),
    ) -> None:
        self.adapter = adapter
        self.secret_key = secret_key
        self.alg = alg
        self.rotation_interval_seconds = rotation_interval_seconds
        self.grace_period_seconds = grace_period_seconds
        self.encrypt_private_keys = encrypt_private_keys
        self.kek = derive_kek(secret_key)
        # KEKs to ATTEMPT during decrypt: primary first, then any rotation
        # entries (older secret_keys that may have encrypted live ciphertext).
        # New ciphertext is always encrypted with the primary KEK.
        self.decryption_keks: list[bytes] = [
            self.kek,
            *(derive_kek(older) for older in secret_key_rotation),
        ]
        self.current_key: JwksKey | None = None

    async def ensure_key(self) -> JwksKey:
        """Return a key whose private portion is decryptable with the current secret.

        Proactively probes each active key by attempting to decrypt its private
        portion. If decryption fails (typically because
        ``FastAuthOptions.secret_key`` changed without an accompanying
        ``secret_key_rotation`` entry), the key is marked rotated immediately
        so it no longer attracts new signs, but its public portion stays in
        ``as_jwks_json`` during the grace period so any in-flight tokens it
        signed can still verify. A fresh key replaces it.
        """
        keys = await self.adapter.list_jwks_keys()
        active = sorted(
            (key for key in keys if key.rotated_at is None and key.alg == self.alg.value),
            key=lambda key: (key.created_at, key.kid),
            reverse=True,
        )
        for candidate in active:
            try:
                self.decrypt_private_jwk(candidate)
            except JwksDecryptionError:
                now = datetime.now(UTC)
                LOGGER.warning(
                    "rotating jwks key %s: private portion cannot be decrypted with "
                    "the current FastAuthOptions.secret_key. "
                    "Old tokens stay verifiable during the %ss grace period; new "
                    "tokens will use a fresh key.",
                    candidate.kid,
                    self.grace_period_seconds,
                )
                candidate.rotated_at = now
                candidate.expires_at = now + timedelta(seconds=self.grace_period_seconds)
                await self.adapter.update_jwks_key(candidate)
                continue
            self.current_key = candidate
            return candidate
        return await self.create_key()

    async def create_key(self) -> JwksKey:
        if self.alg is JwtAlgorithm.ED25519:
            key_obj = jwk.OKPKey.generate_key("Ed25519")
        elif self.alg in (JwtAlgorithm.ES256, JwtAlgorithm.ES512):
            curve = "P-256" if self.alg is JwtAlgorithm.ES256 else "P-521"
            key_obj = jwk.ECKey.generate_key(curve)
        else:
            key_obj = jwk.RSAKey.generate_key(2048)

        kid = secrets.token_urlsafe(12)
        public_jwk = json.dumps(key_obj.as_dict(private=False))
        private_bytes = json.dumps(key_obj.as_dict(private=True)).encode("utf-8")
        if self.encrypt_private_keys:
            private_bytes = encrypt_private_key(private_bytes, self.kek)

        key = JwksKey(
            kid=kid,
            alg=self.alg.value,
            public_key=public_jwk,
            private_key_encrypted=private_bytes,
        )
        await self.adapter.create_jwks_key(key)
        self.current_key = key
        return key

    async def rotate_now(self) -> JwksKey:
        # Publish first. Concurrent rotations may leave several active keys;
        # ensure_key deterministically selects the newest (created_at, kid).
        # Never retire a key created after this snapshot or delete grace keys.
        previous = await self.adapter.list_jwks_keys()
        replacement = await self.create_key()
        now = datetime.now(UTC)
        for key in previous:
            if key.rotated_at is None and key.alg == self.alg.value:
                key.rotated_at = now
                key.expires_at = now + timedelta(seconds=self.grace_period_seconds)
                await self.adapter.update_jwks_key(key)
        return replacement

    async def rotate_if_due(self) -> JwksKey | None:
        current = await self.ensure_key()
        if self.rotation_interval_seconds is None:
            return None
        age = (datetime.now(UTC) - current.created_at).total_seconds()
        if age >= self.rotation_interval_seconds:
            return await self.rotate_now()
        return None

    def decrypt_private_jwk(self, key: JwksKey) -> dict[str, Any]:
        """Return the decrypted private JWK payload ready for ``joserfc.jwk.import_key``.

        Attempts decryption with the primary KEK first, then with each KEK
        derived from ``secret_key_rotation`` (oldest last). Raises
        ``JwksDecryptionError`` if every KEK fails to authenticate the AES-GCM
        ciphertext — almost always because the current
        ``FastAuthOptions.secret_key`` is different from the secret that encrypted
        the stored key and no ``secret_key_rotation`` entry covers the previous
        value.

        **Rule exception — returns a plain ``dict``:** ``joserfc.jwk.import_key``
        accepts ``dict[str, Any]`` because RFC 7517 + RFC 7518 keep JWK members
        algorithm-dependent (OKP/EC/RSA each have their own field set). Wrapping
        in Pydantic would either reject valid keys or accept invalid ones. One
        of the four documented carve-outs in CONTRIBUTING.md.
        """
        blob = key.private_key_encrypted
        if not self.encrypt_private_keys:
            plain = blob
        else:
            plain = None
            for kek in self.decryption_keks:
                try:
                    plain = decrypt_private_key(blob, kek)
                    break
                except InvalidTag:
                    continue
            if plain is None:
                raise JwksDecryptionError(
                    message=(
                        f"failed to decrypt JWKS key {key.kid}: AES-GCM tag mismatch "
                        "against every configured secret_key. Most likely "
                        "FastAuthOptions.secret_key was changed without adding the previous "
                        "value to secret_key_rotation; ensure_key() rotates "
                        "the affected key on startup so this only surfaces from "
                        "out-of-band signers wired after lifespan_startup."
                    ),
                )
        loaded: Any = json.loads(plain.decode("utf-8"))
        if not isinstance(loaded, dict):
            raise ValueError("jwks private key payload is not an object")
        return cast("dict[str, Any]", loaded)

    async def as_jwks_json(self) -> JwksDocument:
        """Return the public JWKS as a Pydantic ``JwksDocument``.

        Each entry of ``keys`` remains a ``dict[str, Any]`` because RFC 7517 +
        RFC 7518 leave JWK members algorithm-dependent — a static Pydantic
        model would either reject valid keys or accept invalid ones. This is
        one of the four documented carve-outs in CONTRIBUTING.md (the inner
        dict carries the external-spec payload; the outer envelope is typed).
        """
        keys = await self.adapter.list_jwks_keys()
        now = datetime.now(UTC)
        usable = [
            key
            for key in keys
            if key.rotated_at is None or (key.expires_at and key.expires_at > now)
        ]
        public = [{**json.loads(key.public_key), "kid": key.kid, "alg": key.alg} for key in usable]
        return JwksDocument(keys=public)


class JwksDocument(BaseModel):
    """Public JWKS envelope as defined by RFC 7517 §5.

    ``keys`` is intentionally typed as ``list[dict[str, Any]]`` because JWK
    members are algorithm-dependent (OKP, EC, RSA, …) and free-form per the
    spec; see ``JwksRegistry.as_jwks_json`` for the rationale.
    """

    model_config = ConfigDict(extra="forbid")
    keys: list[dict[str, Any]]


class LocalKmsSigner:
    """Default in-process signer that uses ``JwksRegistry``'s current key."""

    def __init__(self, registry: JwksRegistry) -> None:
        self.registry = registry

    async def sign(self, *, header: dict[str, Any], payload: dict[str, Any]) -> str:
        # Cached keys cannot be authoritative across workers. Refresh shared
        # state on every sign and perform lazy interval rotation without restart.
        await self.registry.rotate_if_due()
        key = await self.registry.ensure_key()
        private = self.registry.decrypt_private_jwk(key)
        header_with_kid = {**header, "kid": key.kid}
        return jwt.encode(
            header_with_kid,
            payload,
            jwk.import_key(private),
            algorithms=[self.registry.alg.value],
        )


class JwtSessionStrategy:
    """``SessionStrategy`` that issues JWTs signed via the configured signer."""

    def __init__(
        self,
        *,
        adapter: UserStore,
        registry: JwksRegistry,
        signer: KmsSigner,
        issuer: str,
        audience: str,
        expires_in_seconds: int,
        payload_builder: Callable[[User], dict[str, Any]],
    ) -> None:
        self.adapter = adapter
        self.registry = registry
        self.signer = signer
        self.issuer = issuer
        self.audience = audience
        self.expires_in_seconds = expires_in_seconds
        self.payload_builder = payload_builder

    async def create(
        self,
        user: User,
        *,
        ip: str | None,
        user_agent: str | None,
    ) -> SessionContext:
        return await self.renew(
            user,
            session_id=f"jwt:{new_id()}",
            authenticated_at=datetime.now(UTC),
            ip=ip,
            user_agent=user_agent,
        )

    async def renew(
        self,
        user: User,
        *,
        session_id: str,
        authenticated_at: datetime | None,
        ip: str | None,
        user_agent: str | None,
    ) -> SessionContext:
        if not valid_jwt_session_id(session_id):
            raise TokenInvalidError(message="JWT refresh requires a v0.15 session; sign in again")
        now = datetime.now(UTC)
        expires_at = now + timedelta(seconds=self.expires_in_seconds)
        # Registered/session-security claims always win over custom payloads.
        payload: dict[str, Any] = {
            **self.payload_builder(user),
            "iss": self.issuer,
            "aud": self.audience,
            "sub": user.id,
            "sid": session_id,
            "iat": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
            "auth_time": authenticated_at.timestamp() if authenticated_at is not None else None,
        }
        token = await self.signer.sign(
            header={"alg": self.registry.alg.value, "typ": "JWT"},
            payload=payload,
        )
        synthetic = Session(
            id=session_id,
            user_id=user.id,
            token_hash="jwt",  # noqa: S106 — stateless placeholder, not a credential
            expires_at=expires_at,
            ip_address=ip,
            user_agent=user_agent,
            authenticated_at=authenticated_at,
            created_at=now,
            updated_at=now,
        )
        return SessionContext(user=user, session=synthetic, token=token)

    async def read(self, token: str) -> SessionContext | None:
        jwks = await self.registry.as_jwks_json()
        key_set = jwk.KeySet([jwk.import_key(item) for item in jwks.keys])
        try:
            decoded = jwt.decode(token, key_set, algorithms=[self.registry.alg.value])
        except (JoseError, ValueError, TypeError):
            return None
        claims = decoded.claims
        if claims.get("aud") != self.audience or claims.get("iss") != self.issuer:
            return None
        subject, expires, session_id = claims.get("sub"), claims.get("exp"), claims.get("sid")
        if not isinstance(subject, str) or not subject:
            return None
        if not isinstance(expires, (int, float)) or isinstance(expires, bool):
            return None
        if expires <= datetime.now(UTC).timestamp():
            return None
        # Existing v0.14 access JWTs remain valid until expiry. Their deterministic
        # legacy identity cannot match old random refresh session ids; operators
        # must invalidate legacy refresh families during the 0.15 upgrade.
        if session_id is None:
            session_id = "legacy-jwt:" + hashlib.sha256(token.encode()).hexdigest()
        elif not valid_jwt_session_id(session_id):
            return None
        authenticated = claims.get("auth_time")
        if authenticated is not None and (
            not isinstance(authenticated, (int, float)) or isinstance(authenticated, bool)
        ):
            return None
        try:
            expires_at = datetime.fromtimestamp(expires, tz=UTC)
            authenticated_at = (
                datetime.fromtimestamp(authenticated, tz=UTC) if authenticated is not None else None
            )
        except (ValueError, OverflowError, OSError):
            return None
        user = await self.adapter.get_user_by_id(subject)
        if user is None:
            return None
        session = Session(
            id=session_id,
            user_id=user.id,
            token_hash="jwt",  # noqa: S106 — stateless placeholder, not a credential
            expires_at=expires_at,
            authenticated_at=authenticated_at,
        )
        return SessionContext(user=user, session=session, token=token)

    async def revoke(self, token: str) -> None:
        return None

    async def revoke_all(self, user_id: str, *, except_session_id: str | None = None) -> int:
        # Stateless JWTs aren't revocable individually without a denylist.
        # Refresh tokens (Phase D) provide the revocation surface for JWT mode.
        del user_id, except_session_id
        return 0

    async def rotate(self, token: str) -> SessionContext | None:
        current = await self.read(token)
        if current is None:
            return None
        return await self.renew(
            current.user,
            session_id=current.session.id,
            authenticated_at=current.session.authenticated_at,
            ip=current.session.ip_address,
            user_agent=current.session.user_agent,
        )


def valid_jwt_session_id(value: object) -> bool:
    """JWT logical identities are protocol strings, never Mongo-owned references."""
    return (
        isinstance(value, str)
        and value.startswith("jwt:")
        and len(value) == 36
        and all(character in "0123456789abcdef" for character in value[4:])
    )
