from __future__ import annotations

from pydantic import SecretStr

from authkit.security.tokens import SignedCookieValue, TokenService


def test_token_service_generates_url_safe_pair() -> None:
    service = TokenService()
    pair = service.generate_pair()
    assert len(pair.plain) >= 32
    assert all(character.isalnum() or character in "-_" for character in pair.plain)
    assert pair.hashed != pair.plain
    assert service.verify_match(pair.plain, pair.hashed)


def test_hash_only_is_deterministic() -> None:
    service = TokenService()
    assert service.hash_only("abc") == service.hash_only("abc")
    assert service.hash_only("abc") != service.hash_only("abd")


def test_signed_cookie_round_trip() -> None:
    signer = SignedCookieValue(SecretStr("a" * 64), rotation=[])
    packed = signer.pack("session-123")
    assert "session-123" not in packed  # signed
    assert signer.unpack(packed) == "session-123"


def test_signed_cookie_rejects_tampered() -> None:
    signer = SignedCookieValue(SecretStr("a" * 64), rotation=[])
    packed = signer.pack("session-123")
    tampered = packed[:-1] + ("a" if packed[-1] != "a" else "b")
    assert signer.unpack(tampered) is None


def test_signed_cookie_honours_rotation() -> None:
    old = SignedCookieValue(SecretStr("a" * 64), rotation=[])
    packed = old.pack("session-123")
    rotated = SignedCookieValue(SecretStr("b" * 64), rotation=[SecretStr("a" * 64)])
    assert rotated.unpack(packed) == "session-123"
