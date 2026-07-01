from __future__ import annotations

from fastauth.security.jwt import JwksDocument


def test_jwks_document_preserves_jwk_key_parameters() -> None:
    body = JwksDocument(
        keys=[
            {
                "kid": "k1",
                "kty": "OKP",
                "key_ops": ["verify"],
                "x5t#S256": "thumbprint",
            },
        ],
    )

    assert body.model_dump() == {
        "keys": [
            {
                "kid": "k1",
                "kty": "OKP",
                "key_ops": ["verify"],
                "x5t#S256": "thumbprint",
            },
        ],
    }
