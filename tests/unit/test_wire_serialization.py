from __future__ import annotations

from fastauth.web.fastapi import camelize_keys


def test_camelize_keys_preserves_jwks_key_parameters() -> None:
    body = {
        "keys": [
            {
                "kid": "k1",
                "kty": "OKP",
                "key_ops": ["verify"],
                "x5t#S256": "thumbprint",
            },
        ],
    }

    assert camelize_keys(body) == body
