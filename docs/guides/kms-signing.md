# KMS signing

`JwtPlugin` accepts a `signer_factory` callable so production deployments
can keep private keys inside a hardware-backed KMS rather than the
application database. The factory receives the plugin's `JwksRegistry` and
must return any object satisfying the `KmsSigner` Protocol:

Fastauth's local JWT/JWKS encryption and signing path has not been
independently audited. For high-stakes production deployments, prefer a
KMS/HSM-backed signer and run an application-specific security review.

```python
from typing import Any
from fastauth.security.jwt import KmsSigner

class CloudKmsSigner:
    def __init__(self, registry: JwksRegistry, key_id: str) -> None:
        self.registry = registry
        self.key_id = key_id

    async def sign(self, *, header: dict[str, Any], payload: dict[str, Any]) -> str:
        # Build the JWS encoding, then hand the digest to your KMS API.
        ...
```

Wire the factory into the plugin:

```python
from fastauth import FastAuthOptions, fastauth
from fastauth.database import memory
from fastauth.plugins.jwt import JwtOptions
from fastauth.providers import email_password, jwt

auth = fastauth(
    FastAuthOptions(
        secret_key="replace-me-with-your-application-secret",
        database=memory(),
        plugins=[
            email_password(),
            jwt(
                JwtOptions(disable_private_key_encryption=True),
                signer_factory=lambda registry: CloudKmsSigner(
                    registry,
                    key_id="projects/.../fastauth",
                ),
            ),
        ],
    )
)
```

Setting `disable_private_key_encryption=True` tells fastauth not to AES-GCM
encrypt the stored private key — when KMS is responsible for signing, the
plugin still tracks the public JWKS but the in-database private material can
be a placeholder.

## Local fallback

`LocalKmsSigner` is the default signer; it loads the encrypted private key
from the `jwks_keys` collection, decrypts it with a KEK derived from
`options.secret_key`, and signs in-process. This is appropriate for
development and small deployments.
