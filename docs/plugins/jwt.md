# JWT

`JwtPlugin` adds `POST /auth/token` and `GET /auth/jwks` to the router and,
when installed, injects a `set-auth-jwt` response header on
`GET /auth/get-session` carrying a freshly-signed JWT for the active user.

## Endpoints

- `POST /auth/token` — exchange the current session for a JWT
  (default expiry 15 minutes).
- `GET /auth/jwks` — public JWKS document used to verify those tokens.

## Options

`JwtOptions` covers algorithm choice (`alg`, default `EdDSA`),
`expires_in`, `issuer`, `audience`, `rotation_interval`,
`grace_period`, `disable_setting_jwt_header`,
`disable_private_key_encryption`, `jwks_path`, and `token_path`. The plugin
also accepts a custom `payload_builder` and a `signer_factory` for KMS-backed
signing. Duration options are `datetime.timedelta` values — see the
[KMS signing guide](../guides/kms-signing.md).

## Example

```python
from datetime import timedelta

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
            jwt(JwtOptions(
                issuer="https://app.example.com",
                audience="https://api.example.com",
                rotation_interval=timedelta(days=30),
            )),
        ],
    )
)
```
