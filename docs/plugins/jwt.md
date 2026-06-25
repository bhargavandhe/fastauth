# JWT

`JwtPlugin` adds `POST /auth/token` and `GET /auth/jwks` to the router and,
when installed, injects a `set-auth-jwt` response header on
`GET /auth/get-session` carrying a freshly-signed JWT for the active user.

## Endpoints

- `POST /auth/token` — exchange the current session for a JWT
  (default expiry 15 minutes).
- `GET /auth/jwks` — public JWKS document used to verify those tokens.

## Config

`JwtPluginConfig` covers algorithm choice (`alg`, default `EdDSA`),
`expires_in_seconds`, `issuer`, `audience`, `rotation_interval_seconds`,
`grace_period_seconds`, `disable_setting_jwt_header`,
`disable_private_key_encryption`, `jwks_path`, and `token_path`. The plugin
also accepts a custom `payload_builder` and a `signer_factory` for KMS-backed
signing — see the [KMS signing guide](../guides/kms-signing.md).

## Example

```python
from authkit.plugins.jwt import JwtPlugin, JwtPluginConfig

auth = AuthKit(
    config,
    adapter=adapter,
    plugins=[JwtPlugin(JwtPluginConfig(
        issuer="https://app.example.com",
        audience="https://api.example.com",
        rotation_interval_seconds=60 * 60 * 24 * 30,
    ))],
)
```
