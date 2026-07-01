# API keys

`ApiKeyPlugin` provides the `/auth/api-key/*` endpoints for issuing and
verifying long-lived API keys backed by the `ApiKey` model. Keys are stored
hashed; the plain value is shown to the caller exactly once, when the key is
created.

## Endpoints

- `POST /auth/api-key/create` — create a key for the current session (returns the plain `key`).
- `POST /auth/api-key/verify` — verify a key, optionally checking permissions.
- `GET /auth/api-key/list` — paginated list for the current user.
- `POST /auth/api-key/update` — change name/enabled/metadata/permissions.
- `POST /auth/api-key/delete` — revoke a single key.
- `POST /auth/api-key/delete-all-expired` — sweep expired keys.

## Options

`ApiKeyOptions` exposes defaults applied when a create request omits the
matching field: `default_prefix` (e.g. `"ak_"`), `default_remaining` (initial
quota), `default_rate_limit_max`, `default_rate_limit_window`, and
`default_expires_in`. Duration options are `datetime.timedelta` values.

## Example

```python
from fastauth import FastAuthOptions, fastauth
from fastauth.database import memory
from fastauth.plugins.api_key import ApiKeyOptions
from fastauth.providers import api_key, email_password

auth = fastauth(
    FastAuthOptions(
        secret_key="replace-me-with-your-application-secret",
        database=memory(),
        plugins=[
            email_password(),
            api_key(ApiKeyOptions(default_prefix="ak_", default_remaining=10_000)),
        ],
    )
)
```

The plugin emits `ApiKeyCreated`, `ApiKeyRevoked`, and `ApiKeyVerifyFailed`
events so audit logging and downstream subscribers can react.
