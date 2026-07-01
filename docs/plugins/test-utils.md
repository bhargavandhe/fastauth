# Test utils

`TestUtilsPlugin` contributes no HTTP endpoints. Instead it exposes a
`TestHelpers` surface that test code retrieves from the plugin registry:

```python
from fastauth import FastAuth, FastAuthOptions
from fastauth.database import memory
from fastauth.plugins.test_utils import TestUtilsOptions
from fastauth.providers import email_password, test_utils

auth = FastAuth(
    FastAuthOptions(
        secret_key="replace-me-with-your-application-secret",
        database=memory(),
        plugins=[email_password(), test_utils(TestUtilsOptions(capture_otp=True))],
    )
)

helpers = auth.context.plugins.by_id["fastauth-test-utils"].helpers
```

## Helper surface

- `helpers.create_user(**overrides)` — build an unsaved `User` with sensible
  defaults.
- `helpers.save_user(user)` / `helpers.delete_user(user_id)` — go through the
  bound `DatabaseAdapter`.
- `helpers.login(user_id)` — create a session and return a `LoginResult`
  containing the plain token, prebuilt headers, and serialised cookies ready
  for `httpx.AsyncClient`.
- `helpers.get_auth_headers(user_id)` — shortcut returning only the
  `{"cookie": "..."}` dict.
- `helpers.get_otp(identifier)` / `helpers.clear_otps()` — read or wipe the
  most recent captured one-time password (requires `capture_otp=True`).

## Example

```python
user = await helpers.save_user(helpers.create_user(email="alice@example.com"))
session = await helpers.login(user.id)
response = await client.get("/auth/get-session", headers=session.headers)
```
