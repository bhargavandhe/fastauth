# User Management

fastauth ships authenticated endpoints for common account settings screens.

## Update Profile

`PATCH /auth/user` updates the current user's mutable profile fields:

```json
{
  "name": "Alice",
  "image": "https://example.com/avatar.png",
  "metadata": {"plan": "pro"}
}
```

Omitted fields are preserved. `name` and `image` can be set to `null` to
clear them. `metadata` must be an object when present and replaces the stored
metadata object; send `{}` to clear it.

## Password Operations

`POST /auth/set-password` adds a credential password to a user that does not
already have one:

```json
{"new_password": "new-secret-42-aaa"}
```

By default this revokes other sessions and keeps the current session alive.
If the user already has a password, the endpoint returns HTTP 409 with
`code: PASSWORD_ALREADY_SET`; use `POST /auth/change-password` instead.

`POST /auth/verify-password` checks the current user's credential password:

```json
{"password": "current-password"}
```

Successful verification returns `{"valid": true}`. Failed attempts reuse the
same lockout counter as sign-in.

## Delete Account

Credential users can delete directly with password verification:

```http
POST /auth/delete-account
```

```json
{"password": "current-password"}
```

Passwordless users, or applications that prefer email confirmation, can use
the two-step token flow:

```http
POST /auth/delete-account/request
POST /auth/delete-account/confirm
```

```json
{"token": "token-from-email"}
```

The confirmation token is sent to the current account email and is configured
by `FastAuthOptions.delete_account`:

```python
from pydantic import SecretStr
from datetime import timedelta
from fastauth import FastAuthOptions
from fastauth.options import DeleteAccountOptions

options = FastAuthOptions(
    secret_key=SecretStr("..."),
    delete_account=DeleteAccountOptions(
        expires_in=timedelta(minutes=15),
        base_confirm_url="https://app.example.com/account/delete/confirm",
        subject="Confirm account deletion",
    ),
)
```

Both deletion paths clear the auth session cookie, delete auth-owned user
state from the adapter, and preserve audit logs.
