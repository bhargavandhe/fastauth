# Password reset

The password-reset flow is constant-time and revokes every existing session
and every refresh token for the affected user on success. Compromised cookies
or refresh tokens cannot survive a password change.

## Flow

1. Caller submits an identifier:

    ```http
    POST /auth/forgot-password
    {"email": "alice@example.com"}
    ```

    The endpoint always returns `{"success": true}` so attackers cannot probe
    which addresses are registered.

2. fastauth creates a single-use `Verification` row with purpose
   `PASSWORD_RESET`, renders the `reset.html` / `reset.txt` Jinja templates,
   and emits the link via the configured `EmailSender`.

3. The user clicks the link and submits the token plus new password:

    ```http
    POST /auth/reset-password
    {"email": "alice@example.com", "token": "...", "newPassword": "new-correct-horse-staple"}
    ```

4. On success fastauth re-hashes the password, deletes the verification row,
   calls `session_strategy.revoke_all(user_id)`, and revokes every refresh
   token for that user.

## Configuration

```python
from fastauth import FastAuthOptions
from fastauth.options import PasswordResetOptions
from datetime import timedelta

options = FastAuthOptions(
    # ...
    password_reset=PasswordResetOptions(
        expires_in=timedelta(minutes=30),
        callback_path="/reset",
    ),
)
```

Callback URLs are derived from `FastAuthOptions.app.base_url` plus
`callback_path`. Use `callback_url_override` only when the email link must
point at a different origin.

## Events

- `PasswordResetRequested` — fired on `/forgot-password` regardless of
  whether the identifier exists.
- `PasswordResetCompleted` — fired only after a successful reset; carries
  the affected `user_id`.
- `SessionsRevokedAll` — emitted by the session strategy when the cascade
  runs.
