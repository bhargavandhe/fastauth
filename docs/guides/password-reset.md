# Password reset

The password-reset flow is constant-time and revokes every existing session
for the affected user on success — a compromised cookie cannot survive a
password change.

## Flow

1. Caller submits an identifier:

    ```http
    POST /auth/forgot-password
    {"email": "alice@example.com"}
    ```

    The endpoint always returns `{"success": true}` so attackers cannot probe
    which addresses are registered.

2. authkit creates a single-use `Verification` row with purpose
   `PASSWORD_RESET`, renders the `reset.html` / `reset.txt` Jinja templates,
   and emits the link via the configured `EmailSender`.

3. The user clicks the link and submits the token plus new password:

    ```http
    POST /auth/reset-password
    {"token": "...", "password": "new-correct-horse-staple"}
    ```

4. On success authkit re-hashes the password, deletes the verification row,
   and calls `session_strategy.revoke_all(user_id)` — every other session is
   killed.

## Configuration

```python
from authkit.config import AuthKitConfig, PasswordResetConfig

config = AuthKitConfig(
    # ...
    password_reset=PasswordResetConfig(
        token_ttl_minutes=30,
        base_reset_url="https://app.example.com/reset",
    ),
)
```

## Events

- `PasswordResetRequested` — fired on `/forgot-password` regardless of
  whether the identifier exists.
- `PasswordResetCompleted` — fired only after a successful reset; carries
  the affected `user_id`.
- `SessionsRevokedAll` — emitted by the session strategy when the cascade
  runs.
