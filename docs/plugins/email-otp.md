# Email OTP

`EmailOtpPlugin` adds passwordless sign-in, email verification, password
reset, and (optionally) email change via 6-digit one-time codes delivered
to the user's email address. The surface mirrors better-auth's
[`emailOTP` plugin](https://better-auth.com/docs/plugins/email-otp) so
client-side patterns transfer directly.

When enabled, the plugin contributes the following endpoints to
`auth.router`:

| Method | Path | Description |
|---|---|---|
| `POST` | `/auth/email-otp/send-verification-otp` | Issue + email an OTP. `type` ∈ `sign-in \| email-verification \| password-reset` |
| `POST` | `/auth/email-otp/check-verification-otp` | Verify an OTP **without consuming it** (UX pre-check) |
| `POST` | `/auth/sign-in/email-otp` | Consume OTP → return session. Auto-registers if user is new |
| `POST` | `/auth/email-otp/verify-email` | Consume OTP → mark `email_verified=true` |
| `POST` | `/auth/email-otp/request-password-reset` | Issue + email a reset OTP |
| `POST` | `/auth/email-otp/reset-password` | Consume OTP → set new password, revoke sessions |
| `POST` | `/auth/email-otp/request-email-change` | (Auth required) issue OTP for new email — gated by `change_email_enabled` |
| `POST` | `/auth/email-otp/change-email` | (Auth required) consume OTP → update email — gated by `change_email_enabled` |

## Installation

```python
from fastauth import FastAuth, FastAuthConfig
from fastauth.flows.email_otp import EmailOtpConfig
from fastauth.plugins.email_otp import EmailOtpPlugin

auth = FastAuth(
    config,
    adapter=adapter,
    plugins=[
        EmailOtpPlugin(EmailOtpConfig(
            length=6,
            expires_in_seconds=300,
            allowed_attempts=3,
            disable_sign_up=False,
            change_email_enabled=False,
        )),
    ],
)
```

Every config field has a sensible default; the snippet above shows the
defaults explicitly. Pass an empty `EmailOtpConfig()` (or simply
`EmailOtpPlugin()`) to accept all defaults.

## Configuration reference

`EmailOtpConfig` fields:

| Field | Default | Notes |
|---|---|---|
| `length` | `6` | OTP digit count. Range 4–10 (validated at construction). |
| `expires_in_seconds` | `300` | Per-OTP TTL (5 minutes). After this the row is expired and a fresh OTP is required. |
| `allowed_attempts` | `3` | Failed verifications before the OTP row is destroyed. The user must request a new OTP. |
| `disable_sign_up` | `False` | When `True`, sign-in via OTP rejects unknown emails (no auto-register). The send endpoint silently no-ops on unknown emails to preserve anti-enumeration. |
| `change_email_enabled` | `False` | Registers `/email-otp/request-email-change` and `/email-otp/change-email`. |
| `change_email_verify_current` | `False` | When `True`, the email-change request must include an OTP previously sent to the user's *current* email (`type=email-verification`) before a new-email OTP is issued. |

## Sign-in flow

```python
# 1. Client requests an OTP
await client.post(
    "/auth/email-otp/send-verification-otp",
    json={"email": "alice@example.com", "type": "sign-in"},
)
# 2. User reads the email, types the 6-digit code into your UI
# 3. Client exchanges the OTP for a session
response = await client.post(
    "/auth/sign-in/email-otp",
    json={"email": "alice@example.com", "otp": "123456", "name": "Alice"},
)
# response.json() carries {user, session, token?, refresh_token?}
# A session cookie is set on the response.
```

If the email doesn't match an existing user, a new user is created with
`email_verified=true` (OTP delivery proved email ownership) and an
`Account` row tied to `ProviderId.EMAIL_OTP` with no password. The
`name` field on the request is only consulted for new users.

To restrict to existing users only, set `disable_sign_up=True`. The send
endpoint will silently succeed on unknown emails (anti-enumeration) and
the sign-in endpoint will return `401 INVALID_CREDENTIALS`.

## Verify email

```python
await client.post(
    "/auth/email-otp/send-verification-otp",
    json={"email": user.email, "type": "email-verification"},
)
await client.post(
    "/auth/email-otp/verify-email",
    json={"email": user.email, "otp": "123456"},
)
```

This is the OTP-based equivalent of `/auth/verify-email`. Both flows
coexist; pick whichever your UI prefers.

## Password reset

```python
await client.post(
    "/auth/email-otp/request-password-reset",
    json={"email": user.email},
)
await client.post(
    "/auth/email-otp/reset-password",
    json={"email": user.email, "otp": "123456", "password": "new-secure-pw-1"},
)
```

The reset endpoint revokes every active session for the user (same
behaviour as the token-based `/auth/reset-password`). If the user
originally signed up via OTP and never set a password, the reset flow
creates the credential `Account` row for them; subsequent sign-ins via
`/auth/sign-in/email` will work with the new password.

## Change email

Set `change_email_enabled=True` to register the change-email pair.
Without an authenticated session both endpoints return `401`.

```python
# Request OTP for the new email
await client.post(
    "/auth/email-otp/request-email-change",
    json={"new_email": "new@example.com"},
    cookies=session_cookies,
)
# Confirm with the OTP delivered to the new email
await client.post(
    "/auth/email-otp/change-email",
    json={"new_email": "new@example.com", "otp": "123456"},
    cookies=session_cookies,
)
```

For added security, set `change_email_verify_current=True`. The request
endpoint then requires a second OTP that the client must have separately
obtained via `send-verification-otp` with `type=email-verification`. This
double-confirms the change is initiated by someone who controls *both*
the current and new email addresses, defending against the case where an
attacker has temporarily-active session cookies.

```python
# 1. Send an OTP to the user's current email first
await client.post(
    "/auth/email-otp/send-verification-otp",
    json={"email": current_email, "type": "email-verification"},
    cookies=session_cookies,
)
# 2. Submit the change request with that OTP, plus the new email
await client.post(
    "/auth/email-otp/request-email-change",
    json={"new_email": "new@example.com", "otp_for_current": "123456"},
    cookies=session_cookies,
)
# 3. Then confirm with the OTP delivered to the new email
await client.post(
    "/auth/email-otp/change-email",
    json={"new_email": "new@example.com", "otp": "654321"},
    cookies=session_cookies,
)
```

## Pre-checking an OTP

`POST /auth/email-otp/check-verification-otp` verifies an OTP without
consuming it. Useful for "submit your code" forms that want to display a
"correct so far" indicator before posting to the consume endpoint.

```python
await client.post(
    "/auth/email-otp/check-verification-otp",
    json={"email": user.email, "type": "sign-in", "otp": "123456"},
)
```

The check endpoint **does** increment the per-OTP failure counter on
incorrect codes — a cap is necessary regardless of which endpoint
receives the wrong code. It does **not** feed the global account
lockout, so a UX pre-check that finds a typo doesn't risk locking the
account.

## Security notes

- **OTPs are stored hashed.** The `Verification.value_hash` column
  contains the SHA-256 of the plaintext OTP; the plain code is never
  persisted. A database breach therefore doesn't leak live OTPs. As a
  consequence, the "reuse" resend strategy from better-auth is not
  available — every send issues a fresh OTP and invalidates any prior
  un-consumed code (the "rotate" strategy).
- **Per-OTP attempt cap.** Each OTP row carries an `attempt_count`. When
  it equals `allowed_attempts` the row is deleted; the user must
  request a fresh OTP.
- **Lockout coupling.** Failed sign-in / verify-email / reset / change
  OTP attempts feed `AccountLockoutTracker.record_failure(identifier)`
  exactly as failed password attempts do. Five OTP failures in 15
  minutes (or whatever your `LockoutConfig` says) lock the account just
  like five wrong passwords would.
- **Anti-enumeration on sends.** The send endpoint always returns
  `{"success": true}`, regardless of whether the email matches an
  existing user. This holds for `email-verification` and `password-reset`
  where the recipient must already be a user, and for `sign-in` when
  `disable_sign_up=True`.
- **One-time use.** A successful verification deletes the row; the same
  OTP cannot be replayed for a second action.
- **Rate limiting.** The plugin contributes per-IP rate-limit rules:
  - 3/min on `send-verification-otp` and `request-password-reset`
  - 10/min on `check-verification-otp`, `sign-in`, `verify-email`,
    `reset-password`. These compose with the global `RateLimitConfig`.

## Audit events

The plugin publishes three new events that `AuditLogsPlugin` will
auto-capture:

- `OtpRequested(identifier, purpose)` — emitted on every issuance. No
  plaintext OTP.
- `OtpVerified(identifier, purpose, user_id)` — emitted on every
  successful verify.
- `OtpVerifyFailed(identifier, purpose, attempt_count)` — emitted on
  every failed verify.

The internal `OtpGenerated(identifier, purpose, plain)` event is also
published (carrying the plaintext) but is filtered out of audit logs
automatically — it exists for `TestUtilsPlugin.get_otp(...)` to capture
codes during integration tests.

## Capturing OTPs in tests

```python
from fastauth.plugins.email_otp import EmailOtpPlugin
from fastauth.plugins.test_utils import TestUtilsPlugin, TestUtilsConfig

auth = FastAuth(
    config,
    adapter=InMemoryAdapter(),
    plugins=[
        EmailOtpPlugin(),
        TestUtilsPlugin(TestUtilsConfig(capture_otp=True)),
    ],
)

# Trigger send
await client.post("/auth/email-otp/send-verification-otp",
                 json={"email": "alice@example.com", "type": "sign-in"})
# Read it back
helpers = auth.context.plugins.by_id["fastauth-test-utils"].helpers
otp = helpers.get_otp("alice@example.com")
```

`TestUtilsPlugin` subscribes to `OtpGenerated` and stores plaintext OTPs
in memory keyed by `identifier`. Only enable `capture_otp=True` in
tests — production deployments should not capture plaintext codes.
