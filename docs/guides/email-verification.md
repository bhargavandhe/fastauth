# Email verification

fastauth ships a verification flow that is anti-enumeration by design: the
`POST /auth/send-verification-email` endpoint always returns
`{"success": true}` regardless of whether the email is registered. The actual
token is emitted via the `OtpGenerated` event so tests can capture it without
parsing email bodies.

## Flow

1. Caller requests verification:

    ```http
    POST /auth/send-verification-email
    {"email": "alice@example.com"}
    ```

2. fastauth creates a `Verification` row, renders the `verification.html` /
   `verification.txt` Jinja templates, and dispatches them via the configured
   `EmailSender`. The plaintext token is bundled into the rendered link.

3. The user clicks the link, which lands on your front-end's verify page and
   submits the token to:

    ```http
    POST /auth/verify-email
    {"token": "..."}
    ```

4. On success the response sets a fresh session cookie — the verification
   flow doubles as a sign-in for the verified user.

## Configuration

```python
from fastauth import FastAuthOptions
from fastauth.options import EmailVerificationOptions
from datetime import timedelta

options = FastAuthOptions(
    # ...
    email_verification=EmailVerificationOptions(
        expires_in=timedelta(minutes=15),
        base_verify_url="https://app.example.com/verify",
        require_verified_for_sign_in=True,
    ),
)
```

## Custom email transport

Replace the default `ConsoleEmailSender` with your provider's adapter:

```python
from fastauth import FastAuth

class SesEmailSender:
    async def send(self, message: EmailMessage) -> None:
        ...

auth = FastAuth(options, email_sender=SesEmailSender())
```

## Capturing tokens in tests

Install `test_utils(TestUtilsOptions(capture_otp=True))` and read
`helpers.get_otp(identifier)` after triggering the verification email.
