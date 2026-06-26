# authkit

A modular, Pydantic-native, async-only authentication library for FastAPI applications.

## Features (v1)

- Email + username / password sign-up, sign-in, sign-out
- Email verification with anti-enumeration
- Password reset that revokes all existing sessions
- User profile update, set-password, verify-password, and verified account deletion
- Beanie / MongoDB and SQLAlchemy / Postgres persistence
- Pluggable session strategies — DB-backed or JWT
- Cookie + Bearer transports
- CSRF / trusted-origin protection
- Per-route rate limiting with IPv6 subnet bucketing
- API keys (with remaining-quota and per-key rate limits)
- JWT / JWKS with key rotation and KMS-pluggable signer
- Audit logs with paginated query API
- Scalar OpenAPI reference at `/auth/reference`
- Test utilities for factories, login helpers, and OTP capture

## Design principles

- **Pydantic everywhere** — every config, payload, and domain model
- **No private variables** — leading underscores are forbidden project-wide
- **Modular** — adding a feature means adding a `Plugin`, not editing core
- **Async-only**, Python 3.11+
- **`pyright --strict` clean**
