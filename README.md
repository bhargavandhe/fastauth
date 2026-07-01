# fastauth

A modular, Pydantic-native, async-only authentication library for FastAPI.

```bash
pip install fastauth-py
```

```python
from fastapi import FastAPI
from pydantic import SecretStr

from fastauth import FastAuth, FastAuthOptions
from fastauth.database import memory
from fastauth.providers import email_password

app_secret = "replace-me-with-a-secret-from-your-application-config"

auth = FastAuth(
    FastAuthOptions(
        secret_key=SecretStr(app_secret),
        database=memory(),
    ),
    plugins=[email_password()],
)

app = FastAPI(lifespan=auth.lifespan)
auth.mount(app)
```

That's it. You now have `/auth/sign-up/email`, `/auth/sign-in/email`,
`/auth/sign-out`, `/auth/get-session`, `/auth/verify-email`,
`/auth/forgot-password`, `/auth/reset-password`, `/auth/change-password`,
`/auth/set-password`, `/auth/verify-password`, `/auth/user`,
`/auth/delete-account`, `/auth/delete-account/request`,
`/auth/delete-account/confirm`,
`/auth/change-email/{request,confirm}`, `/auth/sessions` (list / revoke /
revoke-others), `/auth/refresh`, and `/auth/health` wired into your FastAPI
application. Rate-limiting, account-lockout, and refresh tokens are part of
the router. CSRF and security headers are ASGI middleware installed by
`auth.mount(app)`. If you use `auth.as_asgi()` instead, fastauth returns a
standalone app with the same routes and middleware already installed.

## Why fastauth

Built deliberately for the **modern Python web stack** — FastAPI + Pydantic
v2 + async-only + MongoDB or Postgres persistence:

- **Pydantic v2 everywhere.** Every domain model, every request body, every
  response is a `BaseModel`. No `dataclass`/`NamedTuple`/`TypedDict` smuggled
  in. Four documented carve-outs for plain dicts (OpenAPI schema, JWK,
  JWT payload, HTTP headers); everything else is typed.
- **Async-only.** No sync wrappers, no thread-pool shims. Your event loop
  doesn't get hijacked.
- **Strict-typed.** `pyright --strict` passes with **0 errors, 0 warnings**.
  `py.typed` marker ships with the wheel — your IDE and your CI get full
  type information.
- **Source-agnostic options.** `FastAuthOptions` is a plain `BaseModel`. The
  framework **never reads process-level configuration**. You build config
  from your application settings object, vault client, parameter store, or
  test fixture and pass it in explicitly.
- **Plugins as first-class extension points.** Seven built-in providers
  (`email_password()`, `api_key()`, `jwt()`, `email_otp()`, `audit_logs()`,
  `openapi()`, `test_utils()`) — each contributes endpoints,
  event handlers, lifecycle hooks, and rate-limit policies through a
  tight `Plugin` ABC. Write your own for OAuth providers, webhooks,
  custom MFA — whatever your app needs.
- **Capability-based storage protocols.** `DatabaseAdapter` covers the core
  auth flows. Optional surfaces (`ApiKeyStore`, `JwksKeyStore`,
  `AuditLogStore`, `RateLimitStore`) are only required when you enable the
  matching plugin or database-backed feature.
- **Pure events.** A single typed `EventBus` carries 19 concrete
  `AuthEvent` subclasses (`UserSignedUp`, `UserEmailVerified`,
  `PasswordChanged`, `AccountLockedOut`, …). Subscribe and react —
  send emails, ping Slack, write audit rows, whatever.

## What's in the box

### Auth flows
- Sign-up / sign-in / sign-out by email or username
- Email verification with anti-enumeration
- Password reset with anti-enumeration and session-wide revoke
- Authenticated change-password (keeps current session, revokes others)
- Authenticated profile update, set-password, verify-password, and
  account deletion with password or email-token verification
- Authenticated change-email with re-verification
- Refresh tokens with **one-time-use rotation** and
  **family-revocation on reuse** (OAuth 2.1-style theft detection)
- Multi-session management: list, revoke one, revoke-all-except-current

### Sessions
- Database-backed sessions (revocable, IP/UA bound) **or** JWT sessions
  (stateless, JWKS-signed). One config flag flips between them.
- JWKS with auto-generated keys, AES-GCM at-rest encryption with master-key
  rotation support, and an opt-in `set-auth-jwt` response header that
  attaches a JWT to every authenticated response.
- Local key signing **or** plug in your own `KmsSigner` (HSM, AWS KMS,
  GCP KMS, …) via a tiny Protocol.
- JWT/JWKS crypto has not been independently audited. For high-stakes
  production deployments, use an external KMS/HSM signer and run your own
  security review before relying on local private-key storage.

### Security
- **Argon2id** password hashing (configurable cost).
- **Account lockout** — HTTP 423 + `Retry-After` after 5 failed sign-ins in 15 min.
- **CSRF middleware** — Origin/Referer validation on state-changing methods,
  bearer-only requests are exempt.
- **Rate limiting** with /64 IPv6-subnet bucketing, per-(IP, path) windowing,
  pluggable storage (memory, MongoDB, Postgres).
- **Security headers** — HSTS, `X-Frame-Options`, `X-Content-Type-Options`,
  `Referrer-Policy` on by default; opt-in `Permissions-Policy` and CSP.

### Plugins (each optional)
- **email_password()** — sign-up, sign-in, password reset, email verification,
  account management, refresh tokens, and session management.
- **api_key()** — create/verify/list/update/delete API keys with optional
  refilling quotas and per-key rate limits.
- **jwt()** — `/auth/token` to mint a JWT from a session, `/auth/jwks`
  for the public key set.
- **email_otp()** — passwordless sign-in, email verification, password
  reset, and (optional) email change via 6-digit OTPs delivered to email.
  Hashed storage, per-OTP attempt cap, lockout-coupled.
- **audit_logs()** — auto-captures every `AuthEvent` into a paginated
  audit-log collection.
- **openapi()** — Scalar UI at `/auth/reference`, OpenAPI 3.1 schema
  at `/auth/openapi.json`.
- **test_utils()** — factories, login helpers, OTP capture for tests.

### Developer experience
- **`CurrentUser` / `CurrentSession` FastAPI dependencies** with optional
  variants, both `Depends(...)` and `Annotated[...]` calling styles
  documented.
- **Explicit storage wiring** — choose `memory()`, `mongo(database)`,
  `postgres(url)`, or `custom(adapter)`. Fastauth never reads storage settings
  from the process environment.
- **`auth.mount(app)`** — install routes, CSRF, and security headers on your
  FastAPI app in one call. `FastAuth.as_asgi()` still returns a standalone app
  when you want fastauth mounted separately.
- **Typer CLI** — `fastauth init --backend memory|mongo|postgres`,
  `fastauth migrate`, `fastauth generate-secret`.
- **mkdocs-material docs** + quickstart example app with its own test suite.

## Installation

```bash
# Core (in-memory adapter only — useful for tests and local dev)
pip install fastauth-py

# MongoDB-backed production
pip install fastauth-py[beanie,jwt]

# Postgres-backed production
pip install fastauth-py[postgres,jwt]

# All implemented optional extras
pip install fastauth-py[beanie,postgres,jwt,cli,docs]
```

Extras: `beanie` (MongoDB), `postgres` (SQLAlchemy async + asyncpg), `jwt`
(JOSE signing + crypto for at-rest JWK encryption), `cli` (Typer CLI),
`docs` (mkdocs-material toolchain).

Python 3.11+ required. FastAPI 0.115+, Pydantic 2.8+.

## Protecting routes

```python
from fastapi import Depends
from fastauth.api.responses import UserView

@app.get("/me")
async def me(user: UserView = Depends(auth.get_current_user_view)) -> UserView:
    return user
```

Or with the `Annotated` style (FastAPI's idiom):

```python
from typing import Annotated
from fastapi import Depends
from fastauth.api.responses import UserView

CurrentUser = Annotated[UserView, Depends(auth.get_current_user_view)]

@app.get("/me")
async def me(user: CurrentUser) -> UserView:
    return user
```

Cookie auth and `Authorization: Bearer …` both work — fastauth handles either
transparently. Use `auth.get_optional_current_user` if anonymous requests
are allowed.

## Configuration

`FastAuthOptions` is a plain `pydantic.BaseModel`. Every field has a sensible
default; pass only what you want to override:

```python
from pydantic import SecretStr
from datetime import timedelta

from fastauth import FastAuth, FastAuthOptions
from fastauth.database import memory
from fastauth.options import (
    AppOptions, CookieOptions, CsrfOptions,
    LockoutOptions, RefreshTokenOptions, SecurityHeadersOptions,
)
from fastauth.providers import email_password

options = FastAuthOptions(
    secret_key=SecretStr("…"),
    database=memory(),
    app=AppOptions(name="My App", base_url="https://myapp.com"),
    cookie=CookieOptions(secure=True, same_site="strict"),
    csrf=CsrfOptions(trusted_origins=("https://myapp.com",)),
    lockout=LockoutOptions(max_failures=10, window=timedelta(minutes=5)),
    refresh_token=RefreshTokenOptions(max_age=timedelta(days=14)),
    security_headers=SecurityHeadersOptions(
        content_security_policy="default-src 'self'",
    ),
)

auth = FastAuth(options, plugins=[email_password()])
```

16 sub-configs cover `app`, `session`, `cookie`, `password`, `email`,
`email_verification`, `password_reset`, `email_change`, `delete_account`,
`rate_limit`, `csrf`, `lockout`, `refresh_token`, `security_headers`,
`advanced`, plus the top-level `database` backend. Plugins are behavior
objects passed to `FastAuth(..., plugins=[...])`.

See [docs/concepts/config.md](docs/concepts/config.md) for the full reference.

## Documentation

Full docs site: `mkdocs serve` from a checkout.

- [Quickstart](docs/quickstart.md)
- [Config](docs/concepts/config.md) · [Sessions](docs/concepts/sessions.md) ·
  [Plugins](docs/concepts/plugins.md) · [Adapters](docs/concepts/adapters.md) ·
  [CSRF](docs/concepts/csrf.md) · [Events](docs/concepts/events.md) ·
  [Hooks](docs/concepts/hooks.md)
- [Email verification guide](docs/guides/email-verification.md) ·
  [Password reset guide](docs/guides/password-reset.md) ·
  [User management guide](docs/guides/user-management.md) ·
  [KMS signing guide](docs/guides/kms-signing.md)

## Project layout

```
fastauth/
├── config.py / exceptions.py          # top-level
├── domain/        # pure data: enums, models, events
├── security/      # auth primitives: passwords, tokens, sessions, jwt,
│                  #                  refresh_tokens, lockout, rate_limit
├── storage/       # Core/optional adapter protocols + InMemory/Beanie/Postgres backends
├── messaging/     # email + Jinja2 templates
├── flows/         # sign-up, sign-in, verification, refresh, …
├── plugins/       # api_key, jwt, audit_logs, openapi, test_utils
├── runtime/       # FastAuth, AuthContext, AuthApi, EventBus, hooks
├── web/           # FastAPI integration + CSRF + security headers
└── cli/           # Typer CLI
```

## Status

**v0.1.0** — first release. Coverage spans unit tests, adapter-contract tests,
integration flows, CLI behavior, and the quickstart example. `pyright --strict`
is clean. See [CHANGELOG.md](CHANGELOG.md) for the detailed feature list.

**Roadmap** (v0.2+):
- OAuth providers (Google → GitHub → Apple → Microsoft)
- 2FA / TOTP
- Webhooks
- HIBP password breach check
- Audit-log enrichment (geo-IP, UA parsing)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the project-wide rules
(no leading-underscore names, async-only, Pydantic-everywhere, …).
Quick development loop:

```bash
uv sync --all-extras
uv run ruff check
uv run pyright
uv run pytest
uv run mkdocs serve
```

## License

MIT — see [LICENSE](LICENSE).
