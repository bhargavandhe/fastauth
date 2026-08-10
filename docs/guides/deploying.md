# Deploying

A production fastauth deployment has two moving parts: the FastAPI app itself
and a persistence backend. This guide covers MongoDB and Postgres.

## Process model

Run the FastAPI app under uvicorn behind your usual reverse proxy:

```bash
uv run uvicorn myapp.main:app --host 0.0.0.0 --port 8000 --workers 4
```

When you scale beyond a single worker, switch the rate limiter to its
database backend so quotas stay consistent across workers. However your app
loads settings, pass this value into `FastAuthOptions`:

```python
from fastauth import FastAuthOptions
from fastauth.domain.enums import RateLimitStorageKind
from fastauth.options import RateLimitOptions

options = FastAuthOptions(
    # ...
    rate_limit=RateLimitOptions(storage=RateLimitStorageKind.DATABASE),
)
```

## Database schema

The Beanie adapter ships every collection's indexes via `init_beanie_documents`.
Run the migration command once during deploy:

```bash
uv run fastauth migrate \
  --mongo-url "mongodb://db.example.com:27017" \
  --database "myapp"
```

The Postgres adapter ships tracked schema migrations. Run them during deploy,
then start the app with a checked lifespan so a stale database fails fast:

```bash
uv run fastauth migrate \
  --postgres-url "postgresql+asyncpg://user:pass@db.example.com/myapp"
```

```python
from pydantic import SecretStr

from fastauth import FastAuth, FastAuthOptions
from fastauth.database import postgres
from fastauth.options import AppOptions
from fastauth import email_password

options = FastAuthOptions(
    secret_key=SecretStr("replace-me-with-your-application-secret"),
    deployment="production",
    app=AppOptions(base_url="https://app.example.com"),
    database=postgres(
        url="postgresql+asyncpg://user:pass@db.example.com/myapp",
        table_prefix="fastauth_",
        table_suffix="",
        migration_mode="check",
        plugin_migration_mode="check",
    ),
)
auth = FastAuth(
    options,
    plugins=[email_password()],
    email_sender=production_email_sender,
)
```

For local development and small deployments, keep the default
`migration_mode="apply"` and the development-default plugin migration mode
apply pending migrations before fastauth starts. Production defaults plugin
migrations to `check` and rejects an explicit automatic `apply`; prefer the
explicit CLI migration path where schema changes are part of the deploy
pipeline.

## TLS termination and production policies

Production defaults independently require HTTPS URLs, secure cookies,
persistent storage, a non-console email sender, and checked migrations. A
deployment whose application-facing transport is intentionally HTTP can relax
only those transport policies:

```python
from fastauth import ProductionSafetyOptions

options = FastAuthOptions(
    # ...
    deployment="production",
    production_safety=ProductionSafetyOptions(
        require_https=False,
        require_secure_cookies=False,
    ),
)
```

The memory-database, console-sender, and automatic-migration guards remain
enabled. Secret strength and `SameSite=None` cookie safety are unconditional.

## Secrets

- `secret_key` — used for cookie signing and as the KEK for the JWKS
  private-key encryption. Rotate by adding the new secret first and listing
  the old one under `secret_key_rotation` for the unwind window.
- Use a secret manager (AWS Secrets Manager, GCP Secret Manager, Vault) and
  pass the resulting value into `FastAuthOptions`; avoid committing secrets.

## Cookie attributes

In production set:

```python
from fastauth.options import CookieOptions

cookie = CookieOptions(
    secure=True,
    same_site="lax",
    domain="app.example.com",
)
```

## Trusted origins

List every browser origin that may call fastauth:

```python
from fastauth.options import CsrfOptions

csrf = CsrfOptions(
    trusted_origins=["https://app.example.com", "https://*.app.example.com"],
)
```

## Health checks

`GET /auth/health/live` proves the process and router are responsive without
touching storage. `GET /auth/health/ready` returns 200 only after database and
plugin startup completed and the database answers a ping; otherwise it returns
a sanitized 503. Use them as liveness and readiness probes respectively.

Fastauth accepts or creates a bounded `X-Request-ID` and returns it on every
response when `auth.add_middleware(app)` is installed.
