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
from fastauth import FastAuthOptions, fastauth
from fastauth.database import postgres
from fastauth.providers import email_password

options = FastAuthOptions(
    secret_key="replace-me-with-your-application-secret",
    database=postgres(
        "postgresql+asyncpg://user:pass@db.example.com/myapp",
        table_prefix="fastauth_",
        table_suffix="",
        apply_migrations=False,
    ),
    plugins=[email_password()],
)
auth = fastauth(options)
```

For local development and small deployments, omit `apply_migrations=False` to
apply pending Postgres migrations before fastauth starts. Prefer the explicit
CLI migration path for production releases where schema changes should be part
of the deploy pipeline.

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

`GET /auth/health` returns `{"status": "ok"}` without touching the database;
use it for liveness probes. For readiness, additionally probe the OpenAPI
schema endpoint.
