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
loads settings, pass this value into `FastAuthConfig`:

```python
from fastauth.config import FastAuthConfig, RateLimitConfig
from fastauth.domain.enums import RateLimitStorageKind

config = FastAuthConfig(
    # ...
    rate_limit=RateLimitConfig(storage=RateLimitStorageKind.DATABASE),
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
from fastapi import FastAPI
from fastauth.storage.postgres import PostgresAdapter

adapter = PostgresAdapter.from_url("postgresql+asyncpg://user:pass@db.example.com/myapp")
app = FastAPI(lifespan=adapter.checked_lifespan(auth))
```

For local development and small deployments, `adapter.lifespan(auth)` applies
pending Postgres migrations before fastauth starts. Prefer the explicit CLI
migration path for production releases where schema changes should be part of
the deploy pipeline.

## Secrets

- `secret_key` — used for cookie signing and as the KEK for the JWKS
  private-key encryption. Rotate by adding the new secret first and listing
  the old one under `secret_key_rotation` for the unwind window.
- Use a secret manager (AWS Secrets Manager, GCP Secret Manager, Vault) and
  pass the resulting value into `FastAuthConfig`; avoid committing secrets.

## Cookie attributes

In production set:

```python
from fastauth.config import CookieConfig

cookie = CookieConfig(
    secure=True,
    same_site="lax",
    domain="app.example.com",
)
```

## Trusted origins

List every browser origin that may call fastauth:

```python
from fastauth.config import CsrfConfig

csrf = CsrfConfig(
    trusted_origins=["https://app.example.com", "https://*.app.example.com"],
)
```

## Health checks

`GET /auth/health` returns `{"status": "ok"}` without touching the database;
use it for liveness probes. For readiness, additionally probe the OpenAPI
schema endpoint.
