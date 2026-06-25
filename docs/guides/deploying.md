# Deploying

A production authkit deployment has two moving parts: the FastAPI app itself
and a MongoDB cluster. This guide walks through the recommended setup.

## Process model

Run the FastAPI app under uvicorn behind your usual reverse proxy:

```bash
uv run uvicorn myapp.main:app --host 0.0.0.0 --port 8000 --workers 4
```

When you scale beyond a single worker, switch the rate limiter to its
database backend so quotas stay consistent across workers. However your app
loads settings, pass this value into `AuthKitConfig`:

```python
from authkit.config import AuthKitConfig, RateLimitConfig
from authkit.domain.enums import RateLimitStorageKind

config = AuthKitConfig(
    # ...
    rate_limit=RateLimitConfig(storage=RateLimitStorageKind.DATABASE),
)
```

## Database indexes

The Beanie adapter ships every collection's indexes via `init_beanie_documents`.
Run the migration command once during deploy:

```bash
uv run authkit migrate \
  --mongo-url "mongodb://db.example.com:27017" \
  --database "myapp"
```

## Secrets

- `secret_key` — used for cookie signing and as the KEK for the JWKS
  private-key encryption. Rotate by adding the new secret first and listing
  the old one under `secret_key_rotation` for the unwind window.
- Use a secret manager (AWS Secrets Manager, GCP Secret Manager, Vault) and
  pass the resulting value into `AuthKitConfig`; avoid committing secrets.

## Cookie attributes

In production set:

```python
from authkit.config import CookieConfig

cookie = CookieConfig(
    secure=True,
    same_site="lax",
    domain="app.example.com",
)
```

## Trusted origins

List every browser origin that may call authkit:

```python
from authkit.config import CsrfConfig

csrf = CsrfConfig(
    trusted_origins=["https://app.example.com", "https://*.app.example.com"],
)
```

## Health checks

`GET /auth/health` returns `{"status": "ok"}` without touching the database;
use it for liveness probes. For readiness, additionally probe the OpenAPI
schema endpoint.
