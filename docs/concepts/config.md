# Configuration

`FastAuthOptions` is a plain `pydantic.BaseModel`. Every nested section is also
a `BaseModel` with `extra="forbid"`, so a typo in any field name is caught at
construction rather than at runtime. **The framework never reads environment
variables**, `.env` files, AWS Secrets Manager, Vault, or any other external
source — every value comes from the constructor. Pydantic v2 validation runs
eagerly on the entire tree at instantiation.

Loading config from your source of choice is the consumer's job. The example
below uses ordinary local variables to emphasize that fastauth only sees the
final values you pass to the constructor.

## Construction

```python
from pydantic import SecretStr
from datetime import timedelta
from pymongo import AsyncMongoClient
from fastauth import FastAuthOptions
from fastauth.database import mongo, postgres
from fastauth.options import (
    AppOptions,
    CookieOptions,
    RateLimitOptions,
    SessionOptions,
)
from fastauth.providers import email_password

app_secret = "replace-me-with-your-application-secret"
mongo_url = "mongodb://db.example.com:27017"
mongo_client = AsyncMongoClient(mongo_url, uuidRepresentation="standard")
mongo_database = mongo_client["myapp"]

options = FastAuthOptions(
    secret_key=SecretStr(app_secret),
    database=mongo(
        mongo_database,
        collection_prefix="tenant_",
        collection_suffix="_auth",
    ),
    plugins=[email_password()],
    app=AppOptions(base_url="https://app.example.com"),
    session=SessionOptions(expires_in=timedelta(days=7)),
    cookie=CookieOptions(same_site="strict"),
    rate_limit=RateLimitOptions(storage="database"),
)
print(options.database.collection_prefix)

postgres_options = FastAuthOptions(
    secret_key=SecretStr(app_secret),
    database=postgres(
        "postgresql+asyncpg://user:pass@db.example.com/app",
        table_prefix="fastauth_",
        table_suffix="_auth",
    ),
    plugins=[email_password()],
)
print(postgres_options.database.url)
print(postgres_options.database.table_suffix)
```

If you use a vault or parameter store, read those values in your application
configuration layer and pass the resulting strings into `FastAuthOptions`.

## Sections

`FastAuthOptions` composes focused Pydantic sections:

| Section | Purpose |
|---|---|
| `secret_key`, `secret_key_rotation` | HMAC for signed cookies and KEK for JWKS private keys; rotation list is checked on decrypt. |
| `app` | Application name, base URL, base path. |
| `session` | DB-backed vs JWT strategy, expiry, idle timeout, refresh rotation. |
| `cookie` | Cookie name, path, domain, `Secure`/`HttpOnly`/`SameSite` attributes. |
| `password` | Argon2id memory/time/parallelism, minimum password length. |
| `email` | From-address, subject lines, optional template directory. |
| `email_verification` | Token TTL, base verify URL, whether sign-in requires a verified email. |
| `password_reset` | Token TTL, base reset URL. |
| `email_change` | Token TTL, base confirm URL, email subject. |
| `delete_account` | Token TTL, base confirm URL, account-deletion email subject. |
| `rate_limit` | Window, max requests, storage backend (memory or DB). |
| `csrf` | Trusted origins, relative-path policy, enable/disable. |
| `lockout` | Account-lockout policy (`max_failures`, `window`). |
| `database` | Database option object from `memory()`, `mongo(database)`, `postgres(url)`, or `custom(adapter)`. |
| `plugins` | Provider/plugin list such as `email_password()`, `jwt()`, or `openapi()`. |
| `advanced` | IP header lookup order, IPv6 subnet bucket size, `__Secure-` cookie prefix flag. |

Pass any subset of sections to override the defaults; omitted sections get
the `BaseModel` `default_factory` values.

`database` defaults to `memory()`. For persistent deployments, pass
`mongo(database)` or `postgres(url)` explicitly.

## HTTP field names

Python models use snake_case field names. Public HTTP request and response
models use Pydantic aliases, so JSON and OpenAPI expose camelCase names such
as `emailVerified`, `refreshToken`, `userId`, and `includeRefreshToken`.

Request bodies accept both Python field names and aliases, but responses emit
one stable camelCase shape. There is no runtime-selectable casing mode.

## Why no process config loader?

Earlier versions shipped an `FastAuthEnvConfig` subclass that layered
`pydantic-settings` on top of the base model. That class has been removed.
The reasoning:

- Tests want to construct config explicitly; an env-loader path forces them
  to monkey-patch process-global state for every test, which leaks between
  tests and obscures intent.
- Production deployments increasingly use vaults, parameter stores, or
  Kubernetes Secrets. Having the framework hard-code one loading convention
  narrowed the integration surface unnecessarily.
- Keeping config loading outside the framework makes the source explicit at
  the application boundary.

The application boundary should look like any other dependency injection:

```python
from fastauth import FastAuthOptions
from fastauth.database import mongo
from fastauth.providers import email_password
from pydantic import SecretStr

options = FastAuthOptions(
    secret_key=SecretStr(app_settings.auth_secret),
    database=mongo(app_settings.mongo_database),
    plugins=[email_password()],
)
```
