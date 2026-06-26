# Configuration

`FastAuthConfig` is a plain `pydantic.BaseModel`. Every nested section is also
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
from fastauth import FastAuthConfig
from fastauth.config import (
    AppConfig,
    CookieConfig,
    DatabaseConfig,
    MongoDatabaseConfig,
    PostgresDatabaseConfig,
    RateLimitConfig,
    SessionConfig,
)

app_secret = "replace-me-with-your-application-secret"
mongo_url = "mongodb://db.example.com:27017"

config = FastAuthConfig(
    secret_key=SecretStr(app_secret),
    app=AppConfig(base_url="https://app.example.com"),
    session=SessionConfig(max_age_seconds=604800),
    cookie=CookieConfig(same_site="strict"),
    rate_limit=RateLimitConfig(storage="database"),
    database=DatabaseConfig(
        backend="mongo",
        mongo=MongoDatabaseConfig(url=mongo_url),
    ),
)
print(config.database.mongo.url)

postgres_config = FastAuthConfig(
    secret_key=SecretStr(app_secret),
    database=DatabaseConfig(
        backend="postgres",
        postgres=PostgresDatabaseConfig(
            url="postgresql+asyncpg://user:pass@db.example.com/app",
            table_prefix="fastauth_",
        ),
    ),
)
print(postgres_config.database.postgres.url)
```

If you use a vault or parameter store, read those values in your application
configuration layer and pass the resulting strings into `FastAuthConfig`.

## Sections

`FastAuthConfig` composes sixteen sub-configs:

| Section | Purpose |
|---|---|
| `secret_key`, `secret_key_rotation` | HMAC for signed cookies and KEK for JWKS private keys; rotation list is checked on decrypt. |
| `app` | Application name, base URL, base path. |
| `session` | DB-backed vs JWT strategy, max age, idle timeout, refresh rotation. |
| `cookie` | Cookie name, path, domain, `Secure`/`HttpOnly`/`SameSite` attributes. |
| `password` | Argon2id memory/time/parallelism, minimum password length. |
| `email` | From-address, subject lines, optional template directory. |
| `email_verification` | Token TTL, base verify URL, whether sign-in requires a verified email. |
| `password_reset` | Token TTL, base reset URL. |
| `email_change` | Token TTL, base confirm URL, email subject. |
| `delete_account` | Token TTL, base confirm URL, account-deletion email subject. |
| `rate_limit` | Window, max requests, storage backend (memory or DB). |
| `csrf` | Trusted origins, relative-path policy, enable/disable. |
| `lockout` | Account-lockout policy (`max_failures`, `window_seconds`). |
| `database` | Backend selector plus nested memory, Mongo, and Postgres settings. |
| `advanced` | IP header lookup order, IPv6 subnet bucket size, `__Secure-` cookie prefix flag. |

Pass any subset of sections to override the defaults; omitted sections get
the `BaseModel` `default_factory` values.

`DatabaseConfig.backend` defaults to `memory`, but `FastAuth` still requires an
explicit adapter instance. Pass `InMemoryAdapter()` for tests/local demos, or
choose `mongo` / `postgres` and pass the matching persistent adapter.

## Wire format

`FastAuthConfig.wire_format` (a `WireFormat` enum) toggles the JSON casing
of every public request and response body. Two modes:

- `WireFormat.SNAKE` — **default**. Output JSON keys are `snake_case`
  (`email_verified`, `refresh_token`, `user_id`, ...). The historical
  fastauth shape; existing clients see no change.
- `WireFormat.CAMEL` — output JSON keys are `camelCase` (`emailVerified`,
  `refreshToken`, `userId`, ...). Useful for JS/TS frontends that prefer
  to keep their domain models in camelCase end-to-end.

Both modes **accept** request bodies in either casing. Send
`{"email_verified": true}` or `{"emailVerified": true}` — both parse
correctly regardless of `wire_format`. Output casing is the only thing
that differs.

```python
from fastauth import FastAuthConfig
from fastauth.domain.enums import WireFormat
from pydantic import SecretStr

config = FastAuthConfig(
    secret_key=SecretStr("..."),
    wire_format=WireFormat.CAMEL,
)
```

### Implementation notes

- The choice is per-`FastAuth` instance. Two `FastAuth` instances with
  different `wire_format` can coexist in the same Python process.
- Camelization happens at response render time via a recursive
  key-walker (`fastauth.web.fastapi.CamelJSONResponse`), not via
  Pydantic alias generation on response models. This means embedded
  domain models like `User` and `Session` get camelCased correctly
  even though they don't carry an alias generator on the model class.
  Persistence via Beanie writes snake_case to MongoDB regardless,
  because the database layer never goes through `CamelJSONResponse`.
- Free-form JSON containers keep their application-defined keys. For example,
  `User.metadata`, API-key `permissions`, audit-log `event_data`, and JWKS
  key parameters are not recursively renamed in camel mode.
- Request-body parsing uses Pydantic's `populate_by_name=True` +
  `alias_generator=to_camel` on the `WireModel` base. This is what
  lets either casing be accepted on input.
- The OpenAPI schema served at `/auth/openapi.json` reflects the
  field-name shape (snake_case) because FastAPI generates the schema
  from the model definition. If your client tooling generates types
  off the schema and you're running in `WireFormat.CAMEL`, run a
  case-conversion step in your codegen pipeline.

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
from fastauth import FastAuthConfig
from fastauth.config import DatabaseConfig, MongoDatabaseConfig
from pydantic import SecretStr

config = FastAuthConfig(
    secret_key=SecretStr(app_settings.auth_secret),
    database=DatabaseConfig(
        backend="mongo",
        mongo=MongoDatabaseConfig(
            url=app_settings.mongo_url,
            database_name=app_settings.database_name,
        ),
    ),
)
```
