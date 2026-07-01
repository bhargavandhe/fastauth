# Adapters

A `DatabaseAdapter` is the storage seam between fastauth's core auth flows and
your database. The protocol lives at `fastauth.storage.base.DatabaseAdapter`
and covers users, accounts, sessions, refresh tokens, and verifications.

Optional capabilities live in separate protocols:

- `ApiKeyStore` for `ApiKeyPlugin`.
- `JwksKeyStore` for `JwtPlugin` and JWT session strategy.
- `AuditLogStore` for `AuditLogsPlugin`.
- `RateLimitStore` when `RateLimitOptions.storage == DATABASE`.

`InMemoryAdapter`, `BeanieAdapter`, and `PostgresAdapter` implement every
first-party capability.

```python
from pymongo import AsyncMongoClient

from fastauth import FastAuth, FastAuthOptions
from fastauth.database import mongo
from fastauth.providers import email_password

mongo_client = AsyncMongoClient("mongodb://localhost:27017", uuidRepresentation="standard")
mongo_database = mongo_client["myapp"]
auth = FastAuth(
    FastAuthOptions(
        secret_key="replace-me-with-your-application-secret",
        database=mongo(mongo_database),
        plugins=[email_password()],
    )
)
```

The Mongo adapter stores primary keys and Mongo-owned relation ids as
`ObjectId` values in BSON. Domain models still expose them as strings at the
boundary; the adapter converts them to and from `ObjectId` internally.
Protocol identifiers such as JWKS `kid` remain strings because they are not
Mongo references.

To namespace fastauth collections inside a shared Mongo database, pass a
prefix and/or suffix through the Mongo database option:

```python
options = FastAuthOptions(
    secret_key="replace-me-with-your-application-secret",
    database=mongo(
        mongo_database,
        collection_prefix="tenant_",
        collection_suffix="_auth",
    ),
    plugins=[email_password()],
)
```

The final collection name is exactly `<prefix><base><suffix>`, so the example
above writes `tenant_users_auth`, `tenant_sessions_auth`, and so on. This only
selects the collections fastauth uses; it does not rename or migrate existing
Mongo data.

For Postgres, install `fastauth-py[postgres]` and pass a SQLAlchemy async
engine or URL:

```python
from fastauth import FastAuth, FastAuthOptions
from fastauth.database import postgres
from fastauth.providers import email_password

auth = FastAuth(
    FastAuthOptions(
        secret_key="replace-me-with-your-application-secret",
        database=postgres(
            "postgresql+asyncpg://user:pass@localhost/myapp",
            table_prefix="fastauth_",
            table_suffix="",
        ),
        plugins=[email_password()],
    )
)
```

`fastauth migrate --postgres-url postgresql+asyncpg://...` applies the same
tracked schema migrations from the CLI and records the fastauth schema version
in `<prefix>schema_migrations<suffix>`. Postgres table names follow the same
`<prefix><base><suffix>` rule as Mongo collections. For long-lived production
deployments, run the CLI during deploy and pass
`postgres(url, apply_migrations=False)` so the app fails fast if the database
is behind instead of mutating schema at process startup.

The adapter uses FastAuth's string domain IDs as primary keys and stores plugin
data in native Postgres types such as `jsonb` and `bytea`.

Adapters are async-only and operate on the Pydantic domain models directly —
there is no separate ORM layer. To plug in a new backend, implement
`DatabaseAdapter` first. Then add the optional store protocols for the plugins
or configuration you support. First-party adapters should run the shared
`tests/adapters/adapter_contract.py` suite, which verifies the full capability
set.

## Minimum viable adapter

Start with `BaseDatabaseAdapter` and override only the core methods needed by
`DatabaseAdapter`. Those methods cover five groups:

- Users: create, read by id/email/username, pending-email lookup, update, delete.
- Sessions: create, read by token hash, list by user, update, delete one/delete many.
- Refresh tokens: create, read by hash, update, atomic rotate, delete one/user/family.
- Accounts: create, read/list by user, update, delete.
- Verifications: create, read active/by hash, update, delete one/delete many.

```python
from datetime import datetime

from fastauth.domain.enums import ProviderId, VerificationPurpose
from fastauth.domain.models import Account, RefreshToken, Session, User, Verification
from fastauth.storage.base import BaseDatabaseAdapter


class MyAdapter(BaseDatabaseAdapter):
    async def create_user(self, user: User) -> User:
        ...

    async def get_user_by_id(self, user_id: str) -> User | None:
        ...

    async def get_user_by_email(self, email: str) -> User | None:
        ...

    async def get_user_by_username(self, username: str) -> User | None:
        ...

    async def find_user_by_pending_email_change(self, new_email: str) -> User | None:
        ...

    async def update_user(self, user: User) -> User:
        ...

    async def delete_user(self, user_id: str) -> None:
        ...

    # Implement the same pattern for Session, RefreshToken, Account, and
    # Verification methods declared by DatabaseAdapter.
```

`BaseDatabaseAdapter` deliberately does not define optional plugin methods.
That keeps runtime capability checks meaningful: if `ApiKeyPlugin` is
installed, the adapter must actually implement `ApiKeyStore`.

`delete_user(user_id)` is intentionally a cascade for auth-owned user state:
it must remove the user, credential/provider accounts, sessions, refresh
tokens, API keys when supported, and verification rows keyed to the user's
current or pending email address. It must not delete audit logs or JWKS keys.
First-party adapters enforce this contract in the shared adapter tests.

## Optional capabilities

Add optional protocols only when your app enables the matching feature:

```python
from fastauth.domain.models import ApiKey
from fastauth.storage.base import ApiKeyStore


class MyAdapter(BaseDatabaseAdapter, ApiKeyStore):
    async def create_api_key(self, api_key: ApiKey) -> ApiKey:
        ...

    async def get_api_key_by_hash(self, key_hash: str) -> ApiKey | None:
        ...

    # Implement the remaining ApiKeyStore methods before installing ApiKeyPlugin.
```

The same pattern applies to `JwksKeyStore`, `AuditLogStore`, and
`RateLimitStore`. If a required capability is missing, `FastAuth` or the plugin
raises `ConfigError` during startup instead of failing on the first request.
