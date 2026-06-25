# Quickstart

authkit's config type is a plain `pydantic.BaseModel`. Every value is passed
explicitly at instantiation time. **The framework never reads environment
variables, `.env` files, or any other external source** — that's the
consumer's responsibility. Pass values from your application settings object,
secret manager, config file, or test fixture and `AuthKitConfig` will validate
them.

```python
from fastapi import FastAPI
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import SecretStr

from authkit import AuthKit, AuthKitConfig
from authkit.config import DatabaseConfig
from authkit.plugins.api_key import ApiKeyPlugin
from authkit.plugins.audit_logs import AuditLogsPlugin
from authkit.plugins.jwt import JwtPlugin
from authkit.plugins.openapi import OpenApiPlugin
from authkit.storage.beanie import BeanieAdapter

app_secret = "replace-me-with-a-secret-from-your-application-config"
mongo_url = "mongodb://localhost:27017"
database_name = "myapp"

config = AuthKitConfig(
    secret_key=SecretStr(app_secret),
    database=DatabaseConfig(
        mongo_url=mongo_url,
        database_name=database_name,
    ),
)

mongo_client = AsyncIOMotorClient(config.database.mongo_url, uuidRepresentation="standard")
mongo_database = mongo_client[config.database.database_name]
adapter = BeanieAdapter(mongo_database)

auth = AuthKit(
    config,
    adapter=adapter,
    plugins=[ApiKeyPlugin(), JwtPlugin(), AuditLogsPlugin(), OpenApiPlugin()],
)

app = FastAPI(title="My App", lifespan=adapter.lifespan(auth))
auth.install(app)
```

`auth.install(app)` attaches the router and installs CSRF/security-header
middleware on the host FastAPI application. If you use `auth.as_asgi()` as a
standalone app instead, authkit returns an app with the same routes and
middleware already installed.

For Postgres, install `authkit-fastapi[postgres,jwt]` and pass an async
SQLAlchemy URL or engine explicitly:

```python
from fastapi import FastAPI
from pydantic import SecretStr

from authkit import AuthKit, AuthKitConfig
from authkit.plugins.jwt import JwtPlugin
from authkit.storage.postgres import PostgresAdapter

config = AuthKitConfig(secret_key=SecretStr("replace-me-with-your-application-secret"))
adapter = PostgresAdapter.from_url("postgresql+asyncpg://user:pass@localhost/myapp")
auth = AuthKit(config, adapter=adapter, plugins=[JwtPlugin()])

app = FastAPI(title="My App", lifespan=adapter.lifespan(auth))
auth.install(app)
```

## Protecting routes with `CurrentUser` / `CurrentSession`

The `AuthKit` instance exposes four FastAPI dependency callables:

| Dependency | Returns | On anonymous request |
|---|---|---|
| `auth.get_current_user` | `User` | raises HTTP 401 with `code: INVALID_CREDENTIALS` |
| `auth.get_optional_current_user` | `User \| None` | returns `None` (never raises) |
| `auth.get_current_session` | `SessionContext` | raises HTTP 401 |
| `auth.get_optional_current_session` | `SessionContext \| None` | returns `None` |

Both cookie and `Authorization: Bearer` transports are honoured automatically.

**Two equivalent ways to use them** — pick whichever fits your codebase style:

```python
# Style 1 — `Depends` as default value (always works, even with
# `from __future__ import annotations`):
from fastapi import Depends
from authkit.domain.models import User

@app.get("/me")
async def me(user: User = Depends(auth.get_current_user)) -> User:
    return user

# Style 2 — `Annotated` type alias (idiomatic, requires `auth` to be a
# module-level name so PEP 563 string-annotation resolution can find it):
from typing import Annotated
from fastapi import Depends
from authkit.domain.models import User

CurrentUser = Annotated[User, Depends(auth.get_current_user)]

@app.get("/me")
async def me(user: CurrentUser) -> User:
    return user
```

If you use `from __future__ import annotations` AND want the `Annotated`
style, make sure `auth` is a module-level binding (not a closure variable in
a fixture or factory function) — FastAPI's `get_type_hints` call resolves
string annotations against the function's `__globals__`, which only contains
module-level names.

## Run migrations and serve

```bash
uv run authkit generate-secret  # prints a fresh 64-char secret

uv run authkit migrate --mongo-url mongodb://localhost:27017 --database myapp
uv run authkit migrate --postgres-url postgresql+asyncpg://user:pass@localhost/myapp
uv run uvicorn examples.quickstart.app:app --reload
```

`uvicorn[standard]` ships with the project's `dev` extra, so
`uv sync --all-extras` once before running this command. The `dev` extra
exists to support local development; production deployments will install
their own ASGI server.

Open `http://localhost:8000/auth/reference` for the Scalar API explorer.
