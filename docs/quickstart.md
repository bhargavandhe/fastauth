# Quickstart

fastauth's options type is a plain `pydantic.BaseModel`. Every value is passed
explicitly at instantiation time. **The framework never reads environment
variables, `.env` files, or any other external source** — that's the
consumer's responsibility. Pass values from your application settings object,
secret manager, config file, or test fixture and `FastAuthOptions` will validate
them.

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

app = FastAPI(title="My App", lifespan=auth.lifespan)
auth.mount(app)
```

`auth.mount(app)` attaches the router and installs CSRF/security-header
middleware on the host FastAPI application. If you use `auth.as_asgi()` as a
standalone app instead, fastauth returns an app with the same routes and
middleware already installed.

`memory()` is suitable for tests and local demos. Pick `mongo(database)` or
`postgres(url)` explicitly for persistent deployments.

For Postgres, install `fastauth-py[postgres,jwt]` and pass an async
SQLAlchemy URL or engine explicitly:

```python
from fastapi import FastAPI
from pydantic import SecretStr

from fastauth import FastAuth, FastAuthOptions
from fastauth.database import postgres
from fastauth.providers import email_password, jwt

options = FastAuthOptions(
    secret_key=SecretStr("replace-me-with-your-application-secret"),
    database=postgres("postgresql+asyncpg://user:pass@localhost/myapp"),
)
auth = FastAuth(options, plugins=[email_password(), jwt()])

app = FastAPI(title="My App", lifespan=auth.lifespan)
auth.mount(app)
```

## Protecting routes with `CurrentUser` / `CurrentSession`

The `FastAuth` instance exposes public DTO dependencies for application routes,
plus lower-level domain/session dependencies for advanced cases:

| Dependency | Returns | On anonymous request |
|---|---|---|
| `auth.get_current_user_view` | `UserView` | raises HTTP 401 with `code: INVALID_CREDENTIALS` |
| `auth.get_optional_current_user_view` | `UserView \| None` | returns `None` (never raises) |
| `auth.get_current_session` | `SessionContext` | raises HTTP 401 |
| `auth.get_optional_current_session` | `SessionContext \| None` | returns `None` |

Both cookie and `Authorization: Bearer` transports are honoured automatically.

**Two equivalent ways to use them** — pick whichever fits your codebase style:

```python
# Style 1 — `Depends` as default value (always works, even with
# `from __future__ import annotations`):
from fastapi import Depends
from fastauth.api.responses import UserView

@app.get("/me")
async def me(user: UserView = Depends(auth.get_current_user_view)) -> UserView:
    return user

# Style 2 — `Annotated` type alias (idiomatic, requires `auth` to be a
# module-level name so PEP 563 string-annotation resolution can find it):
from typing import Annotated
from fastapi import Depends
from fastauth.api.responses import UserView

CurrentUser = Annotated[UserView, Depends(auth.get_current_user_view)]

@app.get("/me")
async def me(user: CurrentUser) -> UserView:
    return user
```

If you use `from __future__ import annotations` AND want the `Annotated`
style, make sure `auth` is a module-level binding (not a closure variable in
a fixture or factory function) — FastAPI's `get_type_hints` call resolves
string annotations against the function's `__globals__`, which only contains
module-level names.

## Run migrations and serve

```bash
uv run fastauth generate-secret  # prints a fresh 64-char secret

uv run fastauth migrate --mongo-url mongodb://localhost:27017 --database myapp
uv run fastauth migrate --postgres-url postgresql+asyncpg://user:pass@localhost/myapp
uv run uvicorn examples.quickstart.app:app --reload
```

`uvicorn[standard]` ships with the project's `dev` extra, so
`uv sync --all-extras` once before running this command. The `dev` extra
exists to support local development; production deployments will install
their own ASGI server.

Open `http://localhost:8000/auth/reference` for the Scalar API explorer.

## Core user endpoints

The default router includes authenticated user-management endpoints:

| Method | Path | Purpose |
|---|---|---|
| `PATCH` | `/auth/user` | Update `name`, `image`, or replace `metadata`. |
| `POST` | `/auth/set-password` | Add a credential password to a passwordless account. |
| `POST` | `/auth/verify-password` | Verify the current password; failed attempts count toward lockout. |
| `POST` | `/auth/delete-account` | Delete the current account after password verification. |
| `POST` | `/auth/delete-account/request` | Email an account-deletion confirmation token. |
| `POST` | `/auth/delete-account/confirm` | Delete the current account with the emailed token. |

Account deletion clears the auth session cookie and removes auth-owned user
state from the adapter while preserving audit logs.
