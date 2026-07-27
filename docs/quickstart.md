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
from fastauth.options import CookieOptions
from fastauth import email_password

app_secret = "replace-me-with-a-secret-from-your-application-config"
options = FastAuthOptions(
    secret_key=SecretStr(app_secret),
    database=memory(),
    cookie=CookieOptions(secure=False),
)
auth = FastAuth(options, plugins=[email_password()])

app = FastAPI(title="My App", lifespan=auth.lifespan)
app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
auth.add_middleware(app)
```

`auth.router` is prefix-free, so the host application owns its final prefix,
tags, and global dependencies. `auth.add_middleware(app)` installs the
FastAuth exception handler, CSRF middleware, and security headers without
including routes. If you use `auth.as_asgi()` as a standalone app instead,
FastAuth returns an app with the configured base path and middleware already
installed.

`memory()` is suitable for tests and local demos. Pick `mongo(database=...)` or
`postgres(url=...)` explicitly for persistent deployments.

`CookieOptions(secure=False)` is only for local HTTP development. Keep secure
cookies enabled for HTTPS deployments; production validation requires it.

For Postgres, install `fastauth-py[postgres,jwt]` and pass an async
SQLAlchemy URL or engine explicitly:

```python
from fastapi import FastAPI
from pydantic import SecretStr

from fastauth import FastAuth, FastAuthOptions
from fastauth.database import postgres
from fastauth import email_password, jwt

options = FastAuthOptions(
    secret_key=SecretStr("replace-me-with-your-application-secret"),
    database=postgres(url="postgresql+asyncpg://user:pass@localhost/myapp"),
)
auth = FastAuth(options, plugins=[email_password(), jwt()])

app = FastAPI(title="My App", lifespan=auth.lifespan)
app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
auth.add_middleware(app)
```

## Protecting routes with `CurrentUser` / `CurrentSession`

The `FastAuth` instance exposes one dependency namespace for application routes:

| Dependency | Returns | On anonymous request |
|---|---|---|
| `auth.depends.user()` | `UserView` | raises HTTP 401 with `code: INVALID_CREDENTIALS` |
| `auth.depends.optional_user()` | `UserView \| None` | returns `None` (never raises) |
| `auth.depends.session()` | `SessionContext` | raises HTTP 401 |
| `auth.depends.optional_session()` | `SessionContext \| None` | returns `None` |

Both cookie and `Authorization: Bearer` transports are honoured automatically.

The initialized instance exposes bound aliases for the two required
dependencies:

```python
from fastauth import UserView

@app.get("/me")
async def me(user: auth.CurrentUser) -> UserView:
    return user

@app.get("/my-session")
async def my_session(session: auth.CurrentSession) -> dict[str, str]:
    return {"session_id": session.session.id}
```

If you use `from __future__ import annotations`, keep `auth` as a module-level
binding. FastAPI resolves the string annotation through the route function's
module globals.

For an auth instance created inside a factory or closure, use the explicit form:

```python
from fastapi import Depends
from fastauth import UserView

@app.get("/me")
async def me(user: UserView = Depends(auth.depends.user())) -> UserView:
    return user
```

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
