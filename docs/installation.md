# Installation

`fastauth` is published as the `fastauth-py` distribution with optional
extras. Install the combination you need:

```bash
pip install "fastauth-py[beanie,jwt,cli]"
```

The available extras are:

- `beanie` — MongoDB persistence via `beanie` + PyMongo's async client.
- `postgres` — Postgres persistence via SQLAlchemy asyncio + `asyncpg`.
- `jwt` — JWT signing, JWKS rotation, and KMS hooks (`joserfc`, `cryptography`).
- `cli` — the `fastauth` Typer CLI (`typer`, `rich`).
- `dev` — test runner, type checker, linter, and pre-commit hooks.
- `docs` — `mkdocs-material` and `mkdocstrings[python]`.

## Configuration source

`FastAuthOptions` is a plain Pydantic model. fastauth never reads environment
variables directly; your application reads configuration from its own source
and passes values into `FastAuthOptions`.

For example, build config from values your application already owns:

```python
from pydantic import SecretStr
from pymongo import AsyncMongoClient

from fastauth import FastAuthOptions
from fastauth.database import mongo
from fastauth.providers import email_password

mongo_client = AsyncMongoClient("mongodb://localhost:27017", uuidRepresentation="standard")
mongo_database = mongo_client["myapp"]

options = FastAuthOptions(
    secret_key=SecretStr("replace-me-with-your-application-secret"),
    database=mongo(
        mongo_database,
        collection_prefix="tenant_",
        collection_suffix="_auth",
    ),
    plugins=[email_password()],
)
```

## Toolchain commands

Local development uses [uv](https://docs.astral.sh/uv/):

```bash
uv sync --all-extras            # install runtime + dev + docs dependencies
uv run ruff check               # lint
uv run pyright                  # type-check (strict)
uv run pytest                   # run the test suite
```

Once your environment is wired up, generate the project scaffold via the CLI
and apply backend setup explicitly:

```bash
uv run fastauth init --backend memory    # writes auth.py
uv run fastauth init --backend mongo     # writes Mongo scaffold
uv run fastauth init --backend postgres  # writes Postgres scaffold
uv run fastauth migrate --mongo-url mongodb://localhost:27017 --database myapp
uv run fastauth migrate --mongo-url mongodb://localhost:27017 --database myapp --mongo-collection-prefix tenant_ --mongo-collection-suffix _auth
uv run fastauth migrate --postgres-url postgresql+asyncpg://user:pass@localhost/myapp
uv run fastauth migrate --postgres-url postgresql+asyncpg://user:pass@localhost/myapp --postgres-table-prefix tenant_ --postgres-table-suffix _auth
```

The Mongo command initializes Beanie documents and indexes. The Postgres
command applies tracked fastauth schema migrations and records the current
schema version in the database.
