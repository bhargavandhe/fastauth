# Installation

`fastauth` is published as the `fastauth-py` distribution with optional
extras. Version 0.15 requires Python 3.11–3.13 (`>=3.11,<3.14`) and Pydantic 2.11–2.x.
Python 3.14 is not supported: current Beanie 2.x releases declare an upper bound
of `<3.14`. The same Python range applies to core and every extra so the supported
release includes all first-party adapters. Use a Python 3.11, 3.12, or 3.13
environment before installing; do not bypass dependency Python-version checks.

The CLI extra requires Typer 0.17.5+; JWT requires joserfc 1.5+. Install the combination you need:

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
- `testing` — `pytest` for the packaged adapter contract suite.

## Configuration source

`FastAuthOptions` is a plain Pydantic model. fastauth never reads environment
variables directly; your application reads configuration from its own source
and passes values into `FastAuthOptions`.

For example, build config from values your application already owns:

```python
from pydantic import SecretStr
from pymongo import AsyncMongoClient

from fastauth import FastAuth, FastAuthOptions
from fastauth.database import mongo
from fastauth import email_password

mongo_client = AsyncMongoClient("mongodb://localhost:27017", uuidRepresentation="standard")
mongo_database = mongo_client["myapp"]

options = FastAuthOptions(
    secret_key=SecretStr("replace-me-with-your-application-secret"),
    database=mongo(
        database=mongo_database,
        collection_prefix="tenant_",
        collection_suffix="_auth",
    ),
)
auth = FastAuth(options, plugins=[email_password()])
```

## Toolchain commands

Local development uses [uv](https://docs.astral.sh/uv/):

```bash
uv sync --all-extras            # install runtime + dev + docs dependencies
uv run ruff format --check src tests examples docs
uv run ruff check               # lint
uv run pyright                  # type-check (strict)
uv run pytest                   # run the test suite
uv run pytest -m "unit and not docker"
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
