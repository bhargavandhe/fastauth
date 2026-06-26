# Installation

`authkit` is published as the `authkit-fastapi` distribution with optional
extras. Install the combination you need:

```bash
pip install "authkit-fastapi[beanie,jwt,cli]"
```

The available extras are:

- `beanie` — MongoDB persistence via `beanie` + `motor`.
- `postgres` — Postgres persistence via SQLAlchemy asyncio + `asyncpg`.
- `jwt` — JWT signing, JWKS rotation, and KMS hooks (`joserfc`, `cryptography`).
- `cli` — the `authkit` Typer CLI (`typer`, `rich`).
- `dev` — test runner, type checker, linter, and pre-commit hooks.
- `docs` — `mkdocs-material` and `mkdocstrings[python]`.

## Configuration source

`AuthKitConfig` is a plain Pydantic model. authkit never reads environment
variables directly; your application reads configuration from its own source
and passes values into `AuthKitConfig`.

For example, build config from values your application already owns:

```python
from pydantic import SecretStr

from authkit import AuthKitConfig
from authkit.config import DatabaseConfig, MongoDatabaseConfig

config = AuthKitConfig(
    secret_key=SecretStr("replace-me-with-your-application-secret"),
    database=DatabaseConfig(
        backend="mongo",
        mongo=MongoDatabaseConfig(
            url="mongodb://localhost:27017",
            database_name="myapp",
        ),
    ),
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
uv run authkit init --backend memory    # writes auth.py
uv run authkit init --backend mongo     # writes Mongo scaffold
uv run authkit init --backend postgres  # writes Postgres scaffold
uv run authkit migrate --mongo-url mongodb://localhost:27017 --database myapp
uv run authkit migrate --postgres-url postgresql+asyncpg://user:pass@localhost/myapp
```

The Mongo command initializes Beanie documents and indexes. The Postgres
command applies tracked authkit schema migrations and records the current
schema version in the database.
