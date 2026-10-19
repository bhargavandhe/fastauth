# Executable deployment recipes

The [copyable example package](https://github.com/bhargavandhe/fastauth/tree/main/examples/deployment)
contains typed FastAPI factories for each backend. Copy `examples/deployment/`
into your application, including its `__init__.py`, `common.py`, and
`email_sender.py`; the wheel intentionally contains the library, not an example
application. The module paths below assume you retain that package layout.

These recipes use database sessions and the email/password plugin. They mount
`/auth`, install the middleware and exception handlers, and expose a typed `/me`
route. The application supplies configuration; neither these examples nor FastAuth
read process environment variables. Shutdown closes application-owned HTTP/Mongo
clients and the FastAuth-managed Postgres engine, including when startup fails.

## Memory: single-process development

```bash
pip install 'fastauth-py==0.15.0' 'uvicorn>=0.30' 'httpx>=0.27'
uvicorn examples.deployment.memory:create_app --factory --host 127.0.0.1 --port 8000
```

Use `http://localhost:8000` in the browser. The recipe explicitly trusts that
origin and uses non-secure development cookies. It uses a clearly marked sample
secret and `ConsoleEmailSender`, which stores messages in an in-memory outbox;
it does not send real mail. Restarting loses users, sessions, and messages.
Do not use multiple workers or deploy this configuration to production.

## Production settings and email

Pass a `MongoSettings` or `PostgresSettings` model explicitly to `create_app`,
or let the no-argument uvicorn factory load an application-owned `deployment.json`
in its working directory. Provision that file through your deployment's secret
manager and mount it read-only with access limited to the application user.
Never commit the real file. This file is an example application convention, not
a FastAuth configuration-discovery mechanism.

The JSON fields are:

| Field | Meaning |
| --- | --- |
| `secret_key` | High-entropy application secret, at least 32 bytes |
| `base_url` | Public HTTPS URL, for example `https://app.example.com` |
| `email_api_key` | Provider API key with email-sending permission |
| `email_from` | Sender on your verified domain, e.g. `Auth <auth@example.com>` |
| `mongo_url`, `mongo_database` | Required only by the Mongo factory |
| `postgres_url` | Required only by the Postgres factory; `postgresql+asyncpg://` |

Alternatively, your application can construct the typed model from its existing
settings/vault source and call the factory. Secret values use `SecretStr`.
Never print full configuration or commit real credentials. The public URL's
origin is explicitly trusted for CSRF. Add any separate browser origins
deliberately. Secure cookies, persistent storage, checked migrations, and
database-backed rate limiting remain enabled. Configure trusted proxy addresses
separately; do not trust arbitrary forwarded IPs.

### Tested async sender

[`email_sender.py`](https://github.com/bhargavandhe/fastauth/blob/main/examples/deployment/email_sender.py)
implements `EmailSender` with HTTPX's async client and the
[Resend send-email API](https://resend.com/docs/api-reference/emails/send-email).
It serializes a typed payload, applies a ten-second per-attempt timeout, and
uses one provider idempotency key for all retries in a send call. It retries
transport errors, HTTP 429, and HTTP 5xx up to three total attempts with bounded
exponential delays. Other HTTP failures propagate immediately; cancellation is
not swallowed. Clients have a connection limit and are closed with the app.

Provider acceptance is not proof of delivery. The recipe has no durable queue:
if all attempts fail, the caller sees an exception, and a process crash loses
in-flight retries. Earlier auth/storage changes are not transactionally rolled
back because mail failed. A later independent call gets a new idempotency key.
For restart-safe delivery, implement an application outbox/queue with persisted
message IDs, bounded retry/backoff, dead-letter monitoring, and an idempotency
key reused by the worker. Respect the provider's retention window (Resend keys
expire after 24 hours), and avoid retrying stale verification/reset links.
Protect queued message bodies as secrets: they contain authentication links.

The sender contract tests use an HTTPX mock transport; CI sends no real email.
Verify your domain/provider account and test delivery in your own staging system.

## MongoDB

```bash
pip install 'fastauth-py[beanie,cli]==0.15.0' 'httpx>=0.27' 'uvicorn>=0.30'
# Existing 0.14 DBs: run the offline Python storage migration linked below first.
# Use the same database connection and collection names.
fastauth migrate --mongo-url "mongodb://db.example.com:27017" --database "myapp"
uvicorn examples.deployment.mongo:create_app --factory --host 0.0.0.0 --port 8000 --workers 4
```

For an existing 0.14 database, run `migrate_mongo_storage_v015` offline before
the normal migration command; the latter deliberately fails on incompatible
legacy indexes. Run these as controlled deployment steps. Read the
[0.15 storage preflight](../migrating/0.15-storage.md) before upgrading an existing
database, particularly the username index. Mongo standalone is supported; the
refresh implementation uses durable per-family coordination rather than assuming
multi-document transactions. Review [family-state retention](../migrating/0.15-sessions.md)
before choosing cleanup policies. The factory sets `plugin_migration_mode="check"`.

## Postgres

```bash
pip install 'fastauth-py[postgres,cli]==0.15.0' 'httpx>=0.27' 'uvicorn>=0.30'
# Substitute your deployment connection; avoid putting credentials in shell history.
fastauth migrate --postgres-url "postgresql+asyncpg://user:pass@db.example.com/myapp"
uvicorn examples.deployment.postgres:create_app --factory --host 0.0.0.0 --port 8000 --workers 4
```

The factory sets both `migration_mode="check"` and
`plugin_migration_mode="check"`; stale schema fails startup. Run migrations before
starting the new workers. Review the [0.15 migration sequence](../migrating/0.15.md)
and plan the refresh-token sign-in requirement before upgrading existing data.

For both persistent backends, terminate TLS at the configured trusted proxy and
route to the app. Readiness (`GET /auth/health/ready`) must pass before routing
traffic; liveness (`GET /auth/health/live`) only checks the process/router. Supply
secrets through your deployment's normal mechanism rather than shell history.

## Verification and browser flow

From a same-origin browser, signup/sign-in set a signed HttpOnly session cookie.
Use these existing routes:

1. `POST /auth/sign-up/email` with email/password
2. `POST /auth/send-verification-email`, then submit the emailed token and email
   to `POST /auth/verify-email`
3. `POST /auth/sign-in/email`, then `GET /me`
4. For explicit bearer delivery, pass `delivery: {"kind": "bearer"}`; securely
   retain the returned refresh credential and pass it to `POST /auth/refresh`
5. `POST /auth/sign-out`; password recovery uses `POST /auth/forgot-password`
   followed by `POST /auth/reset-password` with email, token, and `newPassword`

The [executable recipe tests](https://github.com/bhargavandhe/fastauth/blob/main/tests/docs/test_deployment_apps.py)
exercise this lifecycle with the development outbox. Production email delivery
and your reverse proxy still need staging validation. The recipe's `/me` route
uses the default account policy; see [verification and freshness policy](../migrating/0.15.md#account-status-verification-and-authentication-age)
when an application must restrict access before email verification.

CI type-checks these recipes, executes their tests, and builds the docs strictly.
Separate mandatory database jobs cover persistent-backend contracts. Importing
an app factory alone is not evidence of a successful live database deployment.
