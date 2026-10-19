# Audit logs

`AuditLogsPlugin` subscribes a catch-all handler to `AuthEvent` to attempt
best-effort persistence of eligible domain events in `audit_logs`. Handlers are
awaited sequentially; storage failures are logged and isolated from the auth
operation. There is no durable outbox, automatic retry, or exactly-once guarantee.
Slow audit storage can add latency, and a successful auth response does not prove
that an audit row was committed. For compliance-grade completeness, design a
transactional application-owned delivery path and monitor it. The plugin also
contributes two read-only HTTP endpoints.

## Endpoints

- `GET /auth/audit-logs` — paginated, scoped to the current session's user.
- `GET /auth/audit-logs/all` — paginated, requires the caller's user id to be
  listed in `AuditLogsOptions.admin_user_ids`.

Both endpoints support filtering by `event_type` and `identifier`, and
standard `limit` / `offset` pagination.

## Config

`AuditLogsOptions` exposes `admin_user_ids` — the user ids permitted to call
the `/audit-logs/all` admin endpoint.

## Example

```python
from pydantic import SecretStr

from fastauth import FastAuth, FastAuthOptions
from fastauth.database import memory
from fastauth.plugins.audit_logs import AuditLogsOptions
from fastauth import audit_logs, email_password

auth = FastAuth(
    FastAuthOptions(
        secret_key=SecretStr("replace-me-with-your-application-secret"),
        database=memory(),
    ),
    plugins=[
        email_password(),
        audit_logs(AuditLogsOptions(admin_user_ids=["00000000-...-admin"])),
    ],
)
```

`OtpGenerated` events are explicitly skipped by the recorder so plaintext OTP
values never land in the audit log.
