# Audit logs

`AuditLogsPlugin` subscribes a catch-all handler to `AuthEvent` so every
domain event is persisted as a row in the `audit_logs` collection. It also
contributes two read-only HTTP endpoints.

## Endpoints

- `GET /auth/audit-logs` — paginated, scoped to the current session's user.
- `GET /auth/audit-logs/all` — paginated, requires the caller's user id to be
  listed in `AuditLogsConfig.admin_user_ids`.

Both endpoints support filtering by `event_type` and `identifier`, and
standard `limit` / `offset` pagination.

## Config

`AuditLogsConfig` exposes `admin_user_ids` — the user ids permitted to call
the `/audit-logs/all` admin endpoint.

## Example

```python
from fastauth.plugins.audit_logs import AuditLogsConfig, AuditLogsPlugin

auth = FastAuth(
    config,
    adapter=adapter,
    plugins=[AuditLogsPlugin(AuditLogsConfig(admin_user_ids=["00000000-...-admin"]))],
)
```

`OtpGenerated` events are explicitly skipped by the recorder so plaintext OTP
values never land in the audit log.
