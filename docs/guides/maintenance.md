# Maintenance and retention

Run bounded cleanup from cron, a worker, or a deployment job:

```python
result = await auth.maintenance.run()
if not result.ok:
    raise RuntimeError(result.failures)
```

The run removes expired sessions, refresh tokens, verifications, and API keys,
plus audit logs older than the configured retention period. Every operation is
bounded by `batch_size` and `max_batches` and is safe to retry.

```python
from datetime import timedelta
from fastauth import FastAuthOptions, MaintenanceOptions

options = FastAuthOptions(
    # ...
    maintenance=MaintenanceOptions(
        batch_size=500,
        max_batches=20,
        audit_log_retention=timedelta(days=90),
        continue_on_error=False,
    ),
)
```

The CLI exposes the same operation for memory, MongoDB, and Postgres:

```bash
fastauth maintenance \
  --backend postgres \
  --postgres-url postgresql+asyncpg://... \
  --batch-size 500 \
  --max-batches 20 \
  --audit-log-retention-days 90
```
