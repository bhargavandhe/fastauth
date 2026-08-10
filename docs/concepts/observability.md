# Observability

Fastauth emits dependency-free, privacy-bounded operational events without
configuring global logging. The default sink writes JSON through the standard
`fastauth.observability` logger. Supply an async sink to bridge events into your
own metrics or tracing system.

```python
from fastauth import FastAuth, OperationalEvent

class MetricsSink:
    async def emit(self, event: OperationalEvent) -> None:
        metrics.increment(
            event.name,
            tags={
                "outcome": event.outcome or "none",
                "component": event.component or "none",
                "route": event.route or "none",
            },
        )

auth = FastAuth(options, observability_sink=MetricsSink())
```

`OperationalEvent` has explicit bounded fields for outcome, duration, HTTP
status, component, route template, and request id. Attributes are scalar-only.
Tokens, passwords, email addresses, user ids, raw IP addresses, raw paths, and
exception messages are rejected as attribute keys.

Subscribe imperatively or with a decorator:

```python
auth.observability.subscribe("readiness.checked", record_readiness)

@auth.observability.on("maintenance.completed")
async def record_maintenance(event: OperationalEvent) -> None:
    ...
```

For an OpenTelemetry bridge, start or annotate a span inside a sink and copy
only the explicit bounded fields. For Prometheus, use `name`, `outcome`,
`component`, and `route` as labels; observe `duration_ms` as a histogram value.
Do not turn request ids into metric labels because they are intentionally
high-cardinality correlation values.
