# Events

`EventBus` is the public structured security-event surface for `AuthEvent`
subclasses. Plugins and application code subscribe by concrete event type
(`UserSignedUp`, `SessionCreated`, …) or by the `AuthEvent` base class to
listen to everything.

```python
from fastauth.domain.events import UserSignedUp


@auth.on(UserSignedUp)
async def welcome(event: UserSignedUp) -> None:
    print(f"new user {event.user_id} ({event.identifier})")
```

The decorator returns the original function. Conditional registration can use
the same decorator factory imperatively:

```python
auth.on(UserSignedUp)(welcome)
```

For advanced infrastructure use, `auth.events` exposes the underlying
`EventBus`.

Every domain event carries `event_id`, `occurred_at`, `audit_event_type`, and
optional `ip_address` / `user_agent` fields. Handler exceptions are logged and
isolated so a misbehaving subscriber cannot break sign-in or prevent later
handlers from running. Handlers are awaited sequentially, grouped by subscribed
event type and in registration order within each group; slow handlers add request
latency. There is no durable queue, retry, replay, or exactly-once delivery
guarantee. A crash or storage failure can leave an event unrecorded. The
`AuditLogsPlugin` ships a catch-all subscriber that attempts to turn eligible events into a row
in the `audit_logs` collection.

Core account-management flows publish typed events for profile updates and
deletion as well: `UserUpdated`, `UserDeleteRequested`, and `UserDeleted`.

Events are observational side effects. They should be used for audit logs,
notifications, metrics, and abuse detection, not as the only authority for
mutating auth state. FastAuth flows update storage first, then publish events
for consumers that need to react.

Operational telemetry is deliberately separate from these domain events. Use
`auth.observability` for request, readiness, maintenance, migration, rate-limit,
and lockout signals; see [Observability](observability.md).
