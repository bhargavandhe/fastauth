# Events

`EventBus` is the public structured security-event surface for `AuthEvent`
subclasses. Plugins and application code subscribe by concrete event type
(`UserSignedUp`, `SessionCreated`, …) or by the `AuthEvent` base class to
listen to everything.

```python
from fastauth.domain.events import UserSignedUp

async def welcome(event: UserSignedUp) -> None:
    print(f"new user {event.user_id} ({event.identifier})")

auth.on_event(UserSignedUp, welcome)
```

For advanced use, `auth.events` exposes the underlying `EventBus`.

Every domain event carries `event_id`, `occurred_at`, `audit_event_type`, and
optional `ip_address` / `user_agent` fields. Handlers never raise — the bus
swallows and logs handler errors so a misbehaving subscriber cannot break
sign-in. The `AuditLogsPlugin` ships a catch-all subscriber that turns every
event into a row in the `audit_logs` collection.

Core account-management flows publish typed events for profile updates and
deletion as well: `UserUpdated`, `UserDeleteRequested`, and `UserDeleted`.

Events are observational side effects. They should be used for audit logs,
notifications, metrics, and abuse detection, not as the only authority for
mutating auth state. AuthKit flows update storage first, then publish events
for consumers that need to react.
