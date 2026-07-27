# Event and Hook Decorators

## Goal

Expose decorator-first event subscription and database-hook registration on an
initialized `FastAuth` instance:

```python
@auth.on(UserCreated)
async def send_welcome_email(event: UserCreated) -> None:
    await email_client.send(event.user_id, "Welcome!")


@auth.hook(HookPhase.BEFORE_CREATE, target="user")
async def add_seed_metadata(context: HookContext) -> User:
    user = cast(User, context.payload)
    return user.model_copy(update={"metadata": {"source": "seed"}})
```

The decorators are thin public registration adapters. Existing event dispatch
and hook execution remain the single implementations of runtime behavior.

## Public API

`FastAuth.on()` accepts an `AuthEvent` subclass and returns a decorator for an
async handler of that event:

```python
def on(
    self,
    event_type: type[EventT],
) -> Callable[
    [Callable[[EventT], Awaitable[None]]],
    Callable[[EventT], Awaitable[None]],
]: ...
```

The decorator registers the handler with `self.events.subscribe()` and returns
the exact handler object it received.

`FastAuth.hook()` accepts a `HookPhase` and a keyword-only target name:

```python
HookHandlerT = TypeVar(
    "HookHandlerT",
    bound=Callable[[HookContext], Awaitable[Any | None]],
)


def hook(
    self,
    phase: HookPhase,
    *,
    target: str,
) -> Callable[[HookHandlerT], HookHandlerT]: ...
```

The decorator registers the handler with `self.context.hooks.register()` and
returns the exact handler object. `target` maps directly to the existing hook
registry's `model_name`; no separate normalization or target vocabulary is
introduced.

Decorator factories also support explicit conditional registration:

```python
auth.on(UserCreated)(record_event)
auth.hook(HookPhase.AFTER_CREATE, target="user")(record_hook)
```

`FastAuth.on_event()` is removed without a compatibility alias. The low-level
`EventBus.subscribe()` and `DatabaseHooks.register()` methods remain runtime
primitives but are not the documented application API.

## Runtime Semantics

Event behavior does not change:

- Handlers receive events whose concrete type is the registered type or one of
  its subclasses.
- Handlers run in registration order.
- A handler exception is logged and isolated so later handlers still run.

Hook behavior does not change:

- Handlers are selected by the exact `(HookPhase, target)` pair.
- Before-hook return values replace the current payload and flow into the next
  handler.
- A before hook returning `None` leaves the payload unchanged.
- After-hook return values are ignored.
- Hook exceptions propagate to the mutation flow.

Registration occurs immediately when Python evaluates the decorated function,
matching FastAPI's route-decorator behavior.

## Typing

`auth.on(EventType)` preserves the concrete event type in the decorated
handler's parameter and return type. A handler for `UserCreated` therefore
remains a `Callable[[UserCreated], Awaitable[None]]`.

`auth.hook()` preserves the exact handler callable type with a bound type
variable. Hook handlers continue to accept `HookContext` and may return a
replacement model or `None`. No runtime signature introspection is added;
Pyright and the handler annotations provide developer feedback.

## Errors and Validation

The decorators perform registration only. They do not wrap handlers, catch new
exceptions, or modify existing error behavior. Target strings are matched
exactly as they are today, so `"user"` and `"User"` remain distinct.

Registering the same function twice intentionally produces two invocations,
matching direct `subscribe()` and `register()` behavior.

## Documentation and Migration

Consumer-facing event and hook documentation will use decorators as the
canonical API. The 0.12 migration guide will show:

```python
# Before
auth.on_event(UserCreated, record_event)
auth.context.hooks.register(HookPhase.BEFORE_CREATE, "user", transform)

# After
auth.on(UserCreated)(record_event)
auth.hook(HookPhase.BEFORE_CREATE, target="user")(transform)
```

The changelog will list `auth.on()` and `auth.hook()` as additions and
`auth.on_event()` as removed.

## Testing

Focused tests will prove:

- `auth.on(EventType)` registers a handler and returns the same function.
- Decorated handlers receive published events, including subclass matches.
- Existing event exception isolation remains intact.
- `auth.hook(phase, target=...)` registers a handler and returns the same
  function.
- Before-hook transformations chain in registration order.
- After-hook execution and hook exception propagation remain unchanged.
- Server-side `create_user()` exercises both decorators through real flows.
- Consumer documentation contains decorator examples and no longer recommends
  `auth.on_event()` or direct context-hook registration.

The complete non-Docker test suite, Ruff, Pyright, and strict MkDocs build remain
release gates.
