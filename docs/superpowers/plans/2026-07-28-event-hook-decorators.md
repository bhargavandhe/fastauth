# Event and Hook Decorators Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add typed `auth.on()` and `auth.hook()` registration decorators and remove `auth.on_event()`.

**Architecture:** `FastAuth` exposes thin identity-preserving decorator factories that delegate immediately to the existing `EventBus` and `DatabaseHooks` registries. Dispatch order, subclass matching, hook payload chaining, and exception behavior remain owned by those existing runtime components.

**Tech Stack:** Python 3.11+, FastAPI 0.115+, Pydantic 2.8+, pytest/pytest-asyncio, Ruff, Pyright.

## Global Constraints

- Remove `FastAuth.on_event()` without a compatibility alias.
- Decorators return the exact handler object they register.
- `auth.on(EventType)(handler)` and `auth.hook(phase, target="user")(handler)` remain valid imperative forms.
- Event dispatch and hook execution semantics must not change.
- Preserve unrelated changes in `skills-lock.json` and the untracked `better-auth/` directory.

---

### Task 1: Typed Registration Decorators

**Files:**
- Create: `tests/unit/runtime/test_registration_decorators.py`
- Modify: `src/fastauth/runtime/auth.py`
- Modify: `tests/unit/api/test_server_create_user.py`
- Modify: `tests/unit/domain/test_events.py`

**Interfaces:**
- Consumes: `EventBus.subscribe()`, `DatabaseHooks.register()`, `AuthEvent`,
  `HookPhase`, and `HookHandler`.
- Produces:

```python
def on(
    self,
    event_type: type[EventT],
) -> Callable[
    [Callable[[EventT], Awaitable[None]]],
    Callable[[EventT], Awaitable[None]],
]: ...


def hook(
    self,
    phase: HookPhase,
    *,
    target: str,
) -> Callable[[HookHandlerT], HookHandlerT]: ...
```

- [ ] **Step 1: Write failing decorator tests**

Create `tests/unit/runtime/test_registration_decorators.py` with a memory-backed
`FastAuth`. Add tests proving the decorators return the original function and
deliver real events/hooks:

```python
async def test_on_registers_handler_and_preserves_identity(auth: FastAuth) -> None:
    received: list[str] = []

    async def handler(event: UserCreated) -> None:
        received.append(event.user_id)

    decorated = auth.on(UserCreated)(handler)
    await auth.events.publish(UserCreated(user_id="user-1", identifier="a@app.com"))

    assert decorated is handler
    assert received == ["user-1"]


async def test_hook_registers_handler_and_preserves_identity(auth: FastAuth) -> None:
    async def add_name(context: HookContext) -> User:
        user = cast(User, context.payload)
        return user.model_copy(update={"name": "Decorated"})

    decorated = auth.hook(HookPhase.BEFORE_CREATE, target="user")(add_name)
    result = await auth.context.hooks.run(
        HookPhase.BEFORE_CREATE,
        "user",
        User(email="a@app.com"),
        actor_user_id=None,
    )

    assert decorated is add_name
    assert result.name == "Decorated"
```

Add a decorated event test with one raising handler followed by a successful
handler, and two decorated before hooks whose returned payloads chain in
registration order.

- [ ] **Step 2: Verify the tests fail**

Run:

```bash
uv run pytest tests/unit/runtime/test_registration_decorators.py -q
```

Expected: FAIL because `FastAuth` has no `on` or `hook` method.

- [ ] **Step 3: Implement the minimal decorator factories**

In `runtime/auth.py`, import `HookPhase` and `HookHandler`, define:

```python
HookHandlerT = TypeVar("HookHandlerT", bound=HookHandler)
```

Replace `on_event()` with:

```python
def on(
    self,
    event_type: type[EventT],
) -> Callable[
    [Callable[[EventT], Awaitable[None]]],
    Callable[[EventT], Awaitable[None]],
]:
    def decorator(
        handler: Callable[[EventT], Awaitable[None]],
    ) -> Callable[[EventT], Awaitable[None]]:
        self.events.subscribe(event_type, handler)
        return handler

    return decorator


def hook(
    self,
    phase: HookPhase,
    *,
    target: str,
) -> Callable[[HookHandlerT], HookHandlerT]:
    def decorator(handler: HookHandlerT) -> HookHandlerT:
        self.context.hooks.register(phase, target, handler)
        return handler

    return decorator
```

- [ ] **Step 4: Verify the decorators and runtime regressions**

Run:

```bash
uv run pytest tests/unit/runtime/test_registration_decorators.py tests/unit/domain/test_events.py tests/unit/domain/test_hooks.py -q
uv run ruff check src/fastauth/runtime/auth.py tests/unit/runtime/test_registration_decorators.py
uv run pyright src/fastauth/runtime/auth.py tests/unit/runtime/test_registration_decorators.py
```

Expected: all commands pass.

- [ ] **Step 5: Migrate server-user tests to the public decorators**

Use decorator syntax in `test_create_user_runs_before_and_after_user_hooks()` and
`test_create_user_publishes_user_created_event()`. Replace the old
`auth.on_event()` test in `test_events.py` with `@auth.on(UserSignedIn)`.

- [ ] **Step 6: Run the real-flow tests and commit**

Run:

```bash
uv run pytest tests/unit/api/test_server_create_user.py tests/unit/domain/test_events.py tests/unit/domain/test_hooks.py tests/unit/runtime/test_registration_decorators.py -q
```

Then commit:

```bash
git add src/fastauth/runtime/auth.py tests/unit/api/test_server_create_user.py tests/unit/domain/test_events.py tests/unit/runtime/test_registration_decorators.py
git commit -m "feat: add event and hook decorators"
```

---

### Task 2: Consumer Documentation and Migration

**Files:**
- Modify: `docs/concepts/events.md`
- Modify: `docs/concepts/hooks.md`
- Modify: `docs/reference/index.md`
- Modify: `docs/migrating/0.12.md`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: `auth.on(EventType)` and
  `auth.hook(HookPhase, target="user")`.
- Produces decorator-first consumer guidance with no recommendation to call
  `auth.on_event()` or `auth.context.hooks.register()` directly.

- [ ] **Step 1: Update the event and hook guides**

Use:

```python
@auth.on(UserSignedUp)
async def welcome(event: UserSignedUp) -> None:
    print(f"new user {event.user_id} ({event.identifier})")
```

and:

```python
@auth.hook(HookPhase.BEFORE_CREATE, target="user")
async def stamp_signup_metadata(context: HookContext) -> User:
    user = cast(User, context.payload)
    return user.model_copy(
        update={"metadata": {**user.metadata, "source": "marketing-landing"}},
    )
```

Document event exception isolation, before-hook payload replacement, after-hook
side effects, registration order, and the imperative decorator-factory form.

- [ ] **Step 2: Update reference and migration material**

Add `auth.on()` and `auth.hook()` entries to `docs/reference/index.md`. Update
the 0.12 guide with before/after registration examples. Add both decorators
under `[Unreleased]` and list `auth.on_event()` as removed.

- [ ] **Step 3: Verify documentation**

Run:

```bash
rg -n "auth\.on_event\(|auth\.context\.hooks\.register" README.md docs --glob '!docs/superpowers/**' --glob '!docs/migrating/0.12.md'
uv run --extra docs mkdocs build --strict --site-dir /tmp/authkit-docs-site
```

Expected: the search has no matches and MkDocs exits zero.

- [ ] **Step 4: Commit**

```bash
git add CHANGELOG.md docs/concepts/events.md docs/concepts/hooks.md docs/reference/index.md docs/migrating/0.12.md
git commit -m "docs: document event and hook decorators"
```

---

### Task 3: Full Verification

**Files:**
- Verify all files changed by Tasks 1-2.

- [ ] **Step 1: Run static gates**

Run:

```bash
uv run ruff format --check src tests
uv run ruff check src tests
uv run pyright
```

Expected: zero formatting changes, lint errors, or type errors.

- [ ] **Step 2: Run the complete non-Docker suite**

Run:

```bash
uv run pytest -m "not docker" -q
```

Expected: all selected tests pass.

- [ ] **Step 3: Inspect branch state**

Run:

```bash
git diff --check
git status --short
git diff --stat origin/main...HEAD
```

Confirm `skills-lock.json` and `better-auth/` remain outside feature commits.
