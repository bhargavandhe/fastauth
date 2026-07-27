# Server API, Prefix-Free Router, and Dependency Aliases Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add trusted server-side user creation, a prefix-free FastAPI router, and bound `CurrentUser`/`CurrentSession` dependency aliases.

**Architecture:** A dedicated administrative creation flow will reuse FastAuth's domain validation, password policy, storage adapter, database hooks, and event bus without invoking the interactive sign-up flow. The router will own only relative paths; direct consumers select the prefix in `include_router()`, while `mount()` applies `options.app.base_path`. Dependency aliases will wrap the existing bound dependency manager, so there remains one request-authentication implementation.

**Tech Stack:** Python 3.11+, FastAPI 0.115+, Pydantic 2.8+, pytest/pytest-asyncio, httpx, Ruff, Pyright.

## Global Constraints

- `create_user` creates no session, access credential, refresh token, or verification email.
- User database hooks and the event bus must remain active for server-created users.
- `auth.router` must contain relative paths and no embedded prefix.
- Backward compatibility with the router's old embedded-prefix behavior is not required.
- `auth.mount(app)` must continue to install routes, CSRF, and security headers.
- Direct `app.include_router(auth.router, ...)` must not silently install application-wide middleware.
- Do not introduce a storage transaction API as part of this change.
- Preserve unrelated changes in `skills-lock.json` and the untracked `better-auth/` directory.

---

### Task 1: Trusted Server-Side User Creation

**Files:**
- Create: `src/fastauth/flows/server_users.py`
- Create: `tests/unit/api/test_server_create_user.py`
- Modify: `src/fastauth/runtime/api.py`
- Modify: `src/fastauth/domain/enums.py`
- Modify: `src/fastauth/domain/events.py`
- Modify: `docs/concepts/server-api.md`

**Interfaces:**
- Consumes: `AuthContext`, `User`, `Account`, `ProviderId.CREDENTIAL`, `HookPhase`, `UserMetadata`, `Username`, `validate_password_policy()`, and `user_view()`.
- Produces:

```python
async def create_user(
    context: AuthContext,
    *,
    email: EmailStr | str,
    password: SecretStr | str,
    name: str | None = None,
    username: Username | str | None = None,
    metadata: UserMetadata | Mapping[str, JsonValue] | None = None,
) -> UserView: ...

class UserCreated(AuthEvent):
    audit_event_type: AuditEventType = AuditEventType.USER_CREATED
    user_id: str
    identifier: str

class AuthApi:
    async def create_user(
        self,
        *,
        email: EmailStr | str,
        password: SecretStr | str,
        name: str | None = None,
        username: Username | str | None = None,
        metadata: UserMetadata | Mapping[str, JsonValue] | None = None,
    ) -> UserView: ...
```

- [ ] **Step 1: Write failing persistence and side-effect tests**

Create `tests/unit/api/test_server_create_user.py` with a small `FastAuth`
factory using `memory()`, a recording email sender, and the email-password
plugin. Add this first test:

```python
async def test_create_user_persists_hashed_credential_without_interactive_side_effects() -> None:
    sender = RecordingEmailSender()
    auth = make_auth(email_sender=sender)
    adapter = cast(InMemoryAdapter, auth.context.adapter)

    user = await auth.api.create_user(
        email="ADMIN@APP.COM",
        password="correct-horse-battery",
        name="Admin",
        metadata={"role": "admin"},
    )

    stored_user = await adapter.get_user_by_id(user.id.root)
    account = await adapter.get_account_for_user(user.id.root, ProviderId.CREDENTIAL)
    assert stored_user is not None
    assert str(stored_user.email) == "admin@app.com"
    assert stored_user.metadata == {"role": "admin"}
    assert account is not None and account.password is not None
    assert account.password != "correct-horse-battery"
    assert auth.context.password_hasher.verify(
        "correct-horse-battery",
        account.password,
    )
    assert await adapter.list_sessions_for_user(user.id.root) == []
    assert adapter.refresh_tokens == {}
    assert adapter.verifications == {}
    assert sender.messages == []
```

- [ ] **Step 2: Run the test and verify the missing API failure**

Run:

```bash
uv run pytest tests/unit/api/test_server_create_user.py::test_create_user_persists_hashed_credential_without_interactive_side_effects -q
```

Expected: FAIL because `AuthApi` has no `create_user` method.

- [ ] **Step 3: Add the minimal creation flow and API method**

Implement `src/fastauth/flows/server_users.py`:

```python
async def create_user(
    context: AuthContext,
    *,
    email: EmailStr | str,
    password: SecretStr | str,
    name: str | None = None,
    username: Username | str | None = None,
    metadata: UserMetadata | Mapping[str, JsonValue] | None = None,
) -> UserView:
    secret = password if isinstance(password, SecretStr) else SecretStr(password)
    metadata_value = (
        metadata.root if isinstance(metadata, UserMetadata) else dict(metadata or {})
    )
    user = User(
        email=email,
        name=name,
        username=username,
        metadata=metadata_value,
    )
    user = await context.hooks.run(
        HookPhase.BEFORE_CREATE,
        "user",
        user,
        actor_user_id=None,
    )
    user = await context.adapter.create_user(user)
    account = Account(
        user_id=user.id,
        provider_id=ProviderId.CREDENTIAL,
        account_id=user.id,
        password=context.password_hasher.hash(
            validate_password_policy(context, secret),
        ),
    )
    await context.adapter.create_account(account)
    await context.hooks.run(
        HookPhase.AFTER_CREATE,
        "user",
        user,
        actor_user_id=user.id,
    )
    return user_view(user)
```

Delegate `AuthApi.create_user(...)` directly to this flow using the exact public
signature in the Interfaces section.

- [ ] **Step 4: Run the focused test and verify it passes**

Run:

```bash
uv run pytest tests/unit/api/test_server_create_user.py::test_create_user_persists_hashed_credential_without_interactive_side_effects -q
```

Expected: PASS.

- [ ] **Step 5: Write failing hook, event, duplicate, and sign-in compatibility tests**

Add four focused tests:

```python
async def test_create_user_runs_before_and_after_user_hooks() -> None:
    auth = make_auth()
    after_payloads: list[str] = []

    async def add_seed_metadata(hook: HookContext) -> User:
        user = cast(User, hook.payload)
        return user.model_copy(update={"metadata": {"source": "seed"}})

    async def record_created_user(hook: HookContext) -> None:
        after_payloads.append(cast(User, hook.payload).id)

    auth.context.hooks.register(HookPhase.BEFORE_CREATE, "user", add_seed_metadata)
    auth.context.hooks.register(HookPhase.AFTER_CREATE, "user", record_created_user)
    user = await auth.api.create_user(
        email="seed@app.com",
        password="correct-horse-battery",
    )
    assert user.metadata == {"source": "seed"}
    assert after_payloads == [user.id.root]


async def test_create_user_publishes_user_created_event() -> None:
    events: list[UserCreated] = []

    async def record_event(event: UserCreated) -> None:
        events.append(event)

    auth.on_event(UserCreated, record_event)
    user = await auth.api.create_user(
        email="event@app.com",
        password="correct-horse-battery",
    )
    assert [(event.user_id, event.identifier) for event in events] == [
        (user.id.root, "event@app.com")
    ]


async def test_create_user_rejects_duplicate_email_and_username() -> None:
    await auth.api.create_user(
        email="first@app.com",
        username="same-name",
        password="correct-horse-battery",
    )
    with pytest.raises(DuplicateError):
        await auth.api.create_user(
            email="FIRST@app.com",
            password="correct-horse-battery",
        )
    with pytest.raises(DuplicateError):
        await auth.api.create_user(
            email="second@app.com",
            username="same-name",
            password="correct-horse-battery",
        )


async def test_server_created_user_can_sign_in_normally() -> None:
    await auth.api.create_user(
        email="worker@app.com",
        password="correct-horse-battery",
    )
    response = await auth.api.sign_in.email(
        SignInEmailCommand(
            email="worker@app.com",
            password=SecretStr("correct-horse-battery"),
        )
    )
    assert str(response.user.email) == "worker@app.com"
```

- [ ] **Step 6: Run the tests and verify the missing event failure**

Run:

```bash
uv run pytest tests/unit/api/test_server_create_user.py -q
```

Expected: hook, duplicate, and sign-in tests pass; event test FAILS because
`UserCreated` and `AuditEventType.USER_CREATED` do not exist or are not
published.

- [ ] **Step 7: Add and publish the creation event**

Add `USER_CREATED = "user_created"` to `AuditEventType`, export and define
`UserCreated` in `domain/events.py`, and publish it at the end of the server
creation flow:

```python
await context.event_bus.publish(
    UserCreated(
        user_id=user.id,
        identifier=str(user.email),
    )
)
```

- [ ] **Step 8: Run the server API tests and relevant regression tests**

Run:

```bash
uv run pytest tests/unit/api/test_server_create_user.py tests/unit/api/test_public_api_redesign.py tests/unit/api/test_final_pydantic_native_api.py -q
```

Expected: PASS.

- [ ] **Step 9: Document and commit server-side creation**

Update `docs/concepts/server-api.md` with the keyword-call example, trusted-code
boundary, returned `UserView`, and explicit absence of session/email side
effects.

Run:

```bash
uv run ruff check src/fastauth/flows/server_users.py src/fastauth/runtime/api.py src/fastauth/domain/enums.py src/fastauth/domain/events.py tests/unit/api/test_server_create_user.py
uv run pyright src/fastauth/flows/server_users.py src/fastauth/runtime/api.py tests/unit/api/test_server_create_user.py
git add src/fastauth/flows/server_users.py src/fastauth/runtime/api.py src/fastauth/domain/enums.py src/fastauth/domain/events.py tests/unit/api/test_server_create_user.py docs/concepts/server-api.md
git commit -m "feat: add trusted server-side user creation"
```

Expected: lint and type checks pass; commit contains only Task 1 files.

---

### Task 2: Prefix-Free Router and Arbitrary Include Prefixes

**Files:**
- Modify: `src/fastauth/web/fastapi.py`
- Modify: `src/fastauth/runtime/auth.py`
- Modify: `src/fastauth/runtime/routes.py`
- Modify: `src/fastauth/runtime/inspection.py`
- Modify: `src/fastauth/plugins/openapi.py`
- Modify: `tests/unit/api/test_public_api_redesign.py`
- Modify: `tests/integration/plugins/test_openapi_plugin.py`
- Create: `tests/integration/web/test_router_inclusion.py`
- Modify: `docs/quickstart.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: `FastAuth.router`, `FastAuth.mount()`,
  `FastAuthOptions.app.base_path`, `FastAuthRoute`, and FastAPI's
  `request.scope["route"]`.
- Produces:

```python
auth.router.prefix == ""
app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
auth.mount(app)  # includes the same router at options.app.base_path
```

- `RouteRef.path` and `AuthInspection.routes[*].path` become relative FastAuth
  paths such as `/sign-up/email`.

- [ ] **Step 1: Write failing router-prefix tests**

In `tests/integration/web/test_router_inclusion.py`, create tests that exercise
real requests:

```python
async def test_router_can_be_included_at_consumer_selected_prefix(auth: FastAuth) -> None:
    app = FastAPI()
    app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        response = await client.get("/api/auth/health")
    assert response.status_code == 200
    assert auth.router.prefix == ""


async def test_mount_applies_configured_base_path() -> None:
    auth = make_auth(base_path="/configured/auth")
    app = FastAPI()
    auth.mount(app)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        mounted = await client.get("/configured/auth/health")
        unprefixed = await client.get("/health")
    assert mounted.status_code == 200
    assert unprefixed.status_code == 404
```

Update the old assertion in `test_public_api_redesign.py` to
`assert auth.router.prefix == ""`, and update route-constant assertions to
relative paths.

- [ ] **Step 2: Run the tests and verify they fail on the embedded prefix**

Run:

```bash
uv run pytest tests/integration/web/test_router_inclusion.py tests/unit/api/test_public_api_redesign.py -q
```

Expected: FAIL because `auth.router.prefix` is the configured base path and
direct inclusion produces a doubled prefix.

- [ ] **Step 3: Remove the router prefix and move it into `mount()`**

Change `build_router()` to construct:

```python
router = APIRouter(
    tags=["fastauth"],
    route_class=fastauth_route_class(context),
    dependencies=[Depends(rate_limit_dependency(context))],
    default_response_class=JSONResponse,
)
```

Change `FastAuth.mount()` to:

```python
app.include_router(
    self.router,
    prefix=self.context.config.app.base_path,
)
```

Change `AuthRoutes` construction and inspection expectations to expose relative
paths. Remove prefix concatenation from
`AuthInspector.plugin_endpoint_info_by_route()`.

- [ ] **Step 4: Run the focused tests and verify the basic routing behavior**

Run:

```bash
uv run pytest tests/integration/web/test_router_inclusion.py tests/unit/api/test_public_api_redesign.py -q
```

Expected: PASS for prefix and health-route tests. Any path-sensitive plugin or
rate-limit regressions are handled by the next red-green cycle.

- [ ] **Step 5: Write failing path-sensitive integration tests**

Add tests proving:

1. A plugin middleware declared for `/sign-up/email` still runs when the router
   is included at `/api/auth`.
2. Rate-limit storage keys use `/sign-up/email`, not `/api/auth/sign-up/email`
   or a path derived from the unrelated configured base path.
3. `auth.inspect.routes()` returns relative paths and identifies plugin endpoint
   metadata.
4. The OpenAPI reference served under `/api/auth/reference` points to
   `/api/auth/openapi.json`.

The OpenAPI assertion should parse the response HTML:

```python
reference = await client.get("/api/auth/reference")
assert 'data-url="/api/auth/openapi.json"' in reference.text
```

- [ ] **Step 6: Run the path-sensitive tests and verify their expected failures**

Run:

```bash
uv run pytest tests/integration/web/test_router_inclusion.py tests/integration/plugins/test_openapi_plugin.py -q
```

Expected: at least the rate-limit path or OpenAPI reference test FAILS because
those implementations still use `options.app.base_path`.

- [ ] **Step 7: Make path-sensitive behavior use the matched relative route**

Add a helper in `web/fastapi.py`:

```python
def matched_route_path(request: Request) -> str:
    route = request.scope.get("route")
    if isinstance(route, APIRoute):
        return route.path
    return request.url.path
```

Use `route.path` as the relative candidate in plugin matching, and use
`matched_route_path(request)` for the rate-limit key. Do not strip
`options.app.base_path`.

Change `OpenApiPlugin.reference_handler` to accept `request: Request` and derive
the effective include prefix from the request path and matched relative route:

```python
route = request.scope.get("route")
relative_path = route.path if isinstance(route, APIRoute) else self.options.path
prefix = request.url.path.removesuffix(relative_path)
openapi_url = f"{prefix}/openapi.json"
```

Keep the generated link path-only so it works behind the current host and
scheme.

- [ ] **Step 8: Run router, plugin, inspection, and OpenAPI regression tests**

Run:

```bash
uv run pytest tests/integration/web tests/integration/plugins/test_openapi_plugin.py tests/unit/api/test_public_api_redesign.py tests/unit/plugins -q
```

Expected: PASS.

- [ ] **Step 9: Update routing documentation and commit**

Make direct `include_router()` the primary example in `README.md` and
`docs/quickstart.md`. Explain that direct inclusion does not install CSRF or
security-header middleware; show `auth.mount(app)` as the high-level alternative.

Run:

```bash
uv run ruff check src/fastauth/web/fastapi.py src/fastauth/runtime/auth.py src/fastauth/runtime/routes.py src/fastauth/runtime/inspection.py src/fastauth/plugins/openapi.py tests/integration/web/test_router_inclusion.py tests/integration/plugins/test_openapi_plugin.py tests/unit/api/test_public_api_redesign.py
uv run pyright src/fastauth/web/fastapi.py src/fastauth/runtime/auth.py src/fastauth/runtime/routes.py src/fastauth/runtime/inspection.py src/fastauth/plugins/openapi.py
git add src/fastauth/web/fastapi.py src/fastauth/runtime/auth.py src/fastauth/runtime/routes.py src/fastauth/runtime/inspection.py src/fastauth/plugins/openapi.py tests/integration/web/test_router_inclusion.py tests/integration/plugins/test_openapi_plugin.py tests/unit/api/test_public_api_redesign.py docs/quickstart.md README.md
git commit -m "feat: expose a prefix-free FastAPI router"
```

Expected: checks pass; commit contains only Task 2 files.

---

### Task 3: Bound FastAPI Dependency Aliases

**Files:**
- Modify: `src/fastauth/runtime/auth.py`
- Create: `tests/integration/auth/test_bound_dependency_aliases.py`
- Modify: `docs/quickstart.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: `DependsManager.user_dependency`,
  `DependsManager.session_dependency`, `UserView`, and `SessionContext`.
- Produces these runtime attributes on every initialized `FastAuth` instance:

```python
auth.CurrentUser = Annotated[UserView, Depends(auth.depends.user())]
auth.CurrentSession = Annotated[
    SessionContext,
    Depends(auth.depends.session()),
]
```

- [ ] **Step 1: Write failing real-route alias tests**

Create `tests/integration/auth/test_bound_dependency_aliases.py` without
`from __future__ import annotations`, so local test instances are evaluated as
runtime annotation expressions:

```python
async def test_current_user_alias_resolves_authenticated_user(auth: FastAuth) -> None:
    app = FastAPI()
    auth.mount(app)

    @app.get("/me")
    async def me(user: auth.CurrentUser) -> UserView:
        return user

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        sign_up = await client.post(
            "/auth/sign-up/email",
            json={
                "email": "alias@app.com",
                "password": "correct-horse-battery",
            },
        )
        response = await client.get("/me")

    assert response.status_code == 200
    assert response.json()["id"] == sign_up.json()["user"]["id"]
```

Add separate tests for:

- anonymous `CurrentUser` returning the canonical FastAuth 401;
- authenticated `CurrentSession` returning the active session id;
- anonymous `CurrentSession` returning the canonical FastAuth 401.

- [ ] **Step 2: Run the tests and verify the missing-attribute failure**

Run:

```bash
uv run pytest tests/integration/auth/test_bound_dependency_aliases.py -q
```

Expected: FAIL because `FastAuth` has no `CurrentUser` or `CurrentSession`
attribute.

- [ ] **Step 3: Attach aliases after constructing `DependsManager`**

Import `Annotated`, `Depends`, `UserView`, and `SessionContext` in
`runtime/auth.py`. Immediately after `self.depends = DependsManager(self)`, add:

```python
self.CurrentUser = Annotated[
    UserView,
    Depends(self.depends.user()),
]
self.CurrentSession = Annotated[
    SessionContext,
    Depends(self.depends.session()),
]
```

Because these are runtime-created type forms rather than statically declared
class aliases, give the two attributes an explicit `Any`-compatible annotation
that satisfies Pyright without changing the runtime values.

- [ ] **Step 4: Run alias tests and dependency regressions**

Run:

```bash
uv run pytest tests/integration/auth/test_bound_dependency_aliases.py tests/integration/auth/test_current_user_dependency.py -q
```

Expected: PASS.

- [ ] **Step 5: Document scope rules and commit**

Update `README.md` and `docs/quickstart.md` to lead with:

```python
@app.get("/me")
async def me(user: auth.CurrentUser) -> UserView:
    return user
```

Document that `auth` must be module-level when postponed annotations stringify
`auth.CurrentUser`, and retain the explicit
`Depends(auth.depends.user())` alternative for factory/closure-scoped instances.

Run:

```bash
uv run ruff check src/fastauth/runtime/auth.py tests/integration/auth/test_bound_dependency_aliases.py
uv run pyright src/fastauth/runtime/auth.py tests/integration/auth/test_bound_dependency_aliases.py
git add src/fastauth/runtime/auth.py tests/integration/auth/test_bound_dependency_aliases.py README.md docs/quickstart.md
git commit -m "feat: add bound authentication dependency aliases"
```

Expected: checks pass; commit contains only Task 3 files.

---

### Task 4: Full Verification and Release-Facing Documentation

**Files:**
- Modify: `docs/reference/index.md`

**Interfaces:**
- Consumes all public interfaces from Tasks 1-3.
- Produces a fully documented and regression-tested release candidate.

- [ ] **Step 1: Add concise API reference entries**

Document `auth.api.create_user`, `auth.router`, `auth.mount`,
`auth.CurrentUser`, and `auth.CurrentSession` in `docs/reference/index.md`,
including their trust and middleware boundaries.

- [ ] **Step 2: Run formatting and lint checks**

Run:

```bash
uv run ruff format --check src tests
uv run ruff check src tests
```

Expected: PASS with no changes required. If formatting is required, run
`uv run ruff format` only on files changed by this plan, then rerun both checks.

- [ ] **Step 3: Run the strict type checker**

Run:

```bash
uv run pyright
```

Expected: zero errors.

- [ ] **Step 4: Run the complete non-Docker test suite**

Run:

```bash
uv run pytest -m "not docker" -q
```

Expected: all selected tests pass with no unexpected warnings or coverage
regressions.

- [ ] **Step 5: Inspect the final diff and commit verification documentation**

Run:

```bash
git diff --check
git status --short
git diff --stat HEAD~3
git diff HEAD~3 -- src tests docs README.md
git add docs/reference/index.md
git commit -m "docs: document auth integration surfaces"
```

Confirm that `skills-lock.json` and `better-auth/` remain unmodified and
untracked by these commits. Expected: final documentation commit succeeds and
the implementation diff contains only planned files.
