# Explicit FastAPI Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove `FastAuth.mount()` and expose `FastAuth.add_middleware(app)` so route inclusion and application-wide HTTP integration are explicit.

**Architecture:** `auth.router` remains prefix-free and is always included by the consumer. `auth.add_middleware(app)` delegates to the existing CSRF and security-header installers and registers the `FastAuthError` handler, but never includes routes. `as_asgi()` composes both operations internally to remain a standalone adapter.

**Tech Stack:** Python 3.11+, FastAPI 0.115+, pytest/pytest-asyncio, httpx, Ruff, Pyright.

## Global Constraints

- Remove `FastAuth.mount()` without a compatibility alias.
- `FastAuth.add_middleware(app)` installs CSRF, security headers, and the `FastAuthError` exception handler.
- `FastAuth.add_middleware(app)` does not include routes or select a prefix.
- `FastAuth.as_asgi()` includes `auth.router` at `options.app.base_path` and installs the same HTTP integration.
- Preserve unrelated changes in `skills-lock.json` and the untracked `better-auth/` directory.

---

### Task 1: Replace Mount with Explicit Middleware Installation

**Files:**
- Modify: `src/fastauth/runtime/auth.py`
- Modify: `tests/integration/web/test_router_inclusion.py`
- Modify: `tests/integration/auth/test_current_user_dependency.py`

**Interfaces:**
- Consumes: `install_csrf(app, context)`, `install_security_headers(app, context)`, `fastauth_error_handler`.
- Produces:

```python
class FastAuth:
    def add_middleware(self, app: FastAPI) -> None: ...
```

- [ ] **Step 1: Write failing integration tests**

Replace the mount-path test with a test that includes `auth.router` at
`"/configured/auth"`, calls `auth.add_middleware(app)`, and proves both that
`"/configured/auth/health"` succeeds and `"/health"` is absent. Add a second
app that calls only `auth.add_middleware(app)` and prove `"/health"` remains
404. Rename the host exception-handler test to exercise
`auth.add_middleware(app)`.

- [ ] **Step 2: Verify the new tests fail**

Run:

```bash
uv run pytest tests/integration/web/test_router_inclusion.py tests/integration/auth/test_current_user_dependency.py -q
```

Expected: FAIL with `AttributeError: 'FastAuth' object has no attribute 'add_middleware'`.

- [ ] **Step 3: Implement the minimal public API**

In `runtime/auth.py`, replace `mount()` with:

```python
def add_middleware(self, app: FastAPI) -> None:
    if FastAuthError not in app.exception_handlers:
        app.add_exception_handler(FastAuthError, fastauth_error_handler)
    install_csrf(app, self.context)
    install_security_headers(app, self.context)
```

Change `as_asgi()` to include `self.router` at
`self.context.config.app.base_path`, then call `self.add_middleware(app)`.

- [ ] **Step 4: Verify the focused tests pass**

Run:

```bash
uv run pytest tests/integration/web/test_router_inclusion.py tests/integration/auth/test_current_user_dependency.py tests/integration/plugins/test_plugin_hook_contract.py -q
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/fastauth/runtime/auth.py tests/integration/web/test_router_inclusion.py tests/integration/auth/test_current_user_dependency.py
git commit -m "feat: expose explicit FastAPI middleware setup"
```

---

### Task 2: Migrate Internal, Test, CLI, and Documentation Consumers

**Files:**
- Modify: `src/fastauth/cli/main.py`
- Modify: `tests/cli/test_cli.py`
- Modify: `tests/integration/conftest.py`
- Modify: `tests/integration/auth/test_bound_dependency_aliases.py`
- Modify: `tests/integration/auth/test_callback_urls.py`
- Modify: `tests/integration/auth/test_email_verification.py`
- Modify: `tests/integration/auth/test_lockout.py`
- Modify: `tests/integration/auth/test_password_reset.py`
- Modify: `tests/integration/auth/test_refresh_tokens.py`
- Modify: `tests/integration/auth/test_signup_signin.py`
- Modify: `tests/integration/auth/test_wire_format.py`
- Modify: `tests/integration/plugins/test_email_otp_plugin.py`
- Modify: `tests/integration/plugins/test_jwt_plugin.py`
- Modify: `tests/integration/plugins/test_jwt_session_strategy.py`
- Modify: `tests/integration/web/test_csrf_origin.py`
- Modify: `tests/integration/web/test_rate_limit_endpoints.py`
- Modify: `tests/integration/web/test_security_headers.py`
- Modify: `tests/unit/api/test_public_api_redesign.py`
- Modify: `tests/unit/api/test_pydantic_native_refactor.py`
- Modify: `README.md`
- Modify: `docs/quickstart.md`
- Modify: `docs/reference/index.md`
- Modify: `docs/concepts/csrf.md`
- Modify: `tests/unit/api/test_docs_contract.py`
- Modify: `docs/superpowers/plans/2026-07-28-server-api-router-dependencies.md`

**Interfaces:**
- Consumes: `auth.router`, `auth.context.config.app.base_path`, `auth.add_middleware(app)`.
- Produces the canonical host setup:

```python
app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
auth.add_middleware(app)
```

- [ ] **Step 1: Update CLI scaffold tests first**

Change the generated-scaffold assertion to require both
`app.include_router(auth.router, prefix="/auth")` and
`auth.add_middleware(app)`. Change the README contract test to require the same
two public calls.

- [ ] **Step 2: Run the tests and verify they fail**

Run:

```bash
uv run pytest tests/cli/test_cli.py::test_init_can_write_postgres_scaffold tests/unit/api/test_docs_contract.py::test_readme_quickstart_uses_explicit_fastapi_integration -q
```

Expected: FAIL because generated and documented setup still uses `mount()`.

- [ ] **Step 3: Migrate every consumer**

For application-facing code and docs, use a literal consumer prefix:

```python
app.include_router(auth.router, prefix="/auth")
auth.add_middleware(app)
```

For tests whose expected paths use configured `app.base_path`, use:

```python
app.include_router(auth.router, prefix=auth.context.config.app.base_path)
auth.add_middleware(app)
```

Tests that intentionally verify route-only inclusion must continue to omit
`add_middleware()`. Remove every executable or documentation reference to
`auth.mount(app)`.

- [ ] **Step 4: Run migration regressions**

Run:

```bash
uv run pytest tests/cli tests/integration tests/unit/api -m "not docker" -q
```

Expected: PASS.

- [ ] **Step 5: Commit**

Stage only the migrated source, tests, documentation, and this plan, then:

```bash
git commit -m "refactor: remove FastAuth mount integration"
```

---

### Task 3: Full Verification

**Files:**
- Verify all files changed by Tasks 1-2.

- [ ] **Step 1: Confirm the removed API has no live references**

Run:

```bash
rg -n "auth\.mount\(|\.mount\(app\)" src tests README.md docs --glob '!docs/superpowers/specs/**'
```

Expected: no matches outside historical design material.

- [ ] **Step 2: Run static checks**

Run:

```bash
uv run ruff format --check src tests
uv run ruff check src tests
uv run pyright
uv run --extra docs mkdocs build --strict --site-dir /tmp/authkit-docs-site
```

Expected: all commands exit zero.

- [ ] **Step 3: Run the complete non-Docker suite**

Run:

```bash
uv run pytest -m "not docker" -q
```

Expected: all selected tests pass.

- [ ] **Step 4: Inspect and commit any verification-only formatting**

Run:

```bash
git diff --check
git status --short
git diff --stat origin/main...HEAD
```

Confirm `skills-lock.json` and `better-auth/` remain outside feature commits.
