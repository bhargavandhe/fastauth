# Integration Ergonomics for 0.13 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement all seven approved integration-ergonomics improvements for FastAuth 0.13.

**Architecture:** Each feedback item lands as an independently tested vertical slice using existing option models, flows, storage abstractions, and safe response DTOs. Shared behavior remains centralized: duration parsing uses `parse_duration`, username mutation uses the existing user-update flow, trusted reads live beside trusted creation, and lockout migration uses the existing rate-limit record model.

**Tech Stack:** Python 3.11+, Pydantic v2, FastAPI, Jinja2, pytest/pytest-asyncio, Ruff, Pyright, MkDocs.

## Global Constraints

- Backward compatibility is not required for 0.13.
- Do not add deprecation aliases or compatibility shims.
- Do not add a database schema migration.
- Per-message email variables override configured template globals.
- Production defaults remain strict; each production safety check is independently configurable.
- `auth.api.get_user` is server-side only and returns `UserView | None`.
- Preserve unrelated changes in `skills-lock.json` and the untracked `better-auth/` directory.

---

### Task 1: Uniform First-Party Plugin Durations

**Files:**
- Modify: `src/fastauth/plugins/email_otp_options.py`
- Modify: `src/fastauth/plugins/jwt.py`
- Modify: `src/fastauth/plugins/api_key.py`
- Modify: `tests/unit/options/test_plugin_options.py`
- Modify: `docs/plugins/email-otp.md`
- Modify: `docs/plugins/jwt.md`
- Modify: `docs/plugins/api-key.md`

**Interfaces:**
- Consumes: `fastauth.options.parse_duration(value: object) -> object`
- Produces: duration validators on `EmailOtpOptions`, `JwtOptions`, and `ApiKeyOptions`

- [ ] **Step 1: Write failing duration-coercion tests**

Add parameterized tests that construct each plugin option model with compact
strings and numeric seconds:

```python
@pytest.mark.parametrize(
    ("factory", "field", "value", "expected"),
    [
        (EmailOtpOptions, "expires_in", "10m", timedelta(minutes=10)),
        (JwtOptions, "expires_in", 900, timedelta(minutes=15)),
        (JwtOptions, "rotation_interval", "7d", timedelta(days=7)),
        (JwtOptions, "grace_period", "1h", timedelta(hours=1)),
        (ApiKeyOptions, "default_rate_limit_window", "30s", timedelta(seconds=30)),
        (ApiKeyOptions, "default_expires_in", 3600, timedelta(hours=1)),
    ],
)
def test_first_party_plugin_options_coerce_duration_inputs(
    factory: type[BaseModel],
    field: str,
    value: object,
    expected: timedelta,
) -> None:
    options = factory.model_validate({field: value})
    assert getattr(options, field) == expected
```

Also assert that `True` and `"soon"` remain invalid.

- [ ] **Step 2: Run the focused test and confirm RED**

Run:

```bash
uv run pytest tests/unit/options/test_plugin_options.py -q
```

Expected: the new cases fail because strict plugin models do not coerce strings
or numbers.

- [ ] **Step 3: Add minimal before validators**

Import `field_validator` and `parse_duration`, then add:

```python
@field_validator("expires_in", mode="before")
@classmethod
def normalize_duration_input(cls, value: object) -> object:
    return parse_duration(value)
```

Use one validator for all three JWT duration fields and one for both API-key
option duration fields. Optional `None` values pass through `parse_duration`.

- [ ] **Step 4: Run tests and document accepted forms**

Run the focused test again and update the three plugin docs to state that
durations accept `timedelta`, numeric seconds, and strings such as `"10m"`.

- [ ] **Step 5: Commit the slice**

```bash
git add src/fastauth/plugins/email_otp_options.py src/fastauth/plugins/jwt.py src/fastauth/plugins/api_key.py tests/unit/options/test_plugin_options.py docs/plugins/email-otp.md docs/plugins/jwt.md docs/plugins/api-key.md
git commit -m "fix: normalize first-party plugin durations"
```

### Task 2: Configured Email OTP Subjects

**Files:**
- Modify: `src/fastauth/flows/email_otp.py`
- Modify: `tests/integration/plugins/test_email_otp_plugin.py`
- Modify: `docs/plugins/email-otp.md`

**Interfaces:**
- Consumes: `FastAuthOptions.email`, `FastAuthOptions.email_change`
- Produces: `subject_for_purpose(config: FastAuthOptions, purpose: VerificationPurpose) -> str`

- [ ] **Step 1: Write failing integration tests**

Configure unique subjects and exercise verification, password-reset, and
email-change OTP requests. Assert:

```python
assert sender.outbox[-1].subject == "Brand verify"
assert sender.outbox[-1].subject == "Brand reset"
assert sender.outbox[-1].subject == "Brand email change"
```

Retain a sign-in assertion for `"Your sign-in code"`.

- [ ] **Step 2: Run the focused tests and confirm RED**

```bash
uv run pytest tests/integration/plugins/test_email_otp_plugin.py -q
```

Expected: configured subject assertions fail against `SUBJECTS_BY_PURPOSE`.

- [ ] **Step 3: Add the subject resolver**

Implement:

```python
def subject_for_purpose(
    config: FastAuthOptions,
    purpose: VerificationPurpose,
) -> str:
    configured = {
        VerificationPurpose.EMAIL_OTP_VERIFICATION: config.email.verification_subject,
        VerificationPurpose.EMAIL_OTP_PASSWORD_RESET: config.email.password_reset_subject,
        VerificationPurpose.EMAIL_OTP_EMAIL_CHANGE: config.email_change.subject,
    }
    return configured.get(purpose, SUBJECTS_BY_PURPOSE[purpose])
```

Use it when constructing `EmailMessage`.

- [ ] **Step 4: Verify and document**

Run the plugin integration test and document that core configured subjects also
apply to OTP delivery.

- [ ] **Step 5: Commit the slice**

```bash
git add src/fastauth/flows/email_otp.py tests/integration/plugins/test_email_otp_plugin.py docs/plugins/email-otp.md
git commit -m "fix: honor configured email otp subjects"
```

### Task 3: Declared Email Template Globals

**Files:**
- Modify: `src/fastauth/options.py`
- Modify: `src/fastauth/messaging/email.py`
- Modify: `src/fastauth/runtime/auth.py`
- Modify: `tests/unit/messaging/test_email.py`
- Modify: `tests/unit/options/test_options.py`
- Modify: `docs/concepts/config.md`
- Modify: `README.md`

**Interfaces:**
- Produces: `EmailOptions.template_globals: dict[str, Any]`
- Produces: `TemplateRenderer(template_directory: str | None, template_globals: Mapping[str, Any] | None = None)`

- [ ] **Step 1: Write failing renderer tests**

Create temporary HTML/text templates using `{{ brand }}` and `{{ otp }}`.
Construct:

```python
configured = {"brand": "Acme", "otp": "global-value"}
renderer = TemplateRenderer(str(tmp_path), configured)
configured["brand"] = "Mutated"
html, text = renderer.render("custom", {"otp": "message-value"})
assert "Acme" in html and "Acme" in text
assert "message-value" in html and "message-value" in text
assert "Mutated" not in html
```

Add an options test that accepts a `template_globals` dictionary.

- [ ] **Step 2: Run focused tests and confirm RED**

```bash
uv run pytest tests/unit/messaging/test_email.py tests/unit/options/test_options.py -q
```

Expected: `EmailOptions` rejects the unknown field and `TemplateRenderer`
rejects the second constructor argument.

- [ ] **Step 3: Implement configuration and merge precedence**

Store `dict(template_globals or {})` on the renderer and render with:

```python
render_context = {**self.template_globals, **variables}
```

Pass `config.email.template_globals` from `FastAuth`.

- [ ] **Step 4: Verify and document**

Run the focused tests and add a branded-template configuration example.

- [ ] **Step 5: Commit the slice**

```bash
git add src/fastauth/options.py src/fastauth/messaging/email.py src/fastauth/runtime/auth.py tests/unit/messaging/test_email.py tests/unit/options/test_options.py docs/concepts/config.md README.md
git commit -m "feat: configure email template globals"
```

### Task 4: Independent Production Safety Policies

**Files:**
- Modify: `src/fastauth/options.py`
- Modify: `src/fastauth/runtime/auth.py`
- Modify: `src/fastauth/__init__.py`
- Modify: `tests/unit/options/test_options.py`
- Modify: `tests/unit/options/test_fastauth_defaults.py`
- Modify: `docs/concepts/config.md`
- Modify: `docs/guides/deploying.md`
- Modify: `README.md`

**Interfaces:**
- Produces: `ProductionSafetyOptions`
- Produces: `FastAuthOptions.production_safety`

- [ ] **Step 1: Write failing policy-isolation tests**

Add tests proving each strict default still rejects its unsafe configuration.
Then add one override test per flag, including:

```python
options = FastAuthOptions(
    secret_key=SecretStr("a" * 64),
    deployment="production",
    production_safety=ProductionSafetyOptions(
        require_https=False,
        require_secure_cookies=False,
    ),
    app=AppOptions(base_url="http://internal:8000"),
    cookie=CookieOptions(secure=False),
    database=custom_production_database,
)
```

Also prove that this override still rejects memory storage, console email,
automatic migrations, weak secrets, and `SameSite=None`.

- [ ] **Step 2: Run focused tests and confirm RED**

```bash
uv run pytest tests/unit/options/test_options.py tests/unit/options/test_fastauth_defaults.py -q
```

Expected: `ProductionSafetyOptions` is missing and existing validators remain
all-or-nothing.

- [ ] **Step 3: Implement the typed policy group**

Add the five boolean fields from the approved design, export the class, attach
it to `FastAuthOptions`, and guard each validation block independently. Guard
the `ConsoleEmailSender` check in `FastAuth.__init__` with
`config.production_safety.forbid_console_email_sender`.

- [ ] **Step 4: Verify and document the TLS-termination case**

Run the focused tests. Update config and deployment docs with an internal HTTP
example that disables only transport checks.

- [ ] **Step 5: Commit the slice**

```bash
git add src/fastauth/options.py src/fastauth/runtime/auth.py src/fastauth/__init__.py tests/unit/options/test_options.py tests/unit/options/test_fastauth_defaults.py docs/concepts/config.md docs/guides/deploying.md README.md
git commit -m "feat: decouple production safety checks"
```

### Task 5: Trusted Server-Side User Reads

**Files:**
- Modify: `src/fastauth/flows/server_users.py`
- Modify: `src/fastauth/runtime/api.py`
- Create: `tests/unit/api/test_server_get_user.py`
- Modify: `docs/concepts/server-api.md`
- Modify: `docs/reference/index.md`

**Interfaces:**
- Produces: `get_user(context: AuthContext, *, by_id: UserId | str | None = None, by_email: EmailStr | str | None = None, by_username: Username | str | None = None) -> UserView | None`
- Produces: matching `AuthApi.get_user(...)`

- [ ] **Step 1: Write failing server API tests**

Create one user and assert all selectors return the same `UserView`; assert a
miss returns `None`; assert zero and multiple selectors raise:

```python
with pytest.raises(
    InvalidRequestError,
    match="get_user requires exactly one selector",
):
    await auth.api.get_user()
```

- [ ] **Step 2: Run the focused test and confirm RED**

```bash
uv run pytest tests/unit/api/test_server_get_user.py -q
```

Expected: `AuthApi` has no `get_user`.

- [ ] **Step 3: Implement selector validation and safe conversion**

Count non-`None` selectors, validate the selected input using `UserId`,
`EmailStr`/`normalize_email`, or `Username`, call the matching adapter method,
and return `user_view(user)` or `None`.

- [ ] **Step 4: Verify and document**

Run the focused test and document all three selectors and the exactly-one rule.

- [ ] **Step 5: Commit the slice**

```bash
git add src/fastauth/flows/server_users.py src/fastauth/runtime/api.py tests/unit/api/test_server_get_user.py docs/concepts/server-api.md docs/reference/index.md
git commit -m "feat: add trusted user read api"
```

### Task 6: Required Usernames at Sign-Up

**Files:**
- Modify: `src/fastauth/plugins/email_password.py`
- Modify: `src/fastauth/flows/credentials.py`
- Modify: `tests/integration/auth/test_signup_signin.py`
- Modify: `tests/unit/api/test_public_api_redesign.py`
- Modify: `docs/concepts/config.md`
- Modify: `README.md`

**Interfaces:**
- Produces: `EmailPasswordOptions.require_username: bool = False`

- [ ] **Step 1: Write failing HTTP and server API tests**

Configure `email_password(EmailPasswordOptions(require_username=True))`.
Assert missing usernames raise `INVALID_REQUEST` through HTTP and
`InvalidRequestError` through `auth.api.sign_up.email`, while a valid username
signs up successfully.

- [ ] **Step 2: Run focused tests and confirm RED**

```bash
uv run pytest tests/integration/auth/test_signup_signin.py tests/unit/api/test_public_api_redesign.py -q
```

Expected: the option is unknown and missing usernames are currently accepted.

- [ ] **Step 3: Enforce the option in the shared flow**

At the start of `sign_up_email`, resolve the installed email/password plugin:

```python
plugin = require_email_password(context)
if plugin.options.require_username and request.username is None:
    raise InvalidRequestError(message="username is required")
```

Use a local import if needed to keep module imports acyclic.

- [ ] **Step 4: Verify and document**

Run focused tests and document that trusted `create_user` remains unaffected.

- [ ] **Step 5: Commit the slice**

```bash
git add src/fastauth/plugins/email_password.py src/fastauth/flows/credentials.py tests/integration/auth/test_signup_signin.py tests/unit/api/test_public_api_redesign.py docs/concepts/config.md README.md
git commit -m "feat: optionally require signup usernames"
```

### Task 7: Lockout-State Rekeying

**Files:**
- Modify: `src/fastauth/security/rate_limit.py`
- Modify: `src/fastauth/security/lockout.py`
- Modify: `tests/unit/security/test_rate_limit.py`
- Modify: `tests/unit/security/test_lockout.py`

**Interfaces:**
- Produces: `RateLimitStorage.upsert(rate_limit: RateLimit) -> RateLimit`
- Produces: `AccountLockoutTracker.rekey(old_identifier: str, new_identifier: str) -> None`

- [ ] **Step 1: Write failing storage and rekey tests**

Cover source-only, destination-only, expired, and conflicting active buckets.
For conflicting buckets, assert the greater count survives and the old key is
deleted:

```python
await tracker.rekey("old-name", "new-name")
assert await storage.get(lockout_key("old-name")) is None
assert (await storage.get(lockout_key("new-name"))).count == stricter_count
```

- [ ] **Step 2: Run focused tests and confirm RED**

```bash
uv run pytest tests/unit/security/test_rate_limit.py tests/unit/security/test_lockout.py -q
```

Expected: storage has no `upsert` and tracker has no `rekey`.

- [ ] **Step 3: Implement storage upsert**

Add `upsert` to the protocol. Memory storage replaces the keyed record under
its lock. Database storage delegates to `adapter.upsert_rate_limit`.

- [ ] **Step 4: Implement deterministic rekeying**

Filter buckets with:

```python
bucket.last_request_ms + self.config.window_seconds * 1000 > now
```

Choose `max(active, key=lambda bucket: (bucket.count, bucket.last_request_ms))`,
copy it with `key=lockout_key(new_identifier)`, upsert it, and delete the old
key. Clear stale destination state when neither bucket is active.

- [ ] **Step 5: Verify and commit**

```bash
uv run pytest tests/unit/security/test_rate_limit.py tests/unit/security/test_lockout.py -q
git add src/fastauth/security/rate_limit.py src/fastauth/security/lockout.py tests/unit/security/test_rate_limit.py tests/unit/security/test_lockout.py
git commit -m "feat: rekey username lockout state"
```

### Task 8: Gated Username Updates

**Files:**
- Modify: `src/fastauth/plugins/email_password.py`
- Modify: `src/fastauth/flows/user_management.py`
- Modify: `src/fastauth/api/commands.py`
- Modify: `src/fastauth/runtime/api.py`
- Modify: `tests/integration/auth/test_user_management.py`
- Modify: `tests/unit/api/test_public_api_redesign.py`
- Modify: `docs/guides/user-management.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: `AccountLockoutTracker.rekey(...)`
- Produces: `EmailPasswordOptions.allow_username_change: bool = False`
- Produces: `UpdateUserRequest.username` and `UpdateUserCommand.username`

- [ ] **Step 1: Write failing update tests**

Cover disabled gating, successful assignment/change, duplicate rejection,
explicit-null rejection, same-value no-op, `UserUpdated.changed_fields`, and
lockout rekeying through both HTTP and `auth.api.user.update`.

- [ ] **Step 2: Run focused tests and confirm RED**

```bash
uv run pytest tests/integration/auth/test_user_management.py tests/unit/api/test_public_api_redesign.py -q
```

Expected: update models reject `username` and the option is missing.

- [ ] **Step 3: Add models and feature gating**

Add the option and `Username | None` fields. Add a request validator that rejects
explicit `None`. Include `username` in `UserApi.update` payload construction
without dropping explicit null before validation.

- [ ] **Step 4: Implement uniqueness, mutation, eventing, and rekey**

Resolve `require_email_password(context)`, enforce
`allow_username_change`, reject a different existing owner with
`DuplicateError`, mutate `user.username`, persist, publish the existing event,
then call `lockout_tracker.rekey(old_username, new_username)` after successful
persistence.

- [ ] **Step 5: Verify and document**

Run the focused tests and document the flag and non-null update contract.

- [ ] **Step 6: Commit the slice**

```bash
git add src/fastauth/plugins/email_password.py src/fastauth/flows/user_management.py src/fastauth/api/commands.py src/fastauth/runtime/api.py tests/integration/auth/test_user_management.py tests/unit/api/test_public_api_redesign.py docs/guides/user-management.md README.md
git commit -m "feat: support gated username changes"
```

### Task 9: Cross-Cutting Documentation and Release Verification

**Files:**
- Modify: `README.md`
- Modify: `docs/concepts/config.md`
- Modify: `docs/concepts/server-api.md`
- Modify: `docs/guides/deploying.md`
- Modify: `docs/guides/user-management.md`
- Modify: `docs/plugins/api-key.md`
- Modify: `docs/plugins/email-otp.md`
- Modify: `docs/plugins/jwt.md`
- Modify: `docs/reference/index.md`

**Interfaces:**
- Consumes: all public APIs produced by Tasks 1-8
- Produces: one consistent documented 0.13 integration surface

- [ ] **Step 1: Audit documentation against the design**

Verify docs include the exact names `ProductionSafetyOptions`,
`production_safety`, `template_globals`, `allow_username_change`,
`require_username`, and `auth.api.get_user`.

- [ ] **Step 2: Run focused and full verification**

```bash
uv run pytest tests/unit/options tests/unit/messaging tests/unit/security tests/unit/api tests/integration/auth tests/integration/plugins/test_email_otp_plugin.py -q
uv run ruff check src tests
uv run pyright
uv run pytest -q
uv run mkdocs build --strict
```

Expected: every command exits zero with no test failures, lint errors,
type-checking errors, or documentation warnings.

- [ ] **Step 3: Check the final diff and scope**

```bash
git diff --check
git status --short
git diff --stat main...HEAD
```

Confirm `skills-lock.json` and `better-auth/` are not staged or committed.

- [ ] **Step 4: Commit final documentation corrections if needed**

```bash
git add README.md docs
git commit -m "docs: document 0.13 integration ergonomics"
```
