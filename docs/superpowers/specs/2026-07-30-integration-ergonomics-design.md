# Integration Ergonomics for 0.13

## Goal

Remove the integration friction reported against FastAuth 0.12.1 by making
existing email configuration consistent, accepting uniform duration inputs,
exposing supported user-management and template-customization APIs, and
allowing production safety checks to be configured independently.

This is an in-development project. Backward compatibility is not a requirement
for 0.13; the implementation should prefer a coherent public API and clear
invariants over compatibility shims or preservation of incidental output.

## Scope

The release includes all seven proposal items:

1. Email OTP subjects honor configured email subjects.
2. First-party plugin options accept the common duration input forms.
3. Authenticated users can change their username when enabled.
4. Production safety checks can be relaxed independently.
5. Email templates receive declared application globals.
6. Trusted server code can read users through `auth.api`.
7. Email/password sign-up can require a username.

The work will be implemented and reviewed as independent vertical slices. No
database schema migration is required.

## Email OTP Subjects

OTP message subjects will be selected by a focused resolver in
`fastauth.flows.email_otp`:

- Email verification uses `FastAuthOptions.email.verification_subject`.
- Password reset uses `FastAuthOptions.email.password_reset_subject`.
- Email change uses `FastAuthOptions.email_change.subject`.
- OTP sign-in continues to use the plugin-owned `"Your sign-in code"` subject
  because there is no equivalent core email option.

The hardcoded map remains only for purposes without a configured subject. Since
backward compatibility is not required, the resolver does not inspect
`model_fields_set` or preserve the old email-change wording when the configured
default differs. The configured option is always authoritative.

Focused integration tests will send each OTP purpose through the normal plugin
flow and assert the captured `EmailMessage.subject`.

## Uniform Plugin Duration Inputs

The existing `DurationInput` vocabulary and `parse_duration()` function remain
the single duration-coercion implementation. First-party plugin option models
will add `mode="before"` validators for every duration field:

- `EmailOtpOptions.expires_in`
- `JwtOptions.expires_in`
- `JwtOptions.rotation_interval`
- `JwtOptions.grace_period`
- `ApiKeyOptions.default_rate_limit_window`
- `ApiKeyOptions.default_expires_in`

Request payload durations such as API-key creation expiry are wire data, not
plugin configuration, and are outside this change.

Each field will accept `timedelta`, numeric seconds, or compact strings such as
`"10m"` and `"7d"`. Existing positivity, upper-bound, and optional-value
constraints continue to run after normalization. Invalid strings and booleans
produce the same duration-validation errors as core options.

## Username Requirements and Updates

`EmailPasswordOptions` will gain:

```python
allow_username_change: bool = False
require_username: bool = False
```

`require_username` applies to the shared interactive email sign-up flow, so it
covers both the HTTP endpoint and `auth.api.sign_up.email(...)`. It does not
apply to trusted `auth.api.create_user(...)`, whose provisioning contract keeps
`username` optional.

When `require_username=True`, an omitted username raises
`InvalidRequestError(message="username is required")` before user persistence.
The existing `Username` value object remains the source of format validation.

`UpdateUserRequest` and `UpdateUserCommand` will add
`username: Username | None = None`. Omission means no username change. Explicit
`null` is rejected, so the new capability changes or assigns a username but
does not remove one.

When a username is present in an update:

1. The email/password plugin must be installed.
2. `allow_username_change` must be `True`; otherwise the flow raises
   `FeatureNotEnabledError(feature="username-change")`.
3. The normalized username is compared with the current value. An identical
   value is a no-op for that field.
4. `adapter.get_user_by_username()` checks for an existing owner. A different
   owner raises `DuplicateError(resource="user", field="username")`.
5. The user mutation runs through the existing adapter update and publishes
   `UserUpdated` with `"username"` in `changed_fields`.
6. If the user previously had a username, lockout state is rekeyed from the old
   username to the new username.

The HTTP and server-side update surfaces both delegate to the same flow, so
gating, uniqueness, event, and lockout behavior cannot drift.

## Lockout-State Rekeying

Username lockout counters use rate-limit storage keys. `RateLimitStore` already
supports `upsert_rate_limit`; the higher-level `RateLimitStorage` protocol will
expose the corresponding operation:

```python
async def upsert(self, rate_limit: RateLimit) -> RateLimit: ...
```

`MemoryRateLimitStorage` will replace its in-memory value under its existing
lock. `DatabaseRateLimitStorage` will delegate to
`RateLimitStore.upsert_rate_limit()`. No adapter schema change is necessary.

`AccountLockoutTracker.rekey(old_identifier, new_identifier)` will:

1. Return immediately when lockout is disabled or the identifiers are equal.
2. Read both buckets.
3. Discard buckets whose fixed window has already expired.
4. Select the stricter active state: the bucket with the greater count, using
   the later unlock time as the tie-breaker.
5. Upsert the selected state under the new lockout key.
6. Delete the old key.

If only the destination has active failures, it remains unchanged. If neither
bucket is active, both keys are cleared. This prevents a username change from
evading an active lockout and prevents an attacker-created destination bucket
from being weakened.

Unit tests will cover absent, expired, source-only, destination-only, and
conflicting active buckets against both memory storage and the adapter-backed
storage contract.

## Independent Production Safety Checks

FastAuth will add a distinct options section named `ProductionSafetyOptions`.
The name intentionally avoids confusion with `SecurityHeadersOptions`.

```python
class ProductionSafetyOptions(OptionsSection):
    require_https: bool = True
    require_secure_cookies: bool = True
    forbid_memory_database: bool = True
    forbid_console_email_sender: bool = True
    forbid_automatic_migrations: bool = True
```

`FastAuthOptions.production_safety` will default to this strict configuration.
The checks apply only when `deployment == "production"`. Each flag controls one
independent policy:

- `require_https` validates static and dynamic base URLs, dynamic fallbacks,
  and callback URL overrides.
- `require_secure_cookies` requires `CookieOptions.secure`.
- `forbid_memory_database` rejects adapters declaring the memory backend.
- `forbid_console_email_sender` rejects the default `ConsoleEmailSender` at
  `FastAuth` assembly time.
- `forbid_automatic_migrations` rejects Postgres `migration_mode="apply"`.

Secret keys shorter than 32 bytes and `SameSite=None` with insecure cookies are
general configuration invariants in the current code, not production-only
checks. They remain unconditional and cannot be disabled through
`ProductionSafetyOptions`.

This design permits a TLS-terminating deployment to set:

```python
production_safety=ProductionSafetyOptions(
    require_https=False,
    require_secure_cookies=False,
)
```

while retaining the persistent-database, non-console-sender, migration, and
secret-strength protections.

Validation tests will exercise every flag independently and prove that disabling
one policy does not disable any sibling policy.

## Email Template Globals

`EmailOptions` will add:

```python
template_globals: dict[str, Any] = Field(default_factory=dict)
```

`FastAuth` will pass this mapping into `TemplateRenderer`. The renderer will
copy the mapping during construction and merge it beneath per-message
variables for every render:

```python
render_context = {**self.template_globals, **variables}
```

Per-message variables therefore win on collisions, preventing application
branding from replacing security-sensitive values such as an OTP or callback
URL. Copying the configuration prevents later mutation of the caller's
dictionary from changing renderer behavior.

The renderer's Jinja `Environment` remains an implementation detail; consumers
no longer need to modify `auth.context.template_renderer.environment.globals`.
Tests will cover HTML and text templates, precedence, and defensive copying.

## Trusted Server-Side User Reads

`AuthApi` will expose:

```python
async def get_user(
    self,
    *,
    by_id: UserId | str | None = None,
    by_email: EmailStr | str | None = None,
    by_username: Username | str | None = None,
) -> UserView | None:
    ...
```

Exactly one selector is required. Zero or multiple selectors raise
`InvalidRequestError(message="get_user requires exactly one selector")`.
Email and username values are normalized through `User`/value-object
validation before adapter lookup; ids use `UserId`. The method returns the safe
`UserView` DTO when found and `None` when absent. It never returns the persistence
`User` model.

The implementation will live in `fastauth.flows.server_users` beside
`create_user`, keeping trusted user operations together. It is an in-process API
only and will not add an HTTP endpoint.

## Documentation

Consumer documentation will be updated in the same vertical slice as each API:

- `docs/plugins/email-otp.md` for configured subjects and duration strings.
- `docs/plugins/jwt.md` and `docs/plugins/api-key.md` for duration inputs.
- `docs/guides/user-management.md` for username updates and their feature flag.
- `docs/concepts/config.md` and `docs/guides/deploying.md` for
  `ProductionSafetyOptions` and proxy/TLS examples.
- Email configuration documentation for `template_globals`.
- `docs/concepts/server-api.md` and `docs/reference/index.md` for `get_user`.
- Signup documentation for `require_username`.
- `README.md` where its configuration and feature summaries enumerate these
  public surfaces.

Because 0.13 does not require backward compatibility, no deprecation aliases or
migration shims will be added. Documentation will describe only the final API.

## Testing and Release Gates

Every vertical slice will follow test-driven development with a focused failing
test before implementation. Coverage will include:

- All OTP purposes use the intended configured or plugin-owned subject.
- All first-party plugin option durations accept every supported input form and
  preserve field constraints.
- Required usernames are enforced in both interactive API entry points.
- Username changes are gated, validated, unique, evented, and reflected through
  both HTTP and server-side updates.
- Lockout rekeying preserves the stricter active state across storage backends.
- Each production safety check can be relaxed without weakening sibling checks.
- Template globals render in both template formats and cannot override
  per-message values.
- `get_user` supports all three selectors, returns `None` for misses, and rejects
  ambiguous calls.

Focused test runs will be followed by the complete non-Docker suite, Ruff,
Pyright, and strict MkDocs build. Existing user changes in `skills-lock.json`
and the untracked `better-auth/` directory are unrelated and must remain
untouched.
