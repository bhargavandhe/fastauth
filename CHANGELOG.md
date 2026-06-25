# Changelog

All notable changes are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **`AuthKitConfig.wire_format: WireFormat`** (default
  `WireFormat.SNAKE`). When set to `WireFormat.CAMEL`, every public
  response body is emitted with `camelCase` keys (`email_verified` →
  `emailVerified`, `refresh_token` → `refreshToken`, including nested
  models like the `user` and `session` fields inside `SessionResponse`).
  Both casings are always accepted on input regardless of this setting,
  thanks to `populate_by_name=True` + `alias_generator=to_camel` on the
  new `WireModel` base. SNAKE remains the default — no breaking change
  for existing consumers. Implementation: a custom
  `CamelJSONResponse` recursively converts keys at response render
  time; persistence (Beanie/Mongo) is unaffected. See
  [docs/concepts/config.md#wire-format](docs/concepts/config.md#wire-format).
- **`EmailOtpPlugin`** — passwordless sign-in, email verification, password
  reset, and (optional) email change via 6-digit one-time codes delivered
  to email. Mirrors better-auth's `emailOTP` plugin surface so client
  patterns transfer directly. Eight endpoints under `/auth/email-otp/*`
  plus `/auth/sign-in/email-otp`. Hashed-at-rest storage (no plaintext
  recovery), per-OTP attempt cap (default 3), lockout-coupled (failed
  OTPs feed `AccountLockoutTracker` like failed password attempts do),
  rotate-only resend strategy, anti-enumeration on send + reset. Auto-
  registers new users on sign-in by default (`disable_sign_up=False`);
  newly-created users get an `Account` row with
  `provider_id=EMAIL_OTP` and no password. The change-email pair is
  gated by `change_email_enabled` (default `False`); set
  `change_email_verify_current=True` for a double-confirm flow that
  requires an OTP from the current email before issuing one to the new
  email. See [docs/plugins/email-otp.md](docs/plugins/email-otp.md).

### Changed

- All public request and response models (sign-up, sign-in, refresh,
  session-management, verification, password-reset, change-password,
  change-email, email-OTP, API keys, JWT-token, audit logs, health)
  now inherit from a new `WireModel` base in
  `authkit.domain.models`. The base carries
  `alias_generator=to_camel` + `populate_by_name=True` so request
  bodies in either casing are accepted out of the box. This is purely
  additive on input — existing snake_case clients are unaffected.
- `Verification` model gained an `attempt_count: int = 0` field so OTP
  flows can enforce the per-OTP attempt cap. Token-based flows ignore
  the field (it's never bumped from those paths).
- `DatabaseAdapter` Protocol gained two methods:
  `get_active_verification(identifier, purpose)` (returns the most
  recent un-consumed row without needing the value hash, used by OTP
  flows) and `update_verification(verification)` (used to bump
  `attempt_count` on miss). Both `InMemoryAdapter` and `BeanieAdapter`
  implement them.
- `VerificationPurpose` enum gained four OTP-specific values:
  `EMAIL_OTP_SIGN_IN`, `EMAIL_OTP_VERIFICATION`,
  `EMAIL_OTP_PASSWORD_RESET`, `EMAIL_OTP_EMAIL_CHANGE`.
- `AuditEventType` gained `OTP_REQUESTED`, `OTP_VERIFIED`,
  `OTP_VERIFY_FAILED` for audit-safe (no plaintext) OTP lifecycle
  tracking. The pre-existing `OtpGenerated` event still carries
  plaintext for `TestUtilsPlugin.get_otp(...)`; `AuditLogsPlugin`
  filters it out.

## [0.1.0] — 2026-06-24

First public release. authkit is a modular, Pydantic-native, async-only
authentication library for FastAPI. v0.1 ships credentials auth, sessions
(database-backed or JWT), email verification, password reset, change-password,
change-email, account lockout, CSRF, rate limiting, security headers, multi-
session management, refresh tokens with rotation, API keys, an OpenAPI viewer,
test utilities, and a CLI.

### Added

#### Domain & configuration
- Pydantic v2 domain models: `User`, `Session`, `Account`, `Verification`,
  `ApiKey`, `JwksKey`, `RateLimit`, `AuditLog`, `EmailMessage`, `RefreshToken`.
  All use `ConfigDict(extra="forbid", validate_assignment=True)` and store ids
  as `str` (UUID-hex or ObjectId-hex depending on backend).
- `User.metadata: dict[str, Any]` for application-side extension fields.
- Closed-set string enums: `ProviderId`, `VerificationPurpose`, `AuditEventType`,
  `SessionStrategyKind`, `TokenType`, `HookPhase`, `RateLimitStorageKind`,
  `EmailMessageKind`, `JwtAlgorithm`.
- `AuthKitConfig` with 15 sub-configs (`AppConfig`, `SessionConfig`,
  `CookieConfig`, `PasswordConfig`, `EmailConfig`, `EmailVerificationConfig`,
  `PasswordResetConfig`, `EmailChangeConfig`, `RateLimitConfig`, `CsrfConfig`,
  `LockoutConfig`, `RefreshTokenConfig`, `SecurityHeadersConfig`,
  `DatabaseConfig`, `AdvancedConfig`). Plain `BaseModel` — no env-var loading.
- Exception hierarchy with `EXCEPTION_HTTP_STATUS` map: 16 exception classes
  including `InvalidCredentialsError` (401), `EmailNotVerifiedError` (403),
  `AccountLockedError` (423, `Retry-After`), `RateLimitError` (429),
  `RefreshTokenReuseError` (401), `JwksDecryptionError` (500).

#### Storage
- `DatabaseAdapter` Protocol with ~50 methods covering every domain model.
- `InMemoryAdapter` for tests and ephemeral deployments (dict-backed,
  `asyncio.Lock`-guarded).
- `BeanieAdapter` (MongoDB via Motor + Beanie). Native `bson.ObjectId` storage
  for PKs and foreign keys; string⇄ObjectId conversion at the adapter
  boundary. TTL indexes on `sessions.expires_at`, `verifications.expires_at`,
  `refresh_tokens.expires_at`; unique-index protection on
  `users.email`, `users.username`, hashes, etc.
- Adapter-contract test suite shared between InMemory and Beanie so the two
  backends remain behaviourally interchangeable.

#### Security primitives
- `Argon2idHasher` (PHC strings, configurable time/memory/parallelism).
- `TokenService` — URL-safe opaque tokens + SHA-256 hash for at-rest storage.
- `SignedCookieValue` with `itsdangerous`, key-rotation support.
- `JwksRegistry` + `LocalKmsSigner` (RS256 default; ES256, EdDSA, HS256 also
  supported). Private keys are AES-GCM-encrypted at rest using a KEK derived
  from `secret_key`. Multi-KEK decryption via `secret_key_rotation` lets you
  rotate the master secret without losing access to existing JWKs. Proactive
  re-key on startup when the active key can't be decrypted with the current
  KEK; raises `JwksDecryptionError` only when every known KEK fails.
- `KmsSigner` Protocol for external HSM/KMS integrations.
- `JwtSessionStrategy` (stateless tokens, JWKS-backed signature) and
  `DatabaseSessionStrategy` (revocable, IP/UA bound).
- `RefreshTokenService` — long-lived opaque tokens with **one-time-use
  rotation** and **family-revocation theft-detection** (presenting an
  already-rotated token revokes every token in the rotation chain).
  Optional `absolute_max_age_seconds` caps the lifetime of a single chain
  even with continuous rotation.
- `AccountLockoutTracker` — locks an identifier after 5 failed sign-ins in 15
  minutes (configurable). Returns HTTP 423 with `Retry-After` on the
  triggering attempt. Reuses `RateLimitStorage` so memory + DB backends both
  work without new infrastructure.
- `RateLimiter` with `RateLimitStorage` Protocol (`MemoryRateLimitStorage`,
  `DatabaseRateLimitStorage`); per-(IP-bucket, path) windowing with /64
  IPv6-subnet bucketing.

#### Flows
- `sign-up/email`, `sign-in/email`, `sign-in/username`, `sign-out`,
  `get-session`. `include_token=true` opt-in for bearer-token responses.
- `send-verification-email` and `verify-email` with anti-enumeration (always
  returns success on `send-verification-email` regardless of whether the
  identifier exists).
- `forgot-password` and `reset-password` (revokes every session on
  successful reset, anti-enumeration on `forgot-password`).
- `change-password` (authenticated; revokes other sessions by default,
  keeps the current session).
- `change-email/request` and `change-email/confirm` (authenticated; requires
  password re-verification; new email is held in `User.pending_email_change`
  until confirmation; `email_verified` only set true on confirm).
- `refresh` — exchange a refresh token for a fresh session + rotated
  refresh token. Reuse → 401 + family revocation.

#### Sessions & multi-device
- `GET /auth/sessions` — list every session belonging to the caller with an
  `is_current` flag. Token hashes never leak in the response.
- `DELETE /auth/sessions/{id}` — revoke a specific session. Cross-user
  lookups return 404 (no information leak).
- `DELETE /auth/sessions` — revoke every session except the caller's
  current one.

#### Plugins
- Five built-in plugins, each independently installable:
  - **ApiKeyPlugin** — create/verify/list/update/delete API keys with
    optional refilling quotas and per-key rate limits.
  - **JwtPlugin** — `/auth/token` to exchange a session for a JWT, `/auth/jwks`
    for the public JWK set, optional `set-auth-jwt` response header that
    auto-attaches a JWT to every authenticated response.
  - **AuditLogsPlugin** — auto-subscribes to every `AuthEvent`, persists
    structured rows, exposes a paginated query endpoint. Plain-text OTPs
    are filtered out before persistence.
  - **OpenApiPlugin** — Scalar UI at `/auth/reference`, JSON schema at
    `/auth/openapi.json`. Offline schema generation via
    `AuthApi.generate_openapi_schema()`.
  - **TestUtilsPlugin** — `create_user`, `save_user`, `login`,
    `get_auth_headers`, `get_otp`, `clear_otps`. Auto-captures plain-text
    OTPs from the internal `OtpGenerated` event for assertion.
- `Plugin` ABC + `PluginRegistry` + `EndpointSpec` + `RateLimitRule`. Plugins
  contribute endpoints, event handlers, lifespan hooks, and rate-limit
  policies; everything wires into the central router and event bus.

#### Web & integrations
- `AuthKit.as_asgi()` — standalone FastAPI app with router + middleware
  pre-installed.
- `AuthKit.router` — `APIRouter` for `app.include_router(...)` integration.
  `install_csrf(app, context)` and `install_security_headers(app, context)`
  helpers for that path.
- `CsrfMiddleware` — `Origin`/`Referer` validation on state-changing methods;
  bearer-only requests (no cookie, `Authorization: Bearer ...` present) are
  exempt.
- `SecurityHeadersMiddleware` — OWASP-recommended defaults (HSTS,
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: strict-origin-when-cross-origin`); opt-in
  `Permissions-Policy` and `Content-Security-Policy` fields. Honours
  app-set headers (first occurrence wins).
- `AuthKitRoute(APIRoute)` — catches every `AuthKitError`, emits the matching
  HTTP status with `{code, message}` JSON. `RateLimitError` gets
  `X-Retry-After`; `AccountLockedError` gets `Retry-After`.
- `CurrentUser`, `OptionalCurrentUser`, `CurrentSession`,
  `OptionalCurrentSession` — FastAPI `Depends(...)` shortcuts on the
  `AuthKit` instance; both `Depends(auth.get_current_user)` and
  `Annotated[..., Depends(auth.get_current_user)]` calling styles documented.

#### CLI
- `authkit` Typer CLI with three commands:
  - `authkit init` — scaffolds an `auth.py` that reads from `os.environ`.
  - `authkit migrate --mongo-url <url>` — applies Beanie's index migrations.
  - `authkit generate-secret` — emits a cryptographically random 64-byte hex
    string for `secret_key`.

#### Tooling, packaging, docs
- `uv` for dependency management. `ruff check` + `ruff format` + `pyright
  --strict` (zero errors, zero warnings) gate every commit.
- Test suite: **258 tests** covering unit, adapter-contract, integration
  (against real Mongo or testcontainer), CLI, example app.
- mkdocs-material site (22 pages) built with `mkdocs --strict`. Plugin pages,
  concept pages, guides for KMS signing, password reset, email verification.
- Quickstart example app under `examples/quickstart/` with its own test
  suite (4 end-to-end scenarios against a real test client).
- `py.typed` marker — full type information ships with the wheel.
- GitHub Actions workflow: matrix on Python 3.11 + 3.12, Ubuntu, with
  service-container MongoDB. Pre-configured release workflow for tag-based
  PyPI publishing.

### Changed

- **Package layout reorganized** (`refactor!: reorganize package layout`).
  `authkit.core.*` and `authkit.adapters.*` are gone; the new top-level
  subsystems are `authkit.domain`, `authkit.security`, `authkit.storage`,
  `authkit.messaging`, `authkit.runtime`, `authkit.web`, `authkit.flows`,
  `authkit.plugins`, `authkit.cli` plus `authkit.config` and
  `authkit.exceptions` at the package root. Public re-exports
  (`from authkit import AuthKit, AuthKitConfig`) unchanged.
- **`AuthKitConfig` is now a plain `BaseModel`** (`refactor(config)!:
  AuthKitConfig is a plain BaseModel; env loading is opt-in`).
  `pydantic-settings` is no longer a dependency and the framework reads
  no `os.environ`. Configuration is constructed explicitly; consumers
  source values from whatever they prefer (env, Vault, Parameter Store,
  ...). Subsequent commit `refactor(config)!: remove all env-variable
  support from the framework` removed the `AuthKitEnvConfig` opt-in
  subclass entirely; the CLI `print-config` command and the
  `.env.example` scaffold were also dropped.
- **Beanie adapter stores PKs and FKs as native `bson.ObjectId`**
  (`feat(adapters)!: store PKs and FKs as native MongoDB ObjectId`).
  Domain models keep `str` ids; the adapter converts string↔ObjectId at
  every CRUD boundary. Existing data stored with the previous string-id
  shape requires a migration.
- **Refresh tokens enabled by default** (`feat(security)!: refresh tokens
  enabled by default`). `RefreshTokenConfig.enabled` flipped from
  `False` to `True`. Cookie-only clients (`include_token=false`) are
  unaffected — refresh tokens piggyback on the bearer-token transport
  opt-in.
- **`JwtSessionStrategy` is now the default when `SessionConfig.strategy =
  JWT`.** Previously the JWT plugin had to be manually wired as the
  session strategy; now `AuthKit.__init__` looks up the installed
  `JwtPlugin` and constructs the strategy from its `JwksRegistry`
  automatically. `JwtPlugin.bind` is now idempotent.

### Fixed

- `JwksRegistry` recovers when `AUTHKIT_SECRET_KEY` is rotated without an
  accompanying `secret_key_rotation` entry: each KEK is derived from
  `secret_key + each rotation seed`, and decryption tries every known KEK
  before giving up. `ensure_key()` proactively rotates undecryptable
  active keys at startup so request-time decryption stays serviceable.
- API-key creation rejects non-positive `remaining`, `refill_amount`,
  `refill_interval_ms`, `expires_in_seconds`, `rate_limit_max`, and
  `rate_limit_window_ms` (previously the validators only rejected `<= 0`
  for some fields; now uniformly `Field(ge=1)`).
- `test_defaults_match_documented_values` clears any leaked `AUTHKIT_*`
  environment variables so an ambient `AUTHKIT_SECRET_KEY` in the
  developer's shell doesn't break the test.

### Removed

- `pydantic-settings` dependency (along with `BaseSettings` usage).
- `AuthKitEnvConfig` subclass and its env-loading machinery.
- `authkit init` no longer writes a `.env.example`.
- `authkit print-config` removed (read your config however you like —
  the framework no longer prescribes a source).

[Unreleased]: https://github.com/authkit/authkit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/authkit/authkit/releases/tag/v0.1.0
