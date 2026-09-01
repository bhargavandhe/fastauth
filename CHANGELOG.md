# Changelog

All notable changes are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.14.1] — 2026-09-01

### Changed

- Changed the default minimum password length from 12 back to 8 characters.
  Applications can configure a higher minimum with `PasswordOptions.min_length`.

## [0.14.0] — 2026-08-10

### Added

- Added explicit `/health/live` and `/health/ready` operations plus
  `auth.api.liveness()` and lifecycle-aware `auth.api.readiness()`.
- Added privacy-bounded operational telemetry, `X-Request-ID` propagation,
  async sinks, and decorator/imperative subscriptions through
  `auth.observability`.
- Added bounded retention cleanup through `auth.maintenance.run()` and the
  `fastauth maintenance` command for memory, MongoDB, and Postgres.
- Added executable additive plugin schemas for MongoDB and Postgres with
  deterministic plans, migration ledgers, fingerprints, apply/check/disabled
  modes, namespace affixes, and concurrency control.
- Added `API_STABILITY.md`, `FastAuthDeprecationWarning`, governance templates,
  Dependabot configuration, CodeQL, and dependency-audit automation.
- Added Python 3.13 and 3.14 to the supported and tested Python matrix.

### Changed

- Changed the project classifier to beta and established 0.14 as the public
  compatibility boundary.
- Changed the default minimum password length from 8 to 12 characters.
- Changed the JWT Ed25519 algorithm spelling to the RFC 9864 `Ed25519` name.
- Changed production plugin schema startup to check for pending migrations;
  development applies them by default.
- Changed tag publishing to validate version agreement and create a GitHub
  Release with the exact wheel and source distribution published to PyPI.
- Changed maintenance and plugin-migration failures to use typed
  `FastAuthError` subclasses with stable error codes.

### Removed

- Removed the ambiguous `/health` route.
- Removed the deprecated `EdDSA` JWT algorithm spelling and the unused
  release-please configuration.

## [0.13.0] — 2026-07-30

### Added

- Added short duration strings such as `"10m"`, `"2h"`, and `"7d"` to the
  email OTP, JWT, and API-key plugin option models.
- Added purpose-aware Email OTP subjects for verification, password reset,
  email change, and sign-in messages.
- Added global Jinja email-template variables through
  `EmailOptions.template_globals`, with per-message variables taking
  precedence.
- Added independently configurable production safety policies for HTTPS,
  secure cookies, in-memory storage, console email delivery, and automatic
  migrations.
- Added trusted `auth.api.get_user(...)` lookup by exactly one user id, email,
  or username selector.
- Added `require_username` and `allow_username_change` controls to the
  email/password plugin, including `auth.users.update(..., username=...)`.

### Changed

- Username changes now enforce adapter-level uniqueness and atomically move
  active lockout state across the memory, Postgres, and Beanie backends.

## [0.12.1] — 2026-07-28

### Fixed

- Migrated the quickstart application from the removed `auth.mount()` API to
  explicit router inclusion and middleware installation.

## [0.12.0] — 2026-07-28

### Added

- Added trusted `auth.api.create_user(...)` provisioning for server-side seeds,
  workers, webhooks, and administrative code.
- Added bound `auth.CurrentUser` and `auth.CurrentSession` FastAPI dependency
  aliases.
- Added `auth.add_middleware(app)` for explicit FastAuth exception handling,
  CSRF middleware, and security headers.
- Added typed `auth.on(EventType)` and
  `auth.hook(HookPhase, target=...)` registration decorators.

### Changed

- Made `auth.router` prefix-free so applications choose its prefix with
  `app.include_router(...)`.
- Route constants and inspection output now expose relative FastAuth paths.

### Removed

- Removed `auth.mount(app)`. Include `auth.router` explicitly and call
  `auth.add_middleware(app)` when FastAuth should install its application-wide
  HTTP integration.
- Removed `auth.on_event()`. Register application event handlers with
  `auth.on(EventType)`.

## [0.11.0] — 2026-07-09

### Changed

- Canonicalized construction on `FastAuth(FastAuthOptions(...), plugins=[...])`.
- Made database factories keyword-only for backend handles:
  `mongo(database=...)`, `postgres(url=...)`, and `custom(adapter=...)`.
- Consolidated route protection dependencies under `auth.depends.user()`,
  `auth.depends.optional_user()`, `auth.depends.session()`, and
  `auth.depends.optional_session()`.
- `auth.depends.user()` now returns the public `UserView` DTO by default.
- Duration option fields now accept `timedelta`, numeric seconds, or short
  strings such as `"10m"`, `"2h"`, `"7d"`, and `"4w"`.
- `MongoDatabaseOptions.database` and `mongo(database=...)` now expose a typed
  `MongoDatabase` alias for PyMongo async databases.

### Added

- Added `docs/migrating/0.11.md` with the direct 0.10 to 0.11 migration steps.

### Removed

- Removed `create_auth(...)`.
- Removed `FastAuth.configure(...)`, `FastAuth.local_dev(...)`, and
  `FastAuth.production(...)`.
- Removed duplicate application-route dependency spellings such as
  `auth.require_user`, `auth.optional_user`, `auth.require_session`,
  `auth.optional_session`, `auth.get_current_user`, and
  `auth.get_current_session`.

## [0.10.2] — 2026-07-08

### Changed

- Split the public SDK manager implementation into focused runtime modules
  while preserving the stable `fastauth.runtime.managers` export path.

### Added

- Added CI formatting enforcement with `ruff format --check`.
- Added pytest markers for unit, integration, CLI, adapter, and Docker-backed
  tests, with automatic marker assignment by test path.
- Added an 80% coverage floor to the non-Docker CI test slice.

## [0.10.1] — 2026-07-08

### Fixed

- Plugin server API namespaces are now snapshotted after plugins are bound to
  `AuthContext`, so context-aware plugin API objects can be constructed
  directly in `server_api()`.
- `auth.inspect().routes` now reports plugin route sources from explicit route
  metadata instead of inferring source from the route path prefix.

## [0.10.0] — 2026-07-08

### Added

- Added `create_auth(...)`, `FastAuth.configure(...)`,
  `FastAuth.local_dev(...)`, and `FastAuth.production(...)` construction
  helpers.
- Added Pythonic manager namespaces on `FastAuth`: `auth.sign_up`,
  `auth.sign_in`, `auth.users`, `auth.sessions`, `auth.passwords`,
  `auth.email_changes`, `auth.depends`, `auth.routes`, and `auth.inspect`.
- Added public typed id exports (`UserId`, `SessionId`, `RefreshTokenId`,
  `ApiKeyId`) and capability id constants such as `EMAIL_PASSWORD`,
  `USERNAME_SIGN_IN`, and `API_KEYS`.
- Added split adapter contract classes under `fastauth.testing` so extension
  authors can test only the storage capabilities their backend implements.

### Changed

- `UserPrincipal`, `SessionPrincipal`, and session-revocation commands now use
  the public Pydantic id value objects instead of plain strings.
- Plugin surfaces are snapshotted during `PluginRegistry` construction, so
  validation and runtime mounting observe the same endpoints, capabilities,
  rate limits, event handlers, trusted origins, and server API namespaces.
- `PluginInfo.endpoints` now exposes serializable `EndpointInfo` metadata
  instead of live `EndpointSpec` handlers.
- First-party plugin factories are exported from the package root for concise
  application setup.
- First-party plugin `bind()` overrides now call the base context-binding hook.

### Removed

- Removed the unused `EndpointSpec.request_model` field. Request bodies are
  inferred from typed FastAPI handler signatures.

## [0.9.0] — 2026-07-08

### Added

- Added a public plugin SDK surface for plugin capabilities, plugin metadata,
  and plugin-contributed server API namespaces under `auth.api.plugins`.
- Added `auth.capabilities` with core and plugin capability discovery.
- Added `auth.events` and `auth.on_event(...)` as the public structured
  security-event subscription surface.
- Added `fastauth.testing.adapter_contract` plus the `testing` optional extra
  so adapter authors can run the first-party adapter compliance contract.

### Changed

- First-party plugins now declare discoverable capabilities that reflect
  option-gated runtime behavior.
- The built-in adapter suites now import the same packaged adapter contract
  exposed to third-party adapter authors.

## [0.8.0] — 2026-07-08

### Added

- Added a dedicated `RefreshSessionConsistencyError` for refresh rotations
  that commit a replacement token but require family-wide compensation after
  previous-session cleanup fails.

### Changed

- Postgres refresh-token rotation and family revocation now acquire the same
  namespaced transaction advisory lock per family. This serializes rotation
  against family revocation, but does not claim every bulk refresh-token
  deletion path is globally race-free.
- Beanie refresh-family revocation now deletes associated sessions before
  deleting refresh-token rows, preserving retry state when session deletion
  fails. MongoDB revocation remains best-effort without transactions.
- FastAuth lifespan handling now groups body/plugin failures with database
  shutdown failures only when both occur, and otherwise preserves the original
  exception or context-manager suppression semantics.
- Session revocation responses now require explicit `revoked`,
  `revokedSessions`, and `revokedRefreshTokens` counts and reject inconsistent
  `revoked`/`revokedSessions` values.

### Removed

- Removed the deprecated `fastauth.api.legacy` command models and all `user=`
  server API compatibility paths. Server API commands must use
  `UserPrincipal` or `SessionPrincipal`.

## [0.7.0] — 2026-07-07

### Added

- Added `UserPrincipal` and `SessionPrincipal` as the canonical immutable
  server API identity models.
- Added explicit `revokedSessions` and `revokedRefreshTokens` response fields
  to session revocation responses while preserving `revoked`.

### Changed

- Refresh-token family revocation now happens at the adapter level and revokes
  associated database sessions where the adapter can do so consistently.
- Postgres refresh-family deletion now uses `DELETE ... RETURNING session_id`
  to remove the refresh-row race between lookup and deletion.
- `custom()` now accepts `backend` and `lifespan` keyword arguments.
- `DatabaseRuntime` now requires only `adapter` and `lifespan()`.

### Fixed

- Refresh rotation now revokes the family if previous-session cleanup fails
  after a replacement token has been committed.
- `auth.mount()` no longer replaces the host application's `HTTPException`
  handler.
- Lifespan body failures and database-shutdown failures are reported as an
  explicit exception group.

## [0.6.0] — 2026-07-07

### Added

- Added `AuthPrincipal` for immutable server API caller identity.
- Added refresh-family revocation results so reuse detection can revoke
  associated database sessions.
- Added production validation for rotation secrets, custom memory backends, and
  HTTP callback URL overrides.

### Changed

- Email/password TTLs and email-verification requirements now have one runtime
  source of truth in global flow options.
- Refresh rotation no longer leaves unbounded visible database sessions.
- Database runtime lifecycle now uses async context managers and unwinds through
  `AsyncExitStack`.
- Email/password route handlers are split out of the provider options module
  into typed endpoint groups.
- Username validation now uses one shared constrained value type across domain,
  HTTP, and server API models.

### Fixed

- `auth.api.sign_in.username()` now respects
  `EmailPasswordOptions.allow_username_sign_in=False`.
- FastAuth dependency errors installed through `auth.mount(app)` now return the
  canonical `{code, message}` response shape.
- Local HTTP quickstart now explicitly disables secure cookies only for local
  development.

## [0.5.0] — 2026-07-07

### Added

- Added trusted-proxy client IP resolution with secure defaults.
- Linked refresh-token families to sessions across memory, Beanie, and Postgres.
- Added production option validation for weak secrets, unsafe cookies, memory
  storage, non-HTTPS base URLs, and automatic Postgres migrations.
- Added shallow exports for `AuthenticationResponse`, `SessionView`, and
  `UserView`, plus concise dependency aliases on `FastAuth`.
- Added namespaced server-side APIs for session, password, and user operations.
- Added a managed database runtime abstraction so adapter startup and shutdown
  are owned by database options instead of `FastAuth` concrete type checks.

### Changed

- Refresh-token absolute lifetime now uses the family creation timestamp rather
  than the rotated token creation timestamp.
- Password validation and hashing now use one core credential policy instead of
  provider-level duplicate password policy.
- Email verification, password reset, email-change, and delete-account links now
  derive from `app.base_url` plus callback paths by default.
- Email/password routes are now contributed by the email-password plugin instead
  of being hardcoded in the core FastAPI router.
- Plugin lifespan shutdown is now exception-safe and runs in reverse startup
  order.
- Removed the dead top-level `PluginOptions.enabled` option; plugin presence is
  the feature switch.
- Removed default trust for forwarded IP headers; forwarded headers are only
  honored from configured trusted proxies.

### Fixed

- Server-side email/password APIs now require the email-password provider to be
  installed.
- Session revocation and sign-out now revoke the corresponding refresh-token
  families instead of leaving bearer clients able to refresh.
- Documentation, examples, and security policy now match the current API.

## [0.4.2] — 2026-07-06

### Changed

- Reorganized unit and integration tests into domain-focused folders and added
  shared path helpers for repository-relative test contracts.

## [0.4.1] — 2026-07-06

### Fixed

- Fixed adapter-backed rate-limit bucket creation for Beanie and Postgres when
  the first request starts a new fixed window.

## [0.4.0] — 2026-07-06

### Added

- Mounted shared session routes (`/auth/get-session`, `/auth/sign-out`,
  `/auth/refresh`, and `/auth/sessions`) for OTP-only plugin configurations.
- Added API-key per-key rate-limit enforcement and validation coverage.

### Changed

- Rate-limit storage now uses a consistent fixed-window bucket contract across
  memory, Beanie, and Postgres adapters.
- Plugin route registration now rejects duplicate plugin routes and plugin
  routes that collide with built-in auth routes.
- API-key and audit-log list endpoints now validate pagination query
  parameters (`limit >= 1`, `offset >= 0`).
- Email/password plugin options are now enforced consistently for bearer
  delivery, username sign-in routes, verification requirements, and TTLs.

### Fixed

- Password reset, password change, set-password, sign-out, email change, and
  OTP password reset now revoke refresh tokens where applicable.
- Password reset/change/set/email-change flows now clear relevant lockout
  counters.
- Password reset now publishes `PasswordResetRequested` for unknown emails
  while preserving anti-enumeration responses.
- Email identifiers are normalized consistently across reset, verification,
  email-change, OTP, and sign-in flows.
- Username uniqueness is enforced across first-party adapters.
- API-key creation now rejects incomplete paired options for refill and
  rate-limit settings.
- JWT, password-reset, and email-verification documentation now match current
  runtime behavior.

## [0.3.4] — 2026-07-01

### Fixed

- Updated the quickstart end-to-end test to assert the canonical camelCase
  audit-log response field `eventType`.

## [0.3.3] — 2026-07-01

### Fixed

- Fixed JWT issuance when `JwtPlugin` uses the default app `base_url` for
  issuer/audience. Pydantic `AnyHttpUrl` values are now converted to strings
  before signing, so `/auth/get-session` and `/auth/token` remain JSON
  serializable in the quickstart app.

## [0.3.2] — 2026-07-01

### Fixed

- Hardened API key quota handling so authorization is checked before usage is
  decremented.
- Made CSRF origin validation reject missing origins by default on unsafe
  methods.
- Added idle-timeout enforcement for database-backed sessions.
- Rejected refresh-token cookie delivery and kept refresh tokens bearer-only.
- Normalized email values at Pydantic/domain boundaries.
- Returned safe public audit-log DTOs instead of storage/domain records.
- Guarded production deployments from using the console email sender.
- Added atomic cross-adapter rate-limit increments.
- Removed the unused `SessionOptions.rotate_on_refresh` field and corrected
  session documentation.
- Hid router-only internals from the public `auth.api` surface.
- Updated route-protection documentation to prefer `UserView` dependencies.

## [0.3.1] — 2026-07-01

### Fixed

- Fixed Beanie public document classes (`UserDoc`, `SessionDoc`, `AccountDoc`,
  `RefreshTokenDoc`, `VerificationDoc`, `ApiKeyDoc`, `JwksKeyDoc`,
  `AuditLogDoc`, and `RateLimitDoc`) when MongoDB collection prefix/suffix
  customization is enabled. `init_beanie_documents()` now configures and
  initializes the exported document classes directly, so Beanie query patterns
  such as `UserDoc.find(UserDoc.id == oid)` keep working with custom
  collection names.

## [0.3.0] — 2026-06-30

### Added

- Added MongoDB collection prefix/suffix customization through
  `MongoDatabaseConfig`, `BeanieAdapter`, `init_beanie_documents`, generated
  Mongo scaffolds, and `fastauth migrate`.
- Added Postgres table suffix customization alongside the existing table
  prefix support, including config, adapter, schema builder, CLI migrate, and
  generated scaffolds.

## [0.2.2] — 2026-06-27

### Fixed

- Fixed the quickstart Docker-backed test fixture for PyMongo's async client by
  constructing the Mongo client inside the same event loop that drives the
  FastAPI lifespan and HTTP client.

## [0.2.1] — 2026-06-27

### Fixed

- Fixed Beanie 2 compatibility by switching MongoDB setup, examples, adapter
  tests, and CLI scaffolds from Motor to PyMongo's async client, which is the
  database interface Beanie 2 expects.
- Removed the obsolete `motor` dependency from the `beanie` extra.

## [0.2.0] — 2026-06-27

### Added

- **`FastAuthConfig.wire_format: WireFormat`** (default
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
- Cross-adapter refresh-token rotation contract coverage now runs through the
  shared adapter contract suite. Every first-party adapter must preserve the
  root family id, set `consumed_at`, set `replaced_by`, persist the successor,
  and reject a second rotation of the same token.

### Changed

- **Breaking:** `FastAuth(config)` no longer silently creates an
  `InMemoryAdapter`. Pass storage explicitly, for example
  `FastAuth(config, adapter=InMemoryAdapter())`, `BeanieAdapter`, or
  `PostgresAdapter`.
- `fastauth init` now accepts `--backend memory|mongo|postgres`; the default
  scaffold is dependency-light and no longer Mongo-specific.
- `Plugin` now stores bound `AuthContext` by default and exposes
  `require_context()`, `require_capability(...)`, and
  `require_session(request)` helpers for common plugin-author boilerplate.
- `Plugin` now exposes `extend_session_response(user, response)` so plugins can
  add response behavior without the core FastAPI router importing concrete
  plugin modules. `JwtPlugin` uses this hook for the optional `set-auth-jwt`
  header.
- Postgres schema setup now runs through an ordered migration registry under a
  transaction-level advisory lock. The current migration set records version
  `1` for the initial fastauth schema.
- Removed the unimplemented `redis` optional dependency extra until Redis
  storage exists.
- CI now runs lint/typecheck and tests on Python 3.11 and 3.12, and validates
  built distributions with `uv build` plus `twine check`.
- All public request and response models (sign-up, sign-in, refresh,
  session-management, verification, password-reset, change-password,
  change-email, email-OTP, API keys, JWT-token, audit logs, health)
  now inherit from a new `WireModel` base in
  `fastauth.domain.models`. The base carries
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

### Fixed

- Beanie update methods no longer clobber Mongo `ObjectId` fields into strings
  on update. Updates now assign through the Beanie document and call
  `replace()`.
- Beanie storage keeps Mongo-owned PK/FK fields as BSON `ObjectId` while
  keeping protocol identifiers such as `JwksKey.kid` as strings.
- Refresh-token and JWKS key ids are storage-neutral again in the domain and
  security layers; Mongo-specific id conversion lives in the Beanie adapter.
- Camel wire-format rendering no longer rewrites application/spec-defined
  nested JSON keys such as `User.metadata`, API-key `permissions`, audit-log
  `event_data`, and JWKS `keys`.

## [0.1.0] — 2026-06-24

First public release. fastauth is a modular, Pydantic-native, async-only
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
- `FastAuthConfig` with 15 sub-configs (`AppConfig`, `SessionConfig`,
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
- `BeanieAdapter` (MongoDB via Beanie). Native `bson.ObjectId` storage
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
- `FastAuth.as_asgi()` — standalone FastAPI app with router + middleware
  pre-installed.
- `FastAuth.router` — `APIRouter` for `app.include_router(...)` integration.
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
- `FastAuthRoute(APIRoute)` — catches every `FastAuthError`, emits the matching
  HTTP status with `{code, message}` JSON. `RateLimitError` gets
  `X-Retry-After`; `AccountLockedError` gets `Retry-After`.
- `CurrentUser`, `OptionalCurrentUser`, `CurrentSession`,
  `OptionalCurrentSession` — FastAPI `Depends(...)` shortcuts on the
  `FastAuth` instance; both `Depends(auth.get_current_user)` and
  `Annotated[..., Depends(auth.get_current_user)]` calling styles documented.

#### CLI
- `fastauth` Typer CLI with three commands:
  - `fastauth init` — scaffolds an `auth.py` that accepts explicit
    `FastAuthConfig` and adapter dependencies.
  - `fastauth migrate --mongo-url <url>` — applies Beanie's index migrations.
  - `fastauth migrate --postgres-url <url>` — applies tracked Postgres schema
    migrations for the SQLAlchemy adapter and records the current schema
    version.
  - `fastauth generate-secret` — emits a cryptographically random 64-byte hex
    string for `secret_key`.

#### Tooling, packaging, docs
- `uv` for dependency management. `ruff check` + `ruff format` + `pyright
  --strict` (zero errors, zero warnings) gate every commit.
- Test suite covering unit, adapter-contract, integration, CLI, docs
  contracts, and the quickstart example app.
- mkdocs-material site built with `mkdocs --strict`. Plugin pages,
  concept pages, guides for KMS signing, password reset, email verification.
- Quickstart example app under `examples/quickstart/` with its own test
  suite (4 end-to-end scenarios against a real test client).
- `py.typed` marker — full type information ships with the wheel.
- GitHub Actions workflow: matrix on Python 3.11 + 3.12, Ubuntu, with
  service-container MongoDB. Pre-configured release workflow for tag-based
  PyPI publishing.

### Changed

- **Package layout reorganized** (`refactor!: reorganize package layout`).
  `fastauth.core.*` and `fastauth.adapters.*` are gone; the new top-level
  subsystems are `fastauth.domain`, `fastauth.security`, `fastauth.storage`,
  `fastauth.messaging`, `fastauth.runtime`, `fastauth.web`, `fastauth.flows`,
  `fastauth.plugins`, `fastauth.cli` plus `fastauth.config` and
  `fastauth.exceptions` at the package root. Public re-exports
  (`from fastauth import FastAuth, FastAuthConfig`) unchanged.
- **`FastAuthConfig` is now a plain `BaseModel`** (`refactor(config)!:
  FastAuthConfig is a plain BaseModel; env loading is opt-in`).
  `pydantic-settings` is no longer a dependency and the framework reads
  no `os.environ`. Configuration is constructed explicitly; consumers
  source values from whatever they prefer (env, Vault, Parameter Store,
  ...). Subsequent commit `refactor(config)!: remove all env-variable
  support from the framework` removed the `FastAuthEnvConfig` opt-in
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
  session strategy; now `FastAuth.__init__` looks up the installed
  `JwtPlugin` and constructs the strategy from its `JwksRegistry`
  automatically. `JwtPlugin.bind` is now idempotent.

### Fixed

- `JwksRegistry` recovers when `FASTAUTH_SECRET_KEY` is rotated without an
  accompanying `secret_key_rotation` entry: each KEK is derived from
  `secret_key + each rotation seed`, and decryption tries every known KEK
  before giving up. `ensure_key()` proactively rotates undecryptable
  active keys at startup so request-time decryption stays serviceable.
- API-key creation rejects non-positive `remaining`, `refill_amount`,
  `refill_interval_ms`, `expires_in_seconds`, `rate_limit_max`, and
  `rate_limit_window_ms` (previously the validators only rejected `<= 0`
  for some fields; now uniformly `Field(ge=1)`).
- `test_defaults_match_documented_values` clears any leaked `FASTAUTH_*`
  environment variables so an ambient `FASTAUTH_SECRET_KEY` in the
  developer's shell doesn't break the test.

### Removed

- `pydantic-settings` dependency (along with `BaseSettings` usage).
- `FastAuthEnvConfig` subclass and its env-loading machinery.
- `fastauth init` no longer writes a `.env.example`.
- `fastauth print-config` removed (read your config however you like —
  the framework no longer prescribes a source).

[Unreleased]: https://github.com/bhargavandhe/fastauth/compare/v0.14.1...HEAD
[0.14.1]: https://github.com/bhargavandhe/fastauth/compare/v0.14.0...v0.14.1
[0.14.0]: https://github.com/bhargavandhe/fastauth/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/bhargavandhe/fastauth/compare/v0.12.1...v0.13.0
[0.12.1]: https://github.com/bhargavandhe/fastauth/compare/v0.12.0...v0.12.1
[0.12.0]: https://github.com/bhargavandhe/fastauth/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/bhargavandhe/fastauth/compare/v0.10.2...v0.11.0
[0.10.2]: https://github.com/bhargavandhe/fastauth/compare/v0.10.1...v0.10.2
[0.10.1]: https://github.com/bhargavandhe/fastauth/compare/v0.10.0...v0.10.1
[0.10.0]: https://github.com/bhargavandhe/fastauth/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/bhargavandhe/fastauth/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/bhargavandhe/fastauth/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/bhargavandhe/fastauth/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/bhargavandhe/fastauth/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/bhargavandhe/fastauth/compare/v0.4.2...v0.5.0
[0.4.2]: https://github.com/bhargavandhe/fastauth/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/bhargavandhe/fastauth/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/bhargavandhe/fastauth/compare/v0.3.4...v0.4.0
[0.3.4]: https://github.com/bhargavandhe/fastauth/releases/tag/v0.3.4
[0.1.0]: https://github.com/bhargavandhe/fastauth/releases/tag/v0.1.0
