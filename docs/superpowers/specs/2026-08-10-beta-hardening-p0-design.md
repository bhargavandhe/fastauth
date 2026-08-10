# Beta Hardening P0 Design

## Status

Approved for implementation on `codex/beta-hardening-p0`.

## Goal

Move fastauth from an engineering-complete alpha to a beta-ready framework by
finishing the repository security baseline, operational maintenance,
observability, readiness, release automation, supported-Python matrix, API
stability policy, and executable plugin schema migrations.

An external security review is explicitly outside this milestone.

## Compatibility boundary

Fastauth is still an INDEV project with limited users. This milestone may make
breaking changes, delete dead code, change protocols, invalidate development
JWTs, and remove incomplete extension surfaces. No compatibility shims or
deprecation aliases are required for behavior that predates this milestone.

The resulting release establishes the new compatibility boundary. Starting
with that release, public removals require a documented deprecation period;
the hardening work itself does not preserve the alpha API.

## Release target

The completed milestone becomes `0.14.0` and changes the package classifier to
`Development Status :: 4 - Beta`. It is not a `1.0` release. The release is
created only after the full local and GitHub CI gates pass.

## Workstreams

### 1. Security and governance

`SECURITY.md` will support only the current pre-1.0 minor line. It will explain
the disclosure channel, response targets, supported-version rule, and the fact
that the project has not received an external audit.

The repository will add:

- `.github/dependabot.yml` for monthly GitHub Actions and Python dependency
  updates;
- `.github/workflows/security.yml` with CodeQL and `pip-audit` jobs for pull
  requests, `main`, and a weekly schedule;
- least-privilege workflow permissions and concurrency controls;
- a support guide, Code of Conduct, issue forms, pull-request template, and
  `CODEOWNERS`;
- repository description, topics, secret-scanning push protection, and
  Dependabot security updates when the GitHub API permits those settings.

JWT algorithms will use the RFC 9864 names accepted by the installed JOSE
library. `EdDSA` is removed from fastauth's public algorithm enum and the
default becomes `Ed25519`. Existing development keys and tokens using the old
algorithm are intentionally not supported. ES256 and RS256 remain available.
Tests must emit no JOSE algorithm deprecation warnings.

The default password minimum becomes 12 characters. The HIBP integration
remains a post-P0 feature, but production documentation will recommend longer
passphrases and an application-supplied compromised-password policy until it
exists.

### 2. Maintenance and retention

Maintenance is a first-class runtime subsystem rather than an HTTP endpoint.
It is safe to call from cron, a worker, a deployment job, or trusted server
code.

New public models:

- `MaintenanceOptions`
- `MaintenanceResult`
- `MaintenanceFailure`

New public entry point:

```python
result = await auth.maintenance.run()
```

The manager performs bounded, idempotent cleanup of:

- expired sessions;
- expired refresh tokens;
- expired verification records;
- expired API keys when `ApiKeyStore` is present;
- audit logs older than the configured retention period when `AuditLogStore`
  is present.

The storage contract is intentionally breaking. Core adapters must implement
bounded deletion methods for sessions, refresh tokens, and verifications.
Optional capability protocols own API-key and audit-log cleanup. Each method
accepts an explicit UTC cutoff and batch limit and returns the number removed.

`MaintenanceOptions` contains a positive `batch_size`, optional
`audit_log_retention`, and a positive `max_batches`. The manager stops when a
batch removes fewer than `batch_size` records or `max_batches` is reached. It
returns per-resource counts and failures. The default behavior is fail-fast;
an explicit `continue_on_error` option allows independent resources to
continue while returning structured failures.

MongoDB TTL indexes remain useful but are not treated as immediate cleanup.
Explicit cleanup is still supported and idempotent. Postgres executes bounded
deletes using indexed expiration columns. Memory uses deterministic in-process
deletion.

The CLI gains `fastauth maintenance` with the same MongoDB/Postgres connection
and namespace options used by `fastauth migrate`. It prints a structured
summary and exits non-zero when cleanup has failures.

### 3. Liveness, readiness, and observability

The current health operation is split into explicit semantics:

- `/health/live` and `auth.api.liveness()` prove the process and router are
  responsive without touching storage;
- `/health/ready` and `auth.api.readiness()` prove the database runtime is
  reachable and every installed plugin completed startup;
- `/health` is deleted rather than retained as an ambiguous alias.

`DatabaseAdapter` gains an async `ping()` method. Memory returns immediately,
MongoDB issues a database ping, and Postgres executes `SELECT 1`. A failed
readiness check returns HTTP 503 with a typed response containing only bounded,
non-secret component information. It must not include DSNs, exception text,
queries, user identifiers, or credentials.

Observability remains dependency-free. Fastauth will not configure global
logging and will not require Structlog, Prometheus, or OpenTelemetry.

New runtime types:

- `OperationalEvent`, a frozen Pydantic model with event name, timestamp,
  outcome, duration, HTTP status, correlation ID, and bounded component/route
  labels;
- `ObservabilitySink`, an async protocol receiving operational events;
- `LoggingObservabilitySink`, an optional standard-library logging adapter;
- `ObservabilityManager`, exposed as `auth.observability`, which supports
  decorator and imperative subscriptions.

The HTTP integration generates or accepts an `X-Request-ID`, stores it in a
`ContextVar`, adds it to the response, and includes it in operational events.
Incoming IDs are length- and character-bounded. Request events never include
tokens, passwords, email addresses, user IDs, raw IP addresses, arbitrary
paths, or exception messages. Route templates and a closed set of outcome
labels keep metrics cardinality bounded.

The runtime emits events for HTTP completion, readiness checks, maintenance
runs, database migration runs, authentication success/failure categories,
rate-limit rejection, and lockout. Existing typed domain events remain the
business integration mechanism; operational events are not a second source
of domain truth.

Documentation will provide small Prometheus and OpenTelemetry bridge examples
implemented by consumers, without adding those packages to fastauth core.

### 4. API stability policy

`API_STABILITY.md` will define the public surface as:

- names exported from documented modules and their documented signatures;
- HTTP methods, paths, request/response schemas, and error codes;
- storage and plugin protocols explicitly documented as extension contracts;
- configuration fields and CLI commands.

Implementation modules, undocumented attributes, generated OpenAPI ordering,
and database implementation details are not stable contracts.

From `0.14.0` onward, a public removal requires:

1. a changelog entry and migration instructions;
2. a runtime `FastAuthDeprecationWarning` where technically possible;
3. at least one subsequent minor release before removal;
4. no silent semantic reuse of the old name.

Because the project remains pre-1.0, unavoidable security fixes may bypass the
window and will be called out explicitly. This policy begins after the P0
breaking cleanup; it does not apply retroactively.

A small `fastauth.deprecations` module will contain the warning class and one
helper so future deprecations are consistent. No existing alpha aliases will
be retained merely to exercise it.

### 5. Python and packaging support

CI and package metadata will support Python 3.11, 3.12, 3.13, and 3.14.
Pure unit/integration tests, linting, and typing run across supported versions;
Docker-backed adapters run on the oldest and newest supported versions when
dependency compatibility permits. If an upstream adapter dependency cannot run
on 3.14, the core support claim must be narrowed instead of marking a failing
matrix as allowed.

Package metadata will point `Documentation` to the deployed MkDocs site and
add changelog and security-policy URLs. The unused `release-please-config.json`
is deleted. Version ownership stays explicit in `pyproject.toml`,
`fastauth.__version__`, `uv.lock`, README, and changelog until a separate
single-source version project is justified.

### 6. GitHub releases

The existing tag-triggered publish workflow remains the release authority.
After trusted publishing succeeds, a release job will:

1. download the exact distributions built by the workflow;
2. create a non-draft GitHub Release for the pushed tag;
3. generate release notes from the tag range;
4. attach the wheel and source distribution;
5. fail if the tag, package version, and runtime version disagree.

The job uses the GitHub CLI and `GITHUB_TOKEN` with `contents: write`; no new
long-lived secret is introduced. Workflow action versions are upgraded to
currently supported major versions so Node runtime deprecation annotations are
removed.

### 7. Executable plugin schemas

Plugin schemas become executable for the first-party MongoDB and Postgres
runtimes. The existing planning-only ambiguity is removed.

The schema model remains adapter-neutral and supports additive operations:

- create table/collection;
- create index;
- record plugin migration version.

Destructive alterations, arbitrary SQL, arbitrary MongoDB commands, column
renames, and data migrations are deliberately excluded. A plugin requiring
those operations must ship a backend-specific lifecycle hook.

`PluginMigrationMode` has three values:

- `apply`: apply pending additive operations during explicit migration;
- `check`: fail when pending operations exist;
- `disabled`: do not inspect or apply plugin schemas.

Application startup defaults to `check` in production and `apply` in
development. Production safety rejects automatic `apply`, matching the current
Postgres migration rule.

Every backend maintains a migration ledger containing plugin ID, migration
name, version, schema fingerprint, and applied timestamp. Reusing a recorded
plugin/version with a different fingerprint is an error. Operations are sorted
deterministically.

Postgres applies each plugin migration and ledger write in one transaction
under an advisory lock. MongoDB creates collections and indexes idempotently,
then writes the ledger; because MongoDB DDL is not transactionally equivalent,
retries must converge and the limitation is documented.

The database runtime owns migration execution. `fastauth migrate` builds the
plugin registry, compiles its schema plan, and invokes the backend executor.
Startup and CLI use the same executor. The CLI gains `--plugin-migrations
apply|check|disabled` and a dry-run plan output.

Packaged adapter contracts verify first application, idempotent replay,
pending checks, fingerprint mismatch, conflicting declarations, namespace
prefix/suffix behavior, and concurrent execution.

## Error handling

All new public failures derive from `FastAuthError` and have stable error
codes. Operational responses contain sanitized component names and error codes,
not raw backend exceptions. CLI commands log detailed exception chains only to
stderr when verbose mode is enabled.

Maintenance partial failure is represented in `MaintenanceResult`; fail-fast
raises the first typed maintenance error. Readiness never mutates state.
Migration checks never apply operations. Migration apply is idempotent and
detects divergent fingerprints.

## Testing strategy

Implementation follows red-green-refactor. Each workstream starts with a
failing behavioral or contract test.

Required gates:

- focused unit tests for every new model, protocol, and manager;
- integration tests for request IDs, operational events, liveness/readiness,
  and sanitized failures;
- full adapter-contract tests for cleanup and health checks;
- Docker-backed MongoDB and Postgres tests for cleanup, readiness, plugin
  migration application, idempotency, and concurrency;
- CLI tests for maintenance and migration modes;
- workflow contract tests for security and GitHub release YAML;
- zero JOSE deprecation warnings;
- Ruff format/check, strict Pyright, strict MkDocs, package build/Twine check;
- full test matrix on Python 3.11 through 3.14.

The coverage floor remains 80% globally and rises to 90% for the newly added
maintenance, observability, readiness, and migration modules.

## Documentation deliverables

- updated security and support policies;
- API stability/deprecation policy;
- operations guide covering maintenance and retention;
- observability guide with logging, Prometheus, and OpenTelemetry bridges;
- liveness/readiness deployment guidance;
- executable plugin schema authoring guide;
- migration guide from `0.13` to `0.14`;
- updated README, reference, CLI, adapter, plugin, deployment, and changelog
  pages.

## Explicitly deferred

- external security review;
- OAuth/OIDC providers;
- MFA, passkeys, and recovery codes;
- webhooks;
- RBAC/authorization;
- HIBP integration;
- built-in Prometheus/OpenTelemetry exporters;
- destructive or arbitrary-code plugin migrations;
- Redis, additional databases, and frontend SDKs.

## Completion criteria

The milestone is complete when all nine P0 items are implemented, obsolete
code is removed, the full local verification suite passes, the GitHub workflows
are green, `0.14.0` artifacts build correctly, and no required work remains
except the explicitly excluded external review.
