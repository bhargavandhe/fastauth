# Server API, Prefix-Free Router, and Dependency Aliases

## Goal

Expose a clean, Better Auth-inspired server API for privileged user creation,
make FastAuth routing idiomatic for FastAPI applications, and provide bound
dependency aliases for protected routes.

The public usage should be:

```python
user = await auth.api.create_user(
    email="admin@app.com",
    password="secure-password",
    metadata={"role": "admin"},
)

app.include_router(auth.router, prefix="/api/auth", tags=["auth"])

@app.get("/me")
async def get_me(user: auth.CurrentUser) -> UserView:
    return user
```

Backward compatibility with the router's existing embedded-prefix behavior is
not required.

## Server-Side User Creation

`AuthApi` will expose this method:

```python
async def create_user(
    *,
    email: EmailStr | str,
    password: SecretStr | str,
    name: str | None = None,
    username: Username | str | None = None,
    metadata: UserMetadata | Mapping[str, JsonValue] | None = None,
) -> UserView:
    ...
```

The method is a trusted, in-process administrative operation. It will:

1. Validate and normalize the email, username, password, and metadata through
   the same domain types and password policy used by the authentication flows.
2. Reject an existing email or username through the storage adapter's canonical
   errors.
3. Run the `BEFORE_CREATE` user database hooks.
4. Persist the resulting user.
5. Hash the password and create the credential account.
6. Run the `AFTER_CREATE` user database hooks.
7. Publish a `UserCreated` event for audit and application subscribers.
8. Return the safe `UserView` DTO.

It will not create a session, issue access or refresh credentials, or send a
verification email. This makes it suitable for database seeds, background
workers, webhook handlers, and administrative provisioning.

The operation will live in a dedicated flow rather than reusing the interactive
email sign-up flow. Both flows may share small validation or persistence helpers
where doing so avoids behavioral drift. The dedicated flow prevents interactive
side effects from leaking into privileged server code.

`UserCreated` will be a distinct event rather than overloading `UserSignedUp`.
It will carry the created user's id and normalized email, with no request IP or
user agent. Audit log subscribers already consume the `AuthEvent` base class, so
the new event will be recorded without plugin-specific wiring.

The adapter interface currently creates users and accounts as separate
operations. This feature will retain that established storage contract rather
than introducing a transaction API in unrelated adapters. Transactional
creation across both records is outside this change.

## Prefix-Free FastAPI Router

`build_router()` will construct an `APIRouter` with no prefix. Every core and
plugin route will therefore be relative to the router:

```python
app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
```

`FastAuth.mount(app)` remains the high-level integration and will perform:

```python
app.include_router(auth.router, prefix=auth.options.app.base_path)
```

before installing the FastAuth exception handler, CSRF middleware, and security
headers. `FastAuth.as_asgi()` continues to use `mount()`, so its routes retain
the configured base path.

Route-sensitive internals must not derive relative endpoint identity by removing
`options.app.base_path` from the incoming URL. FastAPI clones routes when a
router is included, so the effective application path can differ from the
configured mount path. FastAuth routes will instead carry their original
relative path as route metadata. Rate limiting, plugin middleware matching,
endpoint inspection, and other path-sensitive behavior will consume this
metadata.

The OpenAPI reference endpoint will derive the schema URL from the active
request or its relative sibling route instead of concatenating
`options.app.base_path`. This keeps the documentation functional under any
consumer-selected prefix.

`auth.routes` and inspection output will describe relative FastAuth routes.
They cannot reliably report an application prefix selected later by
`include_router()`. Consumers that need an absolute route should combine the
relative path with the same prefix supplied to FastAPI.

## Bound Dependency Aliases

After `DependsManager` is initialized, `FastAuth` will attach:

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

These aliases contain the same bound dependency callables exposed through
`auth.depends`; they do not introduce a separate authentication path.

The intended usage requires `auth` to be a module-level binding when postponed
annotations are enabled:

```python
auth = FastAuth(...)

@app.get("/me")
async def get_me(user: auth.CurrentUser) -> UserView:
    return user
```

That constraint follows Python and FastAPI's resolution of string annotations.
The documented `Depends(auth.depends.user())` form remains available for local
or closure-scoped auth instances.

Only required-user and required-session aliases are included in this change.
Optional aliases can be added later if demonstrated by consumer demand.

## Errors and Security

`create_user` is not exposed as a new HTTP endpoint. Possession of the
initialized `FastAuth` object inside trusted server code is the authorization
boundary, matching the direct-call semantics that motivated the feature.

Input validation and duplicate errors use existing FastAuth exception types.
Plaintext passwords are accepted for ergonomic server usage but are immediately
validated and hashed; they are never stored or returned.

Router inclusion does not install application-wide middleware. Consumers using
`include_router()` directly are responsible for installing CSRF and security
header middleware if desired. `mount()` remains the explicit convenience method
that installs them.

## Testing

Focused tests will prove:

- `auth.api.create_user` persists a normalized user and credential account.
- The stored password is hashed and can authenticate through the normal
  sign-in flow.
- User before/after database hooks run and may transform the user.
- A `UserCreated` event is published.
- No session, refresh token, or verification email is created.
- Duplicate email and username failures use canonical errors.
- `auth.router` has no embedded prefix.
- Direct `include_router()` works with an arbitrary prefix and custom tags.
- `mount()` still uses `options.app.base_path` and installs its middleware.
- Rate limiting, plugin middleware matching, OpenAPI references, and inspection
  remain correct under a consumer-selected prefix.
- `auth.CurrentUser` and `auth.CurrentSession` resolve authenticated requests
  and return the canonical 401 response for anonymous requests.

The implementation will use test-driven development: each behavior will first
be represented by a focused failing test, followed by the smallest production
change that makes it pass.
