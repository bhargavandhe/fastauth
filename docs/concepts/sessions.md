# Sessions

`SessionStrategy` is a Protocol implemented by `DatabaseSessionStrategy`
(the default) and `JwtSessionStrategy` (selected via the `JwtPlugin`). A
strategy owns the `create`, `read`, `revoke`, `revoke_all`, and `rotate`
operations on a session token. Endpoints obtain the current user by calling
`context.session_strategy.read(token)`.

```python
from fastauth.security.sessions import DatabaseSessionStrategy

session = await context.session_strategy.create(
    user,
    ip="203.0.113.4",
    user_agent="curl/8.6.0",
)
print(session.token)            # opaque token, set as a signed cookie
print(session.session.id)        # row id in the sessions collection
```

Cookie packaging uses an `itsdangerous`-signed envelope so that tokens are
tamper-evident at the transport boundary. Cookie attributes
(`secure`, `same_site`, `http_only`, …) come from `CookieOptions`.

Database-backed sessions expire on the server and can be revoked individually
(`sign-out`) or wholesale (`revoke_all` on password reset). `SessionOptions`
also supports `idle_timeout`, which expires a session after a period without
authenticated reads.
