# CSRF / trusted origins

`CsrfMiddleware` blocks cross-origin state-changing requests by validating the
`Origin` header (falling back to `Referer`) against
`CsrfConfig.trusted_origins`. `GET`, `HEAD`, and `OPTIONS` are bypassed, and
Bearer-only requests are bypassed too — a request that does not carry the
session cookie cannot be a CSRF target by definition.

```python
from authkit.web.csrf import CsrfMiddleware

app.add_middleware(
    CsrfMiddleware,
    config=config.csrf,
    additional_trusted_origins=auth.context.plugins.all_trusted_origins(),
    cookie_name=config.cookie.name,
)
```

Trusted-origin patterns support a leading `*.` wildcard
(`https://*.app.test`) and can include relative paths when
`csrf.allow_relative_paths` is enabled (default). `auth.install(app)` and
`AuthKit.as_asgi()` install the middleware automatically. If you need
lower-level control, call `authkit.web.fastapi.install_csrf(app, auth.context)`
directly.
