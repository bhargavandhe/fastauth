# OpenAPI / Scalar

`OpenApiPlugin` mounts a Scalar UI page and serves the OpenAPI 3.1 JSON
document for the calling FastAPI app.

## Endpoints

- `GET /auth/reference` — HTML page that loads `@scalar/api-reference` from
  a CDN and points it at the OpenAPI JSON URL below.
- `GET /auth/openapi.json` — the OpenAPI 3.1 schema for the host app.

## Config

`OpenApiOptions` exposes the mount `path` (default `/reference`),
Scalar `theme`, an optional CSP `nonce`, the page `title`, and the
`openapi_version` literal (default `"3.1.0"`).

## Example

```python
from fastauth import FastAuth, FastAuthOptions
from fastauth.database import memory
from fastauth.plugins.openapi import OpenApiOptions
from fastauth.providers import email_password, openapi

auth = FastAuth(
    FastAuthOptions(
        secret_key="replace-me-with-your-application-secret",
        database=memory(),
        plugins=[
            email_password(),
            openapi(OpenApiOptions(path="/reference", theme="default")),
        ],
    )
)
```

The plugin also exposes `render_schema(app)` for offline generation — useful
for emitting `openapi.json` as part of a build pipeline.
