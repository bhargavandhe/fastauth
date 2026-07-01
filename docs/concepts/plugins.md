# Plugins

A `Plugin` is the only sanctioned extension point in fastauth. Subclass
`fastauth.plugins.base.Plugin`, set the `id` class variable, and override only
the hooks you need:

```python
from typing import ClassVar
from collections.abc import Sequence
from datetime import timedelta
from fastauth import FastAuth, FastAuthOptions
from fastauth.database import memory
from fastauth.plugins.base import EndpointSpec, Plugin
from fastauth.providers import email_password

class HelloPlugin(Plugin):
    id: ClassVar[str] = "myapp-hello"

    def endpoints(self) -> Sequence[EndpointSpec]:
        return [
            EndpointSpec.get(
                "/hello",
                name="hello",
                tags=["Hello"],
                handler=self.hello,
            )
        ]

    async def hello(self) -> dict[str, str]:
        return {"hello": "world"}

auth = FastAuth(
    FastAuthOptions(
        secret_key="replace-me-with-your-application-secret",
        database=memory(),
        plugins=[email_password(), HelloPlugin()],
    )
)
```

`PluginRegistry` validates ids and aggregates `endpoints()`,
`event_handlers()`, `trusted_origins()`, and `rate_limit_rules()` across the
installed plugins. Lifespan hooks (`lifespan_startup`, `lifespan_shutdown`)
run in registration order — see the JWT plugin for an example that
provisions the initial JWKS key inside `lifespan_startup`.

`EndpointSpec` is only an HTTP route descriptor: method, path, name, tags,
handler, and request/response models. It does not declare authentication or
rate-limit behavior. Plugin handlers should enforce authentication with
`self.require_session(request)`, and plugins should contribute rate limits
through `rate_limit_rules()`.

## Authoring template

Use this shape for plugins that need fastauth context, authentication, optional
storage capabilities, and route-specific rate limits:

```python
from collections.abc import Sequence
from typing import ClassVar

from fastapi import Request
from pydantic import BaseModel

from fastauth.domain.models import WireModel
from fastauth.plugins.base import EndpointSpec, Plugin, RateLimitRule
from fastauth.runtime.context import AuthContext
from fastauth.storage.base import AuditLogStore


class MyPluginResponse(WireModel):
    user_id: str


class MyPlugin(Plugin):
    id: ClassVar[str] = "myapp-plugin"

    def __init__(self) -> None:
        self.audit_logs: AuditLogStore | None = None

    def bind(self, context: AuthContext) -> None:
        super().bind(context)
        self.audit_logs = self.require_capability(AuditLogStore)

    def endpoints(self) -> Sequence[EndpointSpec]:
        return [
            EndpointSpec.get(
                "/my-plugin/me",
                name="my_plugin_me",
                tags=["MyPlugin"],
                handler=self.me_handler,
                response_model=MyPluginResponse,
            )
        ]

    def rate_limit_rules(self) -> Sequence[RateLimitRule]:
        return [
            RateLimitRule(
                path="/my-plugin/me",
                window=timedelta(seconds=60),
                max_requests=30,
            )
        ]

    async def me_handler(self, request: Request) -> MyPluginResponse:
        session = await self.require_session(request)
        return MyPluginResponse(user_id=session.user.id)
```

The important rules are:

- Use `bind(context)` plus `super().bind(context)` for startup validation and
  for storing `AuthContext`.
- Use `self.require_capability(SomeStoreProtocol)` before enabling a plugin
  that needs optional storage.
- Authenticate in the handler with `await self.require_session(request)`.
- Add route-specific limits with `rate_limit_rules()` rather than extra fields
  on `EndpointSpec`.
