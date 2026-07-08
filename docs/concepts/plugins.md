# Plugins

A `Plugin` is the only sanctioned extension point in fastauth. Subclass
`fastauth.plugins.base.Plugin`, set the `id` class variable, and override only
the hooks you need:

```python
from typing import ClassVar
from collections.abc import Sequence
from datetime import timedelta
from pydantic import SecretStr
from fastauth import FastAuth, FastAuthOptions
from fastauth.database import memory
from fastauth.domain.models import WireModel
from fastauth.plugins.base import Capability, EndpointSpec, Plugin
from fastauth import email_password

class HelloResponse(WireModel):
    message: str

class HelloPlugin(Plugin):
    id: ClassVar[str] = "myapp-hello"

    def capabilities(self) -> Sequence[Capability]:
        return [
            Capability(
                id="myapp.hello",
                description="Example hello-world extension.",
                plugin_id=self.id,
            )
        ]

    def endpoints(self) -> Sequence[EndpointSpec]:
        return [
            EndpointSpec.get(
                "/hello",
                name="hello",
                tags=["Hello"],
                handler=self.hello,
                response_model=HelloResponse,
            )
        ]

    async def hello(self) -> HelloResponse:
        return HelloResponse(message="world")

auth = FastAuth(
    FastAuthOptions(
        secret_key=SecretStr("replace-me-with-your-application-secret"),
        database=memory(),
    ),
    plugins=[email_password(), HelloPlugin()],
)
```

`PluginRegistry` validates ids and aggregates `endpoints()`,
`capabilities()`, `event_handlers()`, `trusted_origins()`, and
`rate_limit_rules()` across the installed plugins. Lifespan hooks
(`lifespan_startup`, `lifespan_shutdown`) start in registration order and shut
down in reverse order. If startup fails, already-started plugins are shut down
before the error is reported.

`EndpointSpec` is only an HTTP route descriptor: method, path, name, tags,
handler, and response model. Request bodies are inferred from handler type
annotations. It does not declare authentication or rate-limit behavior. Plugin
handlers should enforce authentication with
`self.require_session(request)`, and plugins should contribute rate limits
through `rate_limit_rules()`.

## Plugin SDK contract

A production plugin should declare every surface it contributes:

- `capabilities()` for discoverable runtime features.
- `endpoints()` for HTTP routes.
- `server_api_name()` and `server_api()` for typed server-side plugin APIs.
- `event_handlers()` or `bind(context).event_bus.subscribe(...)` for event
  subscribers.
- `rate_limit_rules()` for route-specific limits.
- `trusted_origins()` for callback origins that should pass CSRF origin checks.
- `lifespan_startup()` / `lifespan_shutdown()` for managed external resources.

Applications can inspect installed capabilities through `auth.capabilities`.
Prefer typed constants for first-party features:

```python
from fastauth import EMAIL_PASSWORD, USERNAME_SIGN_IN

if auth.capabilities.has(USERNAME_SIGN_IN):
    ...

auth.capabilities.require(EMAIL_PASSWORD)
```

`auth.plugin_info()` returns typed plugin metadata for diagnostics, generated
docs, and plugin conformance tests. Endpoint metadata is exposed as
`EndpointInfo`, a serializable DTO containing method, path, name, tags, and
model names. It does not expose live handler callables.

Plugin surfaces are snapshotted when `FastAuth` builds its `PluginRegistry`.
Do not make `endpoints()`, `capabilities()`, or related declaration hooks
depend on mutable runtime state after construction.

Plugin server APIs are exposed under `auth.api.plugins` by name and by plugin
id:

```python
api = auth.api.plugins.by_name["my_plugin"]
same_api = auth.api.plugins.by_plugin_id["myapp-plugin"]
```

This keeps core `auth.api.sign_in`, `auth.api.session`, `auth.api.password`,
and `auth.api.user` stable while letting plugins publish their own command /
result based server API.

## Authoring template

Use this shape for plugins that need fastauth context, authentication, optional
storage capabilities, and route-specific rate limits:

```python
from collections.abc import Sequence
from typing import ClassVar

from fastapi import Request
from fastauth.domain.models import WireModel
from fastauth.plugins.base import Capability, EndpointSpec, Plugin, RateLimitRule
from fastauth.runtime.context import AuthContext
from fastauth.storage.base import AuditLogStore


class MyPluginResponse(WireModel):
    user_id: str


class MyPluginServerApi:
    async def ping(self) -> MyPluginResponse:
        return MyPluginResponse(user_id="system")


class MyPlugin(Plugin):
    id: ClassVar[str] = "myapp-plugin"

    def __init__(self) -> None:
        self.audit_logs: AuditLogStore | None = None

    def capabilities(self) -> Sequence[Capability]:
        return [
            Capability(
                id="myapp.plugin",
                description="Example authenticated plugin capability.",
                plugin_id=self.id,
            )
        ]

    def server_api_name(self) -> str:
        return "my_plugin"

    def server_api(self) -> object:
        return MyPluginServerApi()

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
