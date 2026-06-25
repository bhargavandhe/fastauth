# Plugins

A `Plugin` is the only sanctioned extension point in authkit. Subclass
`authkit.plugins.base.Plugin`, set the `id` class variable, and override only
the hooks you need:

```python
from typing import ClassVar
from collections.abc import Sequence
from authkit.plugins.base import EndpointSpec, Plugin

class HelloPlugin(Plugin):
    id: ClassVar[str] = "myapp-hello"

    def endpoints(self) -> Sequence[EndpointSpec]:
        return [EndpointSpec(method="GET", path="/hello", name="hello",
                              tags=["Hello"], handler=self.hello)]

    async def hello(self) -> dict[str, str]:
        return {"hello": "world"}

auth = AuthKit(config, adapter=adapter, plugins=[HelloPlugin()])
```

`PluginRegistry` validates ids and aggregates `endpoints()`,
`event_handlers()`, `trusted_origins()`, and `rate_limit_rules()` across the
installed plugins. Lifespan hooks (`lifespan_startup`, `lifespan_shutdown`)
run in registration order — see the JWT plugin for an example that
provisions the initial JWKS key inside `lifespan_startup`.

`EndpointSpec` is only an HTTP route descriptor: method, path, name, tags,
handler, and request/response models. It does not declare authentication or
rate-limit behavior. Plugin handlers should enforce authentication directly,
and plugins should contribute rate limits through `rate_limit_rules()`.
