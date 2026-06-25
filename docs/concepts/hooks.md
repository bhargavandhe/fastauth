# Hooks

`DatabaseHooks` lets you mutate or observe payloads as they flow through the
core mutation paths. Each hook is registered against a `(HookPhase, model_name)`
pair and receives a `HookContext` describing the call.

```python
from authkit.domain.enums import HookPhase
from authkit.runtime.hooks import HookContext

async def stamp_signup_metadata(ctx: HookContext) -> object:
    user = ctx.payload
    user.metadata = {**user.metadata, "source": "marketing-landing"}
    return user

auth.context.hooks.register(HookPhase.BEFORE_CREATE, "User", stamp_signup_metadata)
```

`before_*` handlers may return a replacement payload; `after_*` handlers run
purely for their side effects. The handler list is iterated in registration
order, so the result of an earlier hook is visible to the next.
