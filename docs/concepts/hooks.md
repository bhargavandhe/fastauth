# Hooks

`DatabaseHooks` lets you mutate or observe payloads as they flow through the
core mutation paths. Each hook is registered against a `(HookPhase, model_name)`
pair and receives a `HookContext` describing the call.

```python
from typing import cast

from fastauth.domain.enums import HookPhase
from fastauth.domain.models import User
from fastauth.runtime.hooks import HookContext

@auth.hook(HookPhase.BEFORE_CREATE, target="user")
async def stamp_signup_metadata(context: HookContext) -> User:
    user = cast(User, context.payload)
    return user.model_copy(
        update={
            "metadata": {
                **user.metadata.root,
                "source": "marketing-landing",
            }
        },
    )
```

`before_*` handlers may return a replacement payload; `after_*` handlers run
purely for their side effects. The handler list is iterated in registration
order, so the result of an earlier hook is visible to the next.

The decorator returns the original function and can also be applied
imperatively:

```python
auth.hook(HookPhase.AFTER_CREATE, target="user")(record_created_user)
```

Hook exceptions propagate to the mutation flow. Targets are matched exactly,
so use the lowercase model names used by FastAuth flows, such as `"user"`.
