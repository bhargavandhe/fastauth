# Server API

`auth.api` is the typed server-side API for application code that wants to run
FastAuth flows without going through HTTP. Commands are frozen Pydantic models
and must use explicit principal objects.

```python
from fastauth.api import UpdateUserCommand, UserPrincipal

result = await auth.api.user.update(
    UpdateUserCommand(
        principal=UserPrincipal(user_id=user_id),
        name="Ada Lovelace",
    )
)
```

Use `UserPrincipal` for user-scoped operations and `SessionPrincipal` for
operations that need a specific session, such as changing a password while
preserving the current session.

```python
from pydantic import SecretStr
from fastauth.api import ChangePasswordCommand, SessionPrincipal

await auth.api.password.change(
    ChangePasswordCommand(
        principal=SessionPrincipal(
            user_id=user_id,
            session_id=session_id,
        ),
        current_password=SecretStr("old-password"),
        new_password=SecretStr("new-password"),
    )
)
```

A `SessionPrincipal` is a trusted application reference. FastAuth verifies that
the session id belongs to the user, but the principal is not proof that the
caller is currently authenticated or that idle-timeout freshness was checked in
the same request. Use FastAPI dependencies such as `auth.require_session` when
you need request-time authentication proof.

The deprecated `fastauth.api.legacy` `user=` command models were removed in
`0.8.0`. Applications must construct commands with `UserPrincipal` or
`SessionPrincipal`.
