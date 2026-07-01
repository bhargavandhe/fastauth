"""fastauth — a modular FastAPI authentication library."""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastauth.options import FastAuthOptions

if TYPE_CHECKING:
    from fastauth.messaging.email import EmailSender
    from fastauth.runtime.auth import FastAuth
    from fastauth.security.passwords import PasswordHasher
    from fastauth.security.sessions import SessionStrategy
    from fastauth.security.tokens import TokenService

__all__ = ["FastAuthOptions", "__version__", "fastauth"]
__version__ = "0.3.0"


def fastauth(
    options: FastAuthOptions,
    *,
    email_sender: EmailSender | None = None,
    password_hasher: PasswordHasher | None = None,
    session_strategy: SessionStrategy | None = None,
    token_service: TokenService | None = None,
) -> FastAuth:
    """Create a FastAuth runtime from validated Pydantic options."""
    from fastauth.runtime.auth import FastAuth

    return FastAuth(
        options,
        email_sender=email_sender,
        password_hasher=password_hasher,
        session_strategy=session_strategy,
        token_service=token_service,
    )
