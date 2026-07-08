"""Client-facing route constants for FastAuth-managed routes."""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "AuthRoutes",
    "RouteRef",
    "SessionRoutes",
    "SignInRoutes",
    "SignUpRoutes",
]


@dataclass(frozen=True)
class RouteRef:
    method: str
    path: str
    name: str


@dataclass(frozen=True)
class SignUpRoutes:
    email: RouteRef


@dataclass(frozen=True)
class SignInRoutes:
    email: RouteRef
    username: RouteRef


@dataclass(frozen=True)
class SessionRoutes:
    refresh: RouteRef
    get: RouteRef
    list: RouteRef
    revoke: RouteRef
    revoke_other: RouteRef
    sign_out: RouteRef


@dataclass(frozen=True)
class AuthRoutes:
    """Client-facing constants for first-party route paths."""

    sign_up: SignUpRoutes
    sign_in: SignInRoutes
    sessions: SessionRoutes

    @classmethod
    def from_base_path(cls, base_path: str) -> AuthRoutes:
        def ref(method: str, path: str, name: str) -> RouteRef:
            return RouteRef(method=method, path=f"{base_path}{path}", name=name)

        return cls(
            sign_up=SignUpRoutes(
                email=ref("POST", "/sign-up/email", "sign_up_email"),
            ),
            sign_in=SignInRoutes(
                email=ref("POST", "/sign-in/email", "sign_in_email"),
                username=ref("POST", "/sign-in/username", "sign_in_username"),
            ),
            sessions=SessionRoutes(
                refresh=ref("POST", "/refresh", "refresh_session"),
                get=ref("GET", "/get-session", "get_session"),
                list=ref("GET", "/sessions", "list_sessions"),
                revoke=ref("DELETE", "/sessions/{session_id}", "revoke_session"),
                revoke_other=ref("DELETE", "/sessions", "revoke_other_sessions"),
                sign_out=ref("POST", "/sign-out", "sign_out"),
            ),
        )
