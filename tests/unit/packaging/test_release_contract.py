"""Release metadata and documentation regressions."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import fastauth

ROOT = Path(__file__).resolve().parents[3]


def test_release_version_and_pydantic_floor() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    assert project["version"] == fastauth.__version__ == "0.15.0"
    assert "pydantic[email]>=2.11,<3" in project["dependencies"]
    assert "typer>=0.17.5" in project["optional-dependencies"]["cli"]
    assert "joserfc>=1.5" in project["optional-dependencies"]["jwt"]


def test_hooks_documentation_executes_with_domain_metadata() -> None:
    from typing import Any

    from pydantic import SecretStr

    from fastauth import FastAuth, FastAuthOptions
    from fastauth.domain.enums import HookPhase
    from fastauth.domain.models import User
    from fastauth.runtime.hooks import HookContext

    page = (ROOT / "docs/concepts/hooks.md").read_text()
    snippet = re.findall(r"```python\n(.*?)```", page, re.DOTALL)[0]
    namespace: dict[str, Any] = {"auth": FastAuth(FastAuthOptions(secret_key=SecretStr("a" * 64)))}
    exec(compile(snippet, "docs/concepts/hooks.md", "exec"), namespace)
    import asyncio

    user = User(id="user-example", email="reader@example.com", metadata={"existing": True})
    context = HookContext(phase=HookPhase.BEFORE_CREATE, model_name="user", payload=user)
    updated = asyncio.run(namespace["stamp_signup_metadata"](context))
    assert updated.metadata == {"existing": True, "source": "marketing-landing"}
