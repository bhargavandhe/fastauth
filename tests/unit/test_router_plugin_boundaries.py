from __future__ import annotations

from pathlib import Path


def test_fastapi_router_does_not_import_concrete_plugins() -> None:
    source = Path("src/fastauth/web/fastapi.py").read_text()

    assert "fastauth.plugins.jwt" not in source
    assert "JwtPlugin" not in source
