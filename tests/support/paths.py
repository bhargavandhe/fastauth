"""Path helpers for tests that need repository-relative files."""

from __future__ import annotations

from pathlib import Path


def find_project_root(start: Path | None = None) -> Path:
    current = start or Path(__file__).resolve()
    for path in (current, *current.parents):
        if (path / "pyproject.toml").is_file() and (path / "src" / "fastauth").is_dir():
            return path
    raise RuntimeError("Could not locate project root")


PROJECT_ROOT = find_project_root()
