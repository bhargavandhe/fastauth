"""Shared pytest fixtures for the fastauth test suite."""

from __future__ import annotations

import pytest


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        path = item.path.as_posix()
        if "/tests/unit/" in path:
            item.add_marker(pytest.mark.unit)
        elif "/tests/integration/" in path:
            item.add_marker(pytest.mark.integration)
        elif "/tests/cli/" in path:
            item.add_marker(pytest.mark.cli)
        elif "/tests/adapters/" in path:
            item.add_marker(pytest.mark.adapter)
            if path.endswith(("test_beanie_adapter.py", "test_postgres_adapter.py")):
                item.add_marker(pytest.mark.docker)
