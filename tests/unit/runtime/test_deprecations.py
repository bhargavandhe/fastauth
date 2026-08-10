from __future__ import annotations

import pytest

from fastauth.deprecations import FastAuthDeprecationWarning, warn_deprecated


def test_warn_deprecated_uses_public_warning_and_actionable_message() -> None:
    with pytest.warns(FastAuthDeprecationWarning) as captured:
        warn_deprecated(
            "auth.old_api",
            replacement="auth.api",
            removal="0.16.0",
        )

    message = str(captured[0].message)
    assert "auth.old_api" in message
    assert "auth.api" in message
    assert "0.16.0" in message
