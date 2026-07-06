from __future__ import annotations

from fastauth.web.csrf import is_trusted_origin


def test_relative_path_allowed_when_flag_set() -> None:
    assert is_trusted_origin("/api/x", ["http://app.test"], allow_relative=True)


def test_relative_path_rejected_when_flag_unset() -> None:
    assert not is_trusted_origin("/api/x", ["http://app.test"], allow_relative=False)


def test_origin_matches_trusted() -> None:
    assert is_trusted_origin("http://app.test/api", ["http://app.test"], allow_relative=False)


def test_origin_mismatch_rejected() -> None:
    assert not is_trusted_origin("http://evil.test/x", ["http://app.test"], allow_relative=False)


def test_wildcard_origin_matches_subdomain() -> None:
    assert is_trusted_origin(
        "http://api.app.test/x",
        ["http://*.app.test"],
        allow_relative=False,
    )
