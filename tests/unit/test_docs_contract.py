"""Contract tests for high-risk documentation claims."""

from __future__ import annotations

import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]


def read_project_file(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def project_files(*roots: str) -> list[pathlib.Path]:
    files: list[pathlib.Path] = []
    for root in roots:
        base = ROOT / root
        if base.is_file():
            files.append(base)
        else:
            files.extend(path for path in base.rglob("*") if path.is_file())
    return files


def test_runtime_and_examples_do_not_read_process_environment() -> None:
    forbidden = ("os.environ", "os.getenv", "getenv(", "environ[")
    offenders: list[str] = []
    for path in project_files("src/authkit", "examples"):
        if path.suffix not in {".py", ".md"}:
            continue
        text = path.read_text(encoding="utf-8")
        for pattern in forbidden:
            if pattern in text:
                offenders.append(f"{path.relative_to(ROOT)} contains {pattern}")
    assert not offenders, "Process-environment access found:\n" + "\n".join(offenders)


def test_user_facing_docs_do_not_teach_env_var_config() -> None:
    forbidden = ("os.environ", "os.getenv", "export AUTHKIT_", "AUTHKIT_*")
    offenders: list[str] = []
    for path in project_files("README.md", "docs"):
        if "docs/superpowers" in path.as_posix() or path.suffix != ".md":
            continue
        text = path.read_text(encoding="utf-8")
        for pattern in forbidden:
            if pattern in text:
                offenders.append(f"{path.relative_to(ROOT)} contains {pattern}")
    assert not offenders, "Env-var config guidance found:\n" + "\n".join(offenders)


def test_installation_docs_describe_explicit_config_construction() -> None:
    text = read_project_file("docs/installation.md")

    assert "Configuration is loaded from environment variables prefixed with `AUTHKIT_`" not in text
    assert "authkit never reads environment" in text
    assert "variables directly" in text


def test_installation_docs_match_authkit_init_output() -> None:
    text = read_project_file("docs/installation.md")

    assert "writes .env.example and auth.py" not in text
    assert "writes auth.py" in text


def test_readme_quickstart_uses_auth_install() -> None:
    text = read_project_file("README.md")

    assert "auth.install(app)" in text
    assert (
        "with CSRF, rate-limiting, account-lockout, refresh\n"
        "tokens, and security headers all on by default."
    ) not in text
