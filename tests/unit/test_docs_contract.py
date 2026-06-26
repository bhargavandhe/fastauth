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
    for path in project_files("src/fastauth", "examples"):
        if path.suffix not in {".py", ".md"}:
            continue
        text = path.read_text(encoding="utf-8")
        for pattern in forbidden:
            if pattern in text:
                offenders.append(f"{path.relative_to(ROOT)} contains {pattern}")
    assert not offenders, "Process-environment access found:\n" + "\n".join(offenders)


def test_user_facing_docs_do_not_teach_env_var_config() -> None:
    forbidden = ("os.environ", "os.getenv", "export FASTAUTH_", "FASTAUTH_*")
    offenders: list[str] = []
    for path in project_files("README.md", "docs"):
        if "docs/superpowers" in path.as_posix() or path.suffix != ".md":
            continue
        text = path.read_text(encoding="utf-8")
        for pattern in forbidden:
            if pattern in text:
                offenders.append(f"{path.relative_to(ROOT)} contains {pattern}")
    assert not offenders, "Env-var config guidance found:\n" + "\n".join(offenders)


def test_historical_docs_do_not_reintroduce_stale_config_guidance() -> None:
    forbidden = (
        "fastauth init` — scaffolds an `auth.py` that reads from `os.environ`",
        "Configuration:** all environment-driven configuration goes through",
        "FastAuthConfig()  # reads FASTAUTH_* from env",
        "export FASTAUTH_",
    )
    offenders: list[str] = []
    for path in project_files("CHANGELOG.md", "docs"):
        if path.suffix != ".md":
            continue
        text = path.read_text(encoding="utf-8")
        for pattern in forbidden:
            if pattern in text:
                offenders.append(f"{path.relative_to(ROOT)} contains {pattern}")
    assert not offenders, "Stale env-based guidance found:\n" + "\n".join(offenders)


def test_installation_docs_describe_explicit_config_construction() -> None:
    text = read_project_file("docs/installation.md")

    assert (
        "Configuration is loaded from environment variables prefixed with `FASTAUTH_`"
        not in text
    )
    assert "fastauth never reads environment" in text
    assert "variables directly" in text


def test_user_facing_docs_do_not_reference_removed_database_config_fields() -> None:
    forbidden = (
        "config.database.mongo_url",
        "config.database.database_name",
        "DatabaseConfig(mongo_url",
        "mongo_url=",
    )
    offenders: list[str] = []
    for path in project_files("README.md", "docs"):
        if "docs/superpowers" in path.as_posix() or path.suffix != ".md":
            continue
        text = path.read_text(encoding="utf-8")
        for pattern in forbidden:
            if pattern in text:
                offenders.append(f"{path.relative_to(ROOT)} contains {pattern}")
    assert not offenders, "Removed DatabaseConfig fields found:\n" + "\n".join(offenders)


def test_postgres_docs_describe_tracked_migrations() -> None:
    adapters = read_project_file("docs/concepts/adapters.md")
    deploying = read_project_file("docs/guides/deploying.md")

    assert "schema_migrations" in adapters
    assert "adapter.checked_lifespan(auth)" in adapters
    assert "tracked schema migrations" in deploying


def test_installation_docs_match_fastauth_init_output() -> None:
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


def test_release_metadata_is_project_specific() -> None:
    pyproject = read_project_file("pyproject.toml")
    mkdocs = read_project_file("mkdocs.yml")

    assert "github.com/fastauth/fastauth" not in pyproject
    assert "github.com/your-org/fastauth" not in mkdocs
    assert '"postgres"' in pyproject
    assert '"sqlalchemy"' in pyproject


def test_release_metadata_does_not_advertise_unimplemented_redis_extra() -> None:
    pyproject = read_project_file("pyproject.toml")
    readme = read_project_file("README.md")

    assert "redis =" not in pyproject
    assert "redis>=" not in pyproject
    assert "redis" not in readme.lower()


def test_readme_no_longer_calls_docs_under_construction() -> None:
    text = read_project_file("README.md")

    assert "under construction" not in text


def test_ci_checks_supported_python_and_package_build() -> None:
    workflow = read_project_file(".github/workflows/ci.yml")

    assert "python-version: [\"3.11\", \"3.12\"]" in workflow
    assert "uv build" in workflow
    assert "twine check" in workflow
