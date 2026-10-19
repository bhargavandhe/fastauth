"""The publisher must fail closed before issuing any PyPI or GitHub writes."""

from __future__ import annotations

import importlib.util
import sys
from email.message import Message
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[3]
SHA = "a" * 40
OTHER = "b" * 40
REPO = "bhargavandhe/fastauth"


@pytest.fixture
def release() -> Any:
    path = ROOT / ".github/scripts/release.py"
    assert path.is_file(), "Automatic release policy is not implemented"
    spec = importlib.util.spec_from_file_location("release_policy", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def run_data(**changes: Any) -> dict[str, Any]:
    value = {
        "id": 10,
        "run_attempt": 1,
        "name": "CI",
        "path": ".github/workflows/ci.yml",
        "event": "push",
        "head_branch": "main",
        "head_sha": SHA,
        "status": "completed",
        "conclusion": "success",
        "repository": {"full_name": REPO},
        "head_repository": {"full_name": REPO},
    }
    value.update(changes)
    return value


def test_gate_accepts_exact_successful_main_push(release: Any) -> None:
    run = release.WorkflowRun.model_validate(run_data())
    assert release.qualifies(run, REPO, SHA, "ci.yml")


@pytest.mark.parametrize(
    "changes",
    [
        {"event": "pull_request"},
        {"event": "workflow_dispatch"},
        {"event": "schedule"},
        {"head_branch": "feature"},
        {"head_sha": OTHER},
        {"status": "in_progress"},
        {"conclusion": "failure"},
        {"conclusion": "cancelled"},
        {"conclusion": "skipped"},
        {"head_repository": {"full_name": "attacker/fastauth"}},
        {"head_repository": None},
        {"repository": {"full_name": "attacker/fastauth"}},
        {"path": ".github/workflows/unrelated.yml"},
    ],
)
def test_gate_rejects_untrusted_or_unsuccessful_run(release: Any, changes: Any) -> None:
    run = release.WorkflowRun.model_validate(run_data(**changes))
    assert not release.qualifies(run, REPO, SHA, "ci.yml")


def test_latest_failed_or_pending_run_overrides_old_success(release: Any) -> None:
    old = release.WorkflowRun.model_validate(run_data())
    latest = release.WorkflowRun.model_validate(
        run_data(id=11, status="in_progress", conclusion=None)
    )
    assert not release.latest_success([old, latest], REPO, SHA, "ci.yml")
    assert not release.latest_success([], REPO, SHA, "ci.yml")
    rerun = release.WorkflowRun.model_validate(run_data(run_attempt=2, conclusion="failure"))
    assert not release.latest_success([old, rerun], REPO, SHA, "ci.yml")


def test_runtime_package_and_tag_versions_must_match(release: Any) -> None:
    assert release.validate_version("0.15.0", "0.15.0", "v0.15.0") == "0.15.0"
    for package, runtime, tag in [
        ("0.15.0", "0.14.0", None),
        ("0.15.0", "0.15.0", "v0.14.0"),
        ("0.15.0+local", "0.15.0+local", None),
        ("garbage", "garbage", None),
    ]:
        with pytest.raises(ValueError):
            release.validate_version(package, runtime, tag)


def state(release: Any, **changes: Any) -> Any:
    value = {
        "version": "0.15.0",
        "sha": SHA,
        "published": {},
        "published_versions": ["0.14.0"],
        "local": {
            "fastauth_py-0.15.0.tar.gz": "1" * 64,
            "fastauth_py-0.15.0-py3-none-any.whl": "2" * 64,
        },
        "tag_sha": None,
        "release_assets": None,
    }
    value.update(changes)
    return release.ReleaseState.model_validate(value)


def test_new_version_can_publish_and_existing_matching_tag_is_supported(release: Any) -> None:
    assert release.decide(state(release)) == "publish"
    assert release.decide(state(release, tag_sha=SHA)) == "publish"


@pytest.mark.parametrize("versions", [["0.16.0"], ["0.15.0"], ["0.15.1rc1"]])
def test_new_version_must_increase_monotonically(release: Any, versions: list[str]) -> None:
    with pytest.raises(ValueError, match="newer"):
        release.decide(state(release, published_versions=versions))


def test_partial_pypi_upload_fails_closed(release: Any) -> None:
    data = state(release)
    data.published = {next(iter(data.local)): "1" * 64}
    with pytest.raises(ValueError, match=r"partial|incomplete"):
        release.decide(data)


def test_pypi_content_conflict_fails_closed(release: Any) -> None:
    data = state(release)
    data.published = dict.fromkeys(data.local, "9" * 64)
    with pytest.raises(ValueError, match="digest"):
        release.decide(data)


def test_retry_repairs_release_only_for_exact_published_artifacts(release: Any) -> None:
    data = state(release)
    data.published = data.local.copy()
    assert release.decide(data) == "release"
    data.tag_sha = SHA
    assert release.decide(data) == "release"
    data.release_assets = {next(iter(data.local)): "1" * 64}
    assert release.decide(data) == "release"


def test_completed_release_is_noop_even_after_main_advances(release: Any) -> None:
    data = state(release)
    data.published = dict.fromkeys(data.local, "9" * 64)
    data.release_assets = data.published.copy()
    data.tag_sha = OTHER
    assert release.decide(data) == "skip"


def test_conflicting_tag_or_release_never_publishes(release: Any) -> None:
    with pytest.raises(ValueError, match="tag"):
        release.decide(state(release, tag_sha=OTHER))
    with pytest.raises(ValueError, match="release"):
        release.decide(state(release, release_assets={}))
    data = state(release)
    data.tag_sha = OTHER
    data.published = data.local.copy()
    with pytest.raises(ValueError, match="tag"):
        release.decide(data)


def test_conflicting_github_asset_fails_closed(release: Any) -> None:
    data = state(release)
    data.published = data.local.copy()
    data.tag_sha = SHA
    data.release_assets = dict.fromkeys(data.local, "9" * 64)
    with pytest.raises(ValueError, match="asset"):
        release.decide(data)


def test_workflow_preserves_identity_and_separates_publishing() -> None:
    workflow = (ROOT / ".github/workflows/publish.yml").read_text()
    assert "workflow_run:" in workflow
    assert 'workflows: ["CI", "Security"]' in workflow
    assert 'tags:\n      - "v*"' in workflow
    assert "group: publish-fastauth-py" in workflow
    assert "cancel-in-progress: false" in workflow
    assert "name: pypi" in workflow
    assert "id-token: write" in workflow
    assert "actions: read" in workflow
    assert "needs.gate.outputs.sha" in workflow
    assert "skip-existing" not in workflow
    assert "release.py gate" in workflow
    assert "release.py check" in workflow
    assert "release.py finish" in workflow
    assert "--verify-tag" not in workflow


def test_ready_checks_both_workflow_files_at_exact_sha(
    release: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths: list[str] = []

    def api(path: str, model: Any) -> Any:
        paths.append(path)
        if path == "commits/main":
            return model(sha=SHA)
        security = "security.yml" in path
        run = run_data(
            name="Security" if security else "CI",
            path=f".github/workflows/{'security' if security else 'ci'}.yml",
        )
        return model(total_count=1, workflow_runs=[run])

    monkeypatch.setattr(release, "github", api)
    assert release.ready(SHA)
    assert len(paths) == 3
    for path in paths[1:]:
        assert f"branch=main&event=push&head_sha={SHA}" in path
    assert any("ci.yml" in path for path in paths)
    assert any("security.yml" in path for path in paths)


def test_ready_rejects_stale_main_and_incomplete_api_response(
    release: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    def stale_main(path: str, model: Any) -> Any:
        return model(sha=OTHER)

    monkeypatch.setattr(release, "github", stale_main)
    assert not release.ready(SHA)

    def api(path: str, model: Any) -> Any:
        if path == "commits/main":
            return model(sha=SHA)
        return model(total_count=101, workflow_runs=[run_data()])

    monkeypatch.setattr(release, "github", api)
    with pytest.raises(ValueError, match="incomplete"):
        release.ready(SHA)


def test_event_gate_never_promotes_a_fork(
    release: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import json

    path = tmp_path / "event.json"
    path.write_text(
        json.dumps(
            {
                "repository": {"full_name": REPO},
                "workflow_run": run_data(head_repository={"full_name": "attacker/fork"}),
            }
        )
    )
    output = tmp_path / "output"
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(path))
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setenv("GITHUB_REPOSITORY", REPO)
    monkeypatch.setenv("GITHUB_EVENT_NAME", "workflow_run")
    release.gate()
    assert output.read_text() == "ready=false\n"


def test_gate_uses_trigger_sha_instead_of_workflow_context_sha(
    release: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import json

    path = tmp_path / "event.json"
    path.write_text(json.dumps({"repository": {"full_name": REPO}, "workflow_run": run_data()}))
    output = tmp_path / "output"
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(path))
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setenv("GITHUB_REPOSITORY", REPO)
    monkeypatch.setenv("GITHUB_EVENT_NAME", "workflow_run")
    monkeypatch.setenv("GITHUB_SHA", OTHER)

    def ready(sha: str) -> bool:
        return sha == SHA

    monkeypatch.setattr(release, "ready", ready)
    release.gate()
    assert output.read_text() == f"sha={SHA}\nready=true\n"


def test_tag_entry_point_resolves_tag_before_requiring_main_checks(
    release: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import json

    path = tmp_path / "event.json"
    path.write_text(json.dumps({"repository": {"full_name": REPO}, "ref": "refs/tags/v0.15.0"}))
    output = tmp_path / "output"
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(path))
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setenv("GITHUB_REPOSITORY", REPO)
    monkeypatch.setenv("GITHUB_EVENT_NAME", "push")

    def tag_commit(tag: str) -> str | None:
        return SHA if tag == "v0.15.0" else None

    def not_ready(sha: str) -> bool:
        return False

    monkeypatch.setattr(release, "tag_commit", tag_commit)
    monkeypatch.setattr(release, "ready", not_ready)
    release.gate()
    assert output.read_text() == f"sha={SHA}\nready=false\n"


def test_finish_writes_nothing_before_pypi_verification(
    release: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = state(release)
    data.published = dict.fromkeys(data.local, "9" * 64)

    def inspect(version: str, sha: str) -> Any:
        return data

    monkeypatch.setattr(release, "inspect", inspect)
    calls: list[Any] = []

    def forbidden(*args: Any, **kwargs: Any) -> None:
        calls.append(args)

    monkeypatch.setattr(release.subprocess, "run", forbidden)
    with pytest.raises(ValueError, match="digest"):
        release.finish("0.15.0", SHA)
    assert calls == []


def test_finish_creates_tag_then_release_and_only_missing_assets(
    release: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    data = state(release)
    data.published = data.local.copy()
    monkeypatch.setattr(release, "ROOT", tmp_path)

    def inspect(version: str, sha: str) -> Any:
        return data

    monkeypatch.setattr(release, "inspect", inspect)

    def tag_commit(tag: str) -> str | None:
        return data.tag_sha

    monkeypatch.setattr(release, "tag_commit", tag_commit)
    calls: list[list[str]] = []

    def command(args: list[str], **kwargs: Any) -> None:
        calls.append(args)
        if args[1] == "api":
            assert args[-1] == f"sha={SHA}"
            data.tag_sha = SHA
        elif args[1:3] == ["release", "create"]:
            assert "--verify-tag" in args
            data.release_assets = {}
        elif args[1:3] == ["release", "upload"]:
            name = Path(args[4]).name
            data.release_assets[name] = data.local[name]
        else:
            raise AssertionError(args)

    monkeypatch.setattr(release.subprocess, "run", command)
    release.finish("0.15.0", SHA)
    assert [call[1:3] for call in calls] == [
        ["api", f"repos/{REPO}/git/refs"],
        ["release", "create"],
        ["release", "upload"],
        ["release", "upload"],
    ]
    release.finish("0.15.0", SHA)
    assert len(calls) == 4


def test_missing_pypi_read_never_becomes_permission_to_publish(
    release: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from urllib.error import HTTPError

    def fail(request: Any, **kwargs: Any) -> None:
        raise HTTPError(request.full_url, 404, "missing", Message(), None)

    monkeypatch.setattr(release, "urlopen", fail)
    with pytest.raises(HTTPError):
        release.read_model("https://pypi.org/pypi/fastauth-py/json", release.PyPI)


def test_concurrency_does_not_drop_a_queued_release() -> None:
    workflow = (ROOT / ".github/workflows/publish.yml").read_text()
    assert "  queue: max\n" in workflow
    assert "cancel-in-progress: false" in workflow


@pytest.mark.parametrize(
    "scenario",
    [
        "success",
        "stale-main",
        "pending-ci",
        "failed-rerun",
        "failed-security",
        "fork",
        "wrong-sha",
        "wrong-branch",
        "wrong-event",
        "wrong-workflow",
        "truncated",
        "pypi-unavailable",
        "pypi-changed",
        "pypi-published",
        "same-tag",
        "annotated-tag",
        "tag-api-failure",
        "conflicting-tag",
        "release-exists",
    ],
)
def test_actual_prepublish_script_rechecks_state(scenario: str) -> None:
    """Execute the actual workflow JavaScript with only external APIs substituted."""
    import hashlib
    import json
    import re
    import shutil
    import subprocess
    import textwrap

    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required to exercise GitHub Actions' JavaScript runtime")
    workflow = (ROOT / ".github/workflows/publish.yml").read_text()
    match = re.search(r"          script: \|\n(.*?)(?=      - name: Publish)", workflow, re.DOTALL)
    assert match is not None
    script = textwrap.dedent(match[1])
    ci = run_data()
    security = run_data(name="Security", path=".github/workflows/security.yml")
    runs = {"ci.yml": [ci], "security.yml": [security]}
    versions: dict[str, Any] = {"0.14.0": []}
    main = SHA
    if scenario == "stale-main":
        main = OTHER
    elif scenario == "pending-ci":
        runs["ci.yml"].append(run_data(id=11, status="in_progress", conclusion=None))
    elif scenario == "failed-rerun":
        runs["ci.yml"].append(run_data(run_attempt=2, conclusion="failure"))
    elif scenario == "failed-security":
        security["conclusion"] = "failure"
    elif scenario == "fork":
        ci["head_repository"] = {"full_name": "attacker/fork"}
    elif scenario == "wrong-sha":
        ci["head_sha"] = OTHER
    elif scenario == "wrong-branch":
        ci["head_branch"] = "feature"
    elif scenario == "wrong-event":
        ci["event"] = "schedule"
    elif scenario == "wrong-workflow":
        ci["path"] = ".github/workflows/unrelated.yml"
    elif scenario == "pypi-changed":
        versions["0.16.0"] = []
    elif scenario == "pypi-published":
        versions["0.15.0"] = [{"filename": "already-uploaded.whl"}]
    harness = """
      const input = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));
      Object.assign(process.env, input.env);
      const github = {rest: {repos: {
        getCommit: async () => ({data: {sha: input.main}}),
        getReleaseByTag: async () => {
          if (input.release_exists) return {data: {}};
          throw Object.assign(Error('missing'), {status: 404});
        }}, git: {getRef: async () => {
          if (input.tag_api_failure) throw Object.assign(Error('denied'), {status: 403});
          if (input.same_tag) return {data: {object: {type: 'commit', sha: input.env.RELEASE_SHA}}};
          if (input.annotated_tag) return {data: {object: {type: 'tag', sha: 'c'.repeat(40)}}};
          if (input.conflicting_tag) return {data: {object: {type: 'commit', sha: 'b'.repeat(40)}}};
          throw Object.assign(Error('missing'), {status: 404});
        }, getTag: async () => ({data: {object: {type: 'commit', sha: input.env.RELEASE_SHA}}})},
        actions: {listWorkflowRuns: async (query) => {
          if (query.head_sha !== input.env.RELEASE_SHA || query.branch !== 'main' ||
              query.event !== 'push' || query.per_page !== 100) throw Error('incorrect API query');
          const runs = input.runs[query.workflow_id];
          return {data: {total_count: input.truncated ? 101 : runs.length, workflow_runs: runs}};
        }}}};
      const fetch = async () => ({ok: input.pypi_ok, status: input.pypi_ok ? 200 : 503,
        json: async () => ({releases: input.versions})});
      const AsyncFunction = Object.getPrototypeOf(async function() {}).constructor;
      new AsyncFunction('github', 'context', 'require', 'fetch', input.script)(
        github, {repo: {owner: 'bhargavandhe', repo: 'fastauth'}}, require, fetch
      ).then(() => process.stdout.write(JSON.stringify({ok: true})))
       .catch(error => process.stdout.write(JSON.stringify({ok: false, error: error.message})));
    """
    payload = {
        "script": script,
        "main": main,
        "runs": runs,
        "versions": versions,
        "truncated": scenario == "truncated",
        "same_tag": scenario == "same-tag",
        "annotated_tag": scenario == "annotated-tag",
        "tag_api_failure": scenario == "tag-api-failure",
        "conflicting_tag": scenario == "conflicting-tag",
        "release_exists": scenario == "release-exists",
        "pypi_ok": scenario != "pypi-unavailable",
        "env": {
            "GITHUB_REPOSITORY": REPO,
            "RELEASE_SHA": SHA,
            "RELEASE_VERSION": "0.15.0",
            "VERSIONS_DIGEST": hashlib.sha256(b'["0.14.0"]').hexdigest(),
        },
    }
    result = subprocess.run(
        [node, "--eval", harness],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=True,
        timeout=20,
    )
    assert json.loads(result.stdout)["ok"] is (
        scenario in ("success", "same-tag", "annotated-tag")
    ), result.stdout


@pytest.fixture(scope="module")
def default_build(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Exercise uv's default dist/ behavior, including its generated .gitignore."""
    import os
    import shutil
    import subprocess

    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("uv is required to reproduce the publishing build")
    project = tmp_path_factory.mktemp("release-default-build")
    for name in (
        "pyproject.toml",
        "README.md",
        "LICENSE",
        "CHANGELOG.md",
        "API_STABILITY.md",
        "SECURITY.md",
    ):
        shutil.copyfile(ROOT / name, project / name)
    shutil.copytree(ROOT / "src", project / "src", ignore=shutil.ignore_patterns("__pycache__"))
    environment = os.environ.copy()
    environment["SOURCE_DATE_EPOCH"] = "1700000000"
    subprocess.run([uv, "build"], cwd=project, env=environment, check=True, capture_output=True)
    assert (project / "dist/.gitignore").read_text() == "*"
    return project


def test_inspect_and_check_accept_actual_default_uv_build(
    release: Any, default_build: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import hashlib
    import tomllib

    import fastauth

    version = tomllib.loads((default_build / "pyproject.toml").read_text())["project"]["version"]
    monkeypatch.setattr(release, "ROOT", default_build)

    def pypi(url: str, model: Any, **kwargs: Any) -> Any:
        assert url == "https://pypi.org/pypi/fastauth-py/json"
        return model(releases={})

    def absent(path: str, model: Any, **kwargs: Any) -> None:
        return None

    monkeypatch.setattr(release, "read_model", pypi)
    monkeypatch.setattr(release, "github", absent)
    state = release.inspect(version, SHA)
    names = {f"fastauth_py-{version}-py3-none-any.whl", f"fastauth_py-{version}.tar.gz"}
    assert set(state.local) == names
    for name in names:
        assert (
            state.local[name]
            == hashlib.sha256((default_build / "dist" / name).read_bytes()).hexdigest()
        )
    output = tmp_path / "output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setenv("GITHUB_EVENT_NAME", "workflow_run")
    release.check(SHA, fastauth.__version__)
    assert f"version={version}\naction=publish\n" in output.read_text()


@pytest.mark.parametrize("unexpected", [".unexpected", "extra.whl", "extra.tar.gz", "notes.txt"])
def test_inspect_still_rejects_every_other_extra_file(
    release: Any,
    default_build: Path,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    unexpected: str,
) -> None:
    import shutil
    import tomllib

    version = tomllib.loads((default_build / "pyproject.toml").read_text())["project"]["version"]
    shutil.copytree(default_build / "dist", tmp_path / "dist")
    (tmp_path / "dist" / unexpected).write_text("unexpected content")
    monkeypatch.setattr(release, "ROOT", tmp_path)
    with pytest.raises(ValueError, match="exactly"):
        release.inspect(version, SHA)


def test_distribution_upload_explicitly_excludes_build_metadata() -> None:
    workflow = (ROOT / ".github/workflows/publish.yml").read_text()
    assert "path: |\n            dist/*.whl\n            dist/*.tar.gz\n" in workflow
