# /// script
# requires-python = ">=3.11"
# dependencies = ["packaging>=24", "pydantic>=2.11,<3"]
# ///
"""Fail-closed release gates; only ``finish`` creates GitHub release metadata.

No credentials are persisted. PyPI publishing stays in its dedicated OIDC action.
All downloaded distributions come from this workflow's own build, never CI/PR artifacts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import time
import tomllib
from pathlib import Path
from typing import TypeVar
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from packaging.version import Version
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parents[2]
REPOSITORY = "bhargavandhe/fastauth"
T = TypeVar("T", bound=BaseModel)


class Repository(BaseModel):
    full_name: str


class WorkflowRun(BaseModel):
    id: int
    run_attempt: int
    name: str
    path: str
    event: str
    head_branch: str | None
    head_sha: str
    status: str
    conclusion: str | None
    repository: Repository
    head_repository: Repository | None


class WorkflowRuns(BaseModel):
    total_count: int
    workflow_runs: list[WorkflowRun]


class GitObject(BaseModel):
    sha: str
    type: str


class GitReference(BaseModel):
    object: GitObject


class Commit(BaseModel):
    sha: str


class Event(BaseModel):
    repository: Repository
    workflow_run: WorkflowRun | None = None
    ref: str = ""
    deleted: bool = False


class Digests(BaseModel):
    sha256: str


class Distribution(BaseModel):
    filename: str
    digests: Digests
    yanked: bool = False


class PyPI(BaseModel):
    releases: dict[str, list[Distribution]]


class Asset(BaseModel):
    name: str
    digest: str | None = None


class Release(BaseModel):
    tag_name: str
    draft: bool
    prerelease: bool
    assets: list[Asset]


class ReleaseState(BaseModel):
    version: str
    sha: str
    published: dict[str, str] = Field(default_factory=dict)
    published_versions: list[str] = Field(default_factory=list)
    local: dict[str, str]
    tag_sha: str | None = None
    release_assets: dict[str, str] | None = None


def read_model(url: str, model: type[T], *, missing_ok: bool = False) -> T | None:
    headers = {"Accept": "application/json"}
    if url.startswith("https://api.github.com/"):
        headers["Authorization"] = f"Bearer {os.environ['GH_TOKEN']}"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    request = Request(url, headers=headers)
    try:
        with urlopen(request, timeout=30) as response:
            return model.model_validate_json(response.read())
    except HTTPError as error:
        if error.code == 404 and missing_ok:
            return None
        raise


def github(path: str, model: type[T], *, missing_ok: bool = False) -> T | None:
    return read_model(
        f"https://api.github.com/repos/{REPOSITORY}/{path}", model, missing_ok=missing_ok
    )


def tag_commit(tag: str) -> str | None:
    reference = github(f"git/ref/tags/{tag}", GitReference, missing_ok=True)
    if reference is None:
        return None
    target = reference.object
    # Lightweight and annotated tags are supported; malformed/cyclic chains fail closed.
    for depth in range(10):  # Bounded annotated-tag traversal; do not follow a cycle forever.
        if target.type == "commit":
            return target.sha
        if target.type != "tag":
            break
        annotation = github(f"git/tags/{target.sha}", GitReference)
        assert annotation is not None
        target = annotation.object
        if depth == 9:
            break
    raise ValueError(f"Cannot resolve release tag {tag} to a commit")


def qualifies(run: WorkflowRun, repository: str, sha: str, workflow: str) -> bool:
    return (
        run.repository.full_name == repository
        and run.head_repository is not None
        and run.head_repository.full_name == repository
        and run.event == "push"
        and run.head_branch == "main"
        and run.head_sha == sha
        and run.path.split("@")[0] == f".github/workflows/{workflow}"
        and run.status == "completed"
        and run.conclusion == "success"
    )


def latest_success(runs: list[WorkflowRun], repository: str, sha: str, workflow: str) -> bool:
    # Never filter to success first: a newer failed/in-progress rerun must veto release.
    if not runs:
        return False
    latest = max(runs, key=lambda run: (run.id, run.run_attempt))
    return qualifies(latest, repository, sha, workflow)


def ready(sha: str) -> bool:
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("Invalid release SHA")
    main = github("commits/main", Commit)
    assert main is not None
    if main.sha != sha:
        print("Skipping: this commit is no longer the current main tip")
        return False
    for workflow in ("ci.yml", "security.yml"):
        runs = github(
            f"actions/workflows/{workflow}/runs?branch=main&event=push&head_sha={sha}&per_page=100",
            WorkflowRuns,
        )
        assert runs is not None
        if runs.total_count != len(runs.workflow_runs):
            raise ValueError("Workflow run response is incomplete; refusing to guess latest status")
        if not latest_success(runs.workflow_runs, REPOSITORY, sha, workflow):
            print(f"Waiting for the latest main push run of {workflow} to succeed")
            return False
    return True


def output(key: str, value: str) -> None:
    if "\n" in value or "\r" in value:
        raise ValueError("Invalid multiline workflow output")
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as stream:
        stream.write(f"{key}={value}\n")


def gate() -> None:
    event = Event.model_validate_json(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    if os.environ["GITHUB_REPOSITORY"] != REPOSITORY or event.repository.full_name != REPOSITORY:
        raise ValueError("Only the upstream repository may publish")
    if os.environ["GITHUB_EVENT_NAME"] == "workflow_run":
        run = event.workflow_run
        if run is None or run.name not in ("CI", "Security"):
            raise ValueError("Unexpected triggering workflow")
        workflow = "ci.yml" if run.name == "CI" else "security.yml"
        if not qualifies(run, REPOSITORY, run.head_sha, workflow):
            output("ready", "false")
            return
        sha = run.head_sha
    elif os.environ["GITHUB_EVENT_NAME"] == "push" and not event.deleted:
        if not re.fullmatch(r"refs/tags/v[0-9][0-9A-Za-z.!+_-]*", event.ref):
            raise ValueError("Expected a version tag push")
        sha = tag_commit(event.ref.removeprefix("refs/tags/"))
        if sha is None:
            raise ValueError("Pushed tag is missing")
    else:
        raise ValueError("Unsupported publishing event")
    output("sha", sha)
    output("ready", str(ready(sha)).lower())


def validate_version(package: str, runtime: str, tag: str | None) -> str:
    version = Version(package)
    if str(version) != package or version.local is not None:
        raise ValueError("Release version must be canonical PEP 440, without a local suffix")
    if runtime != package or (tag is not None and tag != f"v{package}"):
        raise ValueError("Package, runtime, and tag versions must agree")
    return package


def decide(state: ReleaseState) -> str:
    if state.published:
        if state.published.keys() != state.local.keys():
            raise ValueError("Partial/incomplete PyPI release: investigate before retrying")
        if state.release_assets is not None:
            if state.tag_sha is None:
                raise ValueError("GitHub release exists without its tag")
            if any(
                state.published.get(name) != digest for name, digest in state.release_assets.items()
            ):
                raise ValueError("GitHub release asset conflicts with PyPI")
            if state.release_assets == state.published:
                return "skip"  # Normal later main pushes retain the already-released version.
        if state.tag_sha not in (None, state.sha):
            raise ValueError("Existing tag points to another commit; cannot repair this release")
        if state.published != state.local:
            raise ValueError("Published artifact digest differs from the exact-commit build")
        return "release"  # Recover after upload succeeded but tag/release creation failed.
    if state.release_assets is not None:
        raise ValueError("GitHub release exists but its PyPI artifacts are missing")
    if state.tag_sha not in (None, state.sha):
        raise ValueError("Existing tag points to another commit")
    if any(Version(version) >= Version(state.version) for version in state.published_versions):
        raise ValueError("Unpublished version must be newer than every existing PyPI version")
    return "publish"


def inspect(version: str, sha: str) -> ReleaseState:
    local = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (ROOT / "dist").iterdir()
        if path.is_file()
    }
    expected = {f"fastauth_py-{version}.tar.gz", f"fastauth_py-{version}-py3-none-any.whl"}
    if local.keys() != expected:
        raise ValueError("Expected exactly the Fastauth wheel and source distribution")
    project = read_model("https://pypi.org/pypi/fastauth-py/json", PyPI)
    assert project is not None  # An unavailable/deleted project is never a new-release signal.
    distributions = project.releases.get(version, [])
    if any(distribution.yanked for distribution in distributions):
        raise ValueError("Refusing to automatically modify a yanked release")
    published = {
        distribution.filename: distribution.digests.sha256 for distribution in distributions
    }
    if len(published) != len(distributions):
        raise ValueError("Duplicate PyPI filenames")
    tag = f"v{version}"
    release = github(f"releases/tags/{tag}", Release, missing_ok=True)
    if release is not None and (
        release.tag_name != tag
        or release.draft
        or release.prerelease != Version(version).is_prerelease
    ):
        raise ValueError("Existing GitHub release metadata conflicts with this release")
    assets = (
        None
        if release is None
        else {asset.name: (asset.digest or "").removeprefix("sha256:") for asset in release.assets}
    )
    if release is not None and len(assets or {}) != len(release.assets):
        raise ValueError("Duplicate GitHub release assets")
    return ReleaseState(
        version=version,
        sha=sha,
        published=published,
        published_versions=list(project.releases),
        local=local,
        tag_sha=tag_commit(tag),
        release_assets=assets,
    )


def check(sha: str, runtime: str) -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    if project["name"] != "fastauth-py":
        raise ValueError("Unexpected package name")
    tag = os.environ["GITHUB_REF_NAME"] if os.environ["GITHUB_EVENT_NAME"] == "push" else None
    version = validate_version(project["version"], runtime, tag)
    state = inspect(version, sha)
    action = decide(state)
    versions = json.dumps(sorted(state.published_versions), separators=(",", ":"))
    output("versions_digest", hashlib.sha256(versions.encode()).hexdigest())
    print(f"Release v{version}: {action}")
    output("version", version)
    output("action", action)


def finish(version: str, sha: str) -> None:
    # PyPI's JSON endpoint can briefly lag a successful upload. Never write a tag first.
    for attempt in range(6):
        state = inspect(version, sha)
        if state.published == state.local:
            break
        if state.published:
            raise ValueError("PyPI artifact digest mismatch after publishing")
        if attempt == 5:
            raise ValueError("Published artifacts are not yet visible on PyPI; retry this workflow")
        time.sleep(10)
    action = decide(state)
    if action == "skip":
        return
    if action != "release":
        raise ValueError("PyPI publish has not been verified")
    tag = f"v{version}"
    if state.tag_sha is None:
        subprocess.run(
            [
                "gh",
                "api",
                f"repos/{REPOSITORY}/git/refs",
                "-f",
                f"ref=refs/tags/{tag}",
                "-f",
                f"sha={sha}",
            ],
            check=True,
        )
    if tag_commit(tag) != sha:
        raise ValueError("Tag changed during release creation")
    if state.release_assets is None:
        command = [
            "gh",
            "release",
            "create",
            tag,
            "--repo",
            REPOSITORY,
            "--verify-tag",
            "--generate-notes",
            "--title",
            tag,
        ]
        if Version(version).is_prerelease:
            command.append("--prerelease")
        subprocess.run(command, check=True)
    # Never clobber existing assets. Retrying completes only verified missing assets.
    current = inspect(version, sha)
    decide(current)
    for name in sorted(current.local.keys() - (current.release_assets or {}).keys()):
        subprocess.run(
            ["gh", "release", "upload", tag, str(ROOT / "dist" / name), "--repo", REPOSITORY],
            check=True,
        )
    if decide(inspect(version, sha)) != "skip":
        raise ValueError("GitHub release verification did not complete")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("gate", "check", "finish"))
    parser.add_argument("--sha", default="")
    parser.add_argument("--runtime", default="")
    parser.add_argument("--version", default="")
    arguments = parser.parse_args()
    if arguments.command == "gate":
        gate()
    elif arguments.command == "check":
        check(arguments.sha, arguments.runtime)
    else:
        finish(arguments.version, arguments.sha)


if __name__ == "__main__":
    main()
