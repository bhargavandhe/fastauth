# FastAuth Rebrand Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rename the entire codebase from FastAuth to FastAuth, including the public API, package/module root, CLI, docs, tests, and release metadata, with no FastAuth traces left in the repository.

**Architecture:** Move the import namespace from `fastauth` to `fastauth`, rename the public classes and errors to `FastAuth*`, and update every import, doc reference, example, and test to match. Keep the underlying implementation structure intact so the change is mostly mechanical rather than architectural, but make the user-facing identifiers consistent everywhere.

**Tech Stack:** Python 3.11, FastAPI, Pydantic 2, Hatchling, Pytest, Ruff, Pyright.

---

### Task 1: Rename the package root and public API

**Files:**
- Modify: `pyproject.toml`
- Move: `src/fastauth` -> `src/fastauth`
- Modify: `src/fastauth/__init__.py`
- Modify: `src/fastauth/config.py`
- Modify: `src/fastauth/exceptions.py`
- Modify: `src/fastauth/runtime/auth.py`
- Modify: `src/fastauth/web/fastapi.py`
- Modify: `src/fastauth/runtime/context.py`
- Modify: `src/fastauth/runtime/api.py`

- [ ] **Step 1: Rename the source tree**

Run:
```bash
git mv src/fastauth src/fastauth
```

Expected: the package root now lives at `src/fastauth`.

- [ ] **Step 2: Rename the public symbols in code**

Replace public classes and imports so the exported API becomes `FastAuth`, `FastAuthOptions`, `FastAuthError`, and related `FastAuth*` names.

```python
from fastauth import FastAuthOptions
from fastauth.runtime.auth import FastAuth

__all__ = ["FastAuth", "FastAuthOptions", "__version__"]
__version__ = "0.1.0"
```

- [ ] **Step 3: Update packaging metadata for the new namespace**

```toml
[project]
name = "fastauth"

[project.scripts]
fastauth = "fastauth.cli.main:app"

[tool.hatch.build.targets.wheel]
packages = ["src/fastauth"]

[tool.hatch.build.targets.sdist]
include = ["src/fastauth", "README.md", "LICENSE"]
```

Expected: builds and imports resolve through `fastauth`.

### Task 2: Update docs, examples, and release metadata

**Files:**
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `CONTRIBUTING.md`
- Modify: `mkdocs.yml`
- Modify: `release-please-config.json`
- Modify: `examples/quickstart/app.py`
- Modify: `examples/quickstart/settings.py`
- Modify: `examples/quickstart/tests/test_end_to_end.py`

- [ ] **Step 1: Rename all user-facing references**

Change the README, docs, examples, and changelog text so they refer to FastAuth, `fastauth`, `FastAuthOptions`, and the `fastauth` CLI.

- [ ] **Step 2: Update release and repo metadata**

Change repository URLs, package keywords, and release-please package names so they no longer mention FastAuth.

```json
{
  "packages": {
    ".": {
      "package-name": "fastauth"
    }
  }
}
```

- [ ] **Step 3: Rewrite the quickstart example imports and names**

```python
from fastauth import FastAuth, FastAuthOptions
```

Expected: the quickstart imports the renamed public API and no longer mentions FastAuth anywhere.

### Task 3: Rewrite tests for the renamed API and namespace

**Files:**
- Modify: `tests/unit/test_config.py`
- Modify: `tests/unit/test_fastauth_defaults.py`
- Modify: `tests/unit/test_exceptions.py`
- Modify: `tests/unit/test_docs_contract.py`
- Modify: `tests/unit/test_plugin_registry.py`
- Modify: `tests/integration/test_*`
- Modify: `tests/adapters/test_*`
- Modify: `examples/quickstart/tests/test_end_to_end.py`

- [ ] **Step 1: Update import paths and type names**

Replace `fastauth` imports with `fastauth` imports everywhere, including fixture types and helper annotations.

- [ ] **Step 2: Update assertions for renamed defaults**

Update checks for the default cookie name, table prefixes, CLI output, and exception names to the new FastAuth naming.

- [ ] **Step 3: Refresh docs-contract tests**

Keep the docs-vs-code assertions aligned with the renamed README, changelog, and installation docs.

### Task 4: Remove the last FastAuth traces and verify the rename

**Files:**
- Modify: any remaining source, docs, tests, and config files reported by search

- [ ] **Step 1: Run a full repository search**

Run:
```bash
rg -n --hidden --glob '!.git' --glob '!.venv' --glob '!**/__pycache__/**' --glob '!**/*.pyc' 'FastAuth|fastauth|FASTAUTH_' /Users/bhargav/Developer/fastauth
```

Expected: no matches remain.

- [ ] **Step 2: Run the focused test suite**

Run:
```bash
uv run pytest tests/unit tests/integration tests/adapters examples/quickstart/tests -q
```

Expected: the renamed package passes the core test surface.

- [ ] **Step 3: Run lint and typing checks**

Run:
```bash
uv run ruff check .
uv run pyright
```

Expected: no import-path or symbol-name regressions remain.

