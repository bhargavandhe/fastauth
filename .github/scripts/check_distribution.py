"""Resolve the built wheel as a consumer, independently of the repository lockfile.

For lowest-direct, promote the selected wheel's declared dependency roots to
explicit resolver inputs. Otherwise uv treats them as transitive and chooses
latest versions, which does not test the advertised dependency floors.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--extra", default="core")
    parser.add_argument("--resolution", choices=("highest", "lowest-direct"), default="highest")
    arguments = parser.parse_args()
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    wheels = list((ROOT / "dist").glob("*.whl"))
    if len(wheels) != 1:
        raise RuntimeError("Build exactly one release wheel into dist/ before running this check")
    extra = arguments.extra
    requirements = [str(wheels[0]) + (f"[{extra}]" if extra != "core" else "")]
    if arguments.resolution == "lowest-direct":
        requirements.extend(project["dependencies"])
        requirements.extend(project["optional-dependencies"].get(extra, []))
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    with tempfile.TemporaryDirectory(prefix="fastauth-consumer-") as directory:
        workspace = Path(directory)
        python = workspace / "venv/bin/python"
        subprocess.run(
            ["uv", "venv", "--python", sys.executable, str(workspace / "venv")],
            check=True,
            cwd=workspace,
            env=environment,
        )
        subprocess.run(
            [
                "uv",
                "pip",
                "install",
                "--python",
                str(python),
                "--resolution",
                arguments.resolution,
                *requirements,
            ],
            check=True,
            cwd=workspace,
            env=environment,
        )
        subprocess.run(
            ["uv", "pip", "check", "--python", str(python)],
            check=True,
            cwd=workspace,
            env=environment,
        )
        shutil.copyfile(ROOT / ".github/scripts/wheel_smoke.py", workspace / "smoke.py")
        subprocess.run(
            [str(python), "smoke.py", extra],
            check=True,
            cwd=workspace,
            env=environment,
        )


main()
