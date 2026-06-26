"""Enforces the project-wide rule: no leading-underscore names anywhere in `src/fastauth`."""

from __future__ import annotations

import ast
import pathlib

import pytest

ALLOWED_DUNDER = {
    "__init__",
    "__all__",
    "__version__",
    "__name__",
    "__main__",
    "__doc__",
    "__call__",
}
SOURCE_ROOT = pathlib.Path(__file__).resolve().parents[2] / "src" / "fastauth"


def collect_python_files() -> list[pathlib.Path]:
    return [p for p in SOURCE_ROOT.rglob("*.py") if p.is_file()]


class LeadingUnderscoreVisitor(ast.NodeVisitor):
    def __init__(self, path: pathlib.Path) -> None:
        self.path = path
        self.violations: list[str] = []

    def check(self, name: str, node: ast.AST) -> None:
        if name in ALLOWED_DUNDER:
            return
        if name.startswith("_"):
            line = getattr(node, "lineno", 0)
            self.violations.append(f"{self.path}:{line} '{name}'")

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.check(node.name, node)
        for arg in (*node.args.args, *node.args.kwonlyargs, *node.args.posonlyargs):
            self.check(arg.arg, node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.check(node.name, node)
        for arg in (*node.args.args, *node.args.kwonlyargs, *node.args.posonlyargs):
            self.check(arg.arg, node)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.check(node.name, node)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.check(target.id, node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if isinstance(node.target, ast.Name):
            self.check(node.target.id, node)
        self.generic_visit(node)


@pytest.mark.parametrize("file_path", collect_python_files(), ids=lambda p: str(p))
def test_no_leading_underscore_names(file_path: pathlib.Path) -> None:
    tree = ast.parse(file_path.read_text(encoding="utf-8"))
    visitor = LeadingUnderscoreVisitor(file_path)
    visitor.visit(tree)
    assert not visitor.violations, "Leading-underscore names found:\n" + "\n".join(
        visitor.violations
    )
