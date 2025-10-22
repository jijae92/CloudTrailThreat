"""Helper functions for analysing Python source code."""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable, List

from .fileio import ensure_path


class LiteralVisitor(ast.NodeVisitor):
    """AST visitor collecting string literals."""

    def __init__(self) -> None:
        self.literals: List[str] = []

    def visit_Constant(self, node: ast.Constant) -> None:  # noqa: N802
        if isinstance(node.value, str):
            self.literals.append(node.value)
        self.generic_visit(node)


def load_module_ast(path_str: str) -> ast.AST:
    """Parse a Python file into an AST."""
    path = ensure_path(path_str)
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def extract_string_literals(path_str: str) -> Iterable[str]:
    """Yield string literals defined within the module."""
    tree = load_module_ast(path_str)
    visitor = LiteralVisitor()
    visitor.visit(tree)
    return visitor.literals
