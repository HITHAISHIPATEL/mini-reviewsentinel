from __future__ import annotations

import ast
import math
import re
from pathlib import Path

from .models import Finding, Severity

SENSITIVE_NAME = re.compile(r"(?:password|passwd|pwd|api[_-]?key|secret|token|access[_-]?key|private[_-]?key)", re.I)
PLACEHOLDERS = {
    "", "password", "your_password", "your_api_key", "api_key_here", "secret_here",
    "changeme", "change_me", "replace_me", "replace-this", "placeholder", "example",
    "example_key", "dummy", "test", "testing", "none", "null", "todo", "xxx", "xxxx",
}
SQL_WORD = re.compile(r"\b(select|insert|update|delete|replace|drop|alter|create)\b", re.I)


def _source_segment(source: str, node: ast.AST) -> str:
    return ast.get_source_segment(source, node) or ast.dump(node, include_attributes=False)


def _is_dynamic(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return bool(node.args or node.keywords)
    return False


def _sql_context(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        text = " ".join(v.value for v in node.values if isinstance(v, ast.Constant) and isinstance(v.value, str))
    elif isinstance(node, ast.BinOp):
        parts = [node.left, node.right]
        text = " ".join(p.value for p in parts if isinstance(p, ast.Constant) and isinstance(p.value, str))
    elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        text = str(node.func.value.value) if isinstance(node.func.value, ast.Constant) and isinstance(node.func.value.value, str) else ""
    else:
        text = ""
    return bool(SQL_WORD.search(text))


def _unsafe_sql_node(node: ast.AST, aliases: dict[str, ast.AST], seen: set[str] | None = None) -> ast.AST | None:
    seen = seen or set()
    if _is_dynamic(node) and _sql_context(node):
        return node
    if isinstance(node, ast.Name) and node.id in aliases and node.id not in seen:
        return _unsafe_sql_node(aliases[node.id], aliases, seen | {node.id})
    # Follow simple concatenations that contain SQL text, even if the operator's
    # immediate operands do not both carry a literal.
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        text = ast.unparse(node)
        if SQL_WORD.search(text):
            return node
    return None


def _unsafe_sql_expr(node: ast.AST, aliases: dict[str, ast.AST], seen: set[str] | None = None) -> bool:
    return _unsafe_sql_node(node, aliases, seen) is not None


def _secret_looks_real(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized in PLACEHOLDERS or normalized.startswith(("your_", "<", "${", "os.getenv", "os.environ")):
        return False
    if "example" in normalized or "placeholder" in normalized or "changeme" in normalized:
        return False
    if len(value.strip()) < 8 or " " in value.strip():
        return False
    # A modest entropy / composition heuristic avoids reporting obvious labels.
    groups = sum(bool(re.search(pattern, value)) for pattern in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    if groups < 2:
        return False
    counts = [value.count(c) for c in set(value)]
    entropy = -sum((n / len(value)) * math.log2(n / len(value)) for n in counts)
    return entropy >= 2.1


def analyze_source(source: str, filename: str) -> tuple[list[Finding], list[dict[str, str]]]:
    """Perform bounded AST-based checks without importing or executing source."""
    findings: list[Finding] = []
    errors: list[dict[str, str]] = []
    try:
        tree = ast.parse(source, filename=filename)
    except (SyntaxError, ValueError) as exc:
        errors.append({"file": filename, "error": f"Python parse failed: {exc}"})
        return findings, errors

    alias_rows: list[tuple[int, str, ast.AST]] = []
    builtin_aliases: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "builtins":
            for item in node.names:
                if item.name in {"eval", "exec"}:
                    builtin_aliases.add(item.asname or item.name)
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            if value is None:
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    alias_rows.append((node.lineno, target.id, value))
                    if isinstance(value, ast.Constant) and isinstance(value.value, str) and SENSITIVE_NAME.search(target.id):
                        if _secret_looks_real(value.value):
                            findings.append(Finding(filename, node.lineno, "Possible hard-coded secret", Severity.HIGH,
                                f"Sensitive variable {target.id!r} is assigned a non-placeholder string literal.",
                                "Load the credential from a secret manager or environment variable; rotate it if real."))

    emitted_sql: set[int] = set()
    emitted_eval: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func_name = node.func.id if isinstance(node.func, ast.Name) else (node.func.attr if isinstance(node.func, ast.Attribute) else "")
            if func_name in {"eval", "exec"} or func_name in builtin_aliases:
                if node.lineno not in emitted_eval:
                    emitted_eval.add(node.lineno)
                    findings.append(Finding(filename, node.lineno, f"Dangerous dynamic code execution via {func_name}()", Severity.HIGH,
                        f"Call expression: {_source_segment(source, node)}",
                        "Avoid evaluating source strings; use a safe parser or an explicit allowlisted operation."))
            if func_name in {"execute", "executemany", "executescript"} and node.args:
                query = node.args[0]
                aliases: dict[str, ast.AST] = {}
                for assign_line, name, value in sorted(alias_rows, key=lambda row: row[0]):
                    if assign_line <= node.lineno:
                        aliases[name] = value
                culprit = _unsafe_sql_node(query, aliases)
                if culprit is not None and node.lineno not in emitted_sql:
                    emitted_sql.add(node.lineno)
                    findings.append(Finding(filename, node.lineno, "Potential SQL injection", Severity.HIGH,
                        f"SQL execution receives a dynamically assembled query: {_source_segment(source, culprit)}",
                        "Use a constant query with bound parameters (for example, execute(sql, (value,)))."))
    # Stable de-duplication and ordering.
    unique: dict[tuple[str, int, str], Finding] = {}
    for item in findings:
        unique[(item.file, item.line, item.finding)] = item
    return sorted(unique.values(), key=lambda f: (f.file, f.line, f.finding)), errors


def collect_python_files(path: str, max_bytes: int = 1_000_000) -> tuple[list[tuple[str, str]], list[dict[str, str]]]:
    root = Path(path)
    errors: list[dict[str, str]] = []
    ignored = {".git", ".venv", "venv", "__pycache__", "node_modules", "dist", "build", ".tox", ".mypy_cache"}
    if not root.exists():
        return [], [{"file": str(root), "error": "Input path does not exist"}]
    paths = [root] if root.is_file() else sorted(p for p in root.rglob("*.py") if not any(part in ignored for part in p.parts))
    if root.is_file() and root.suffix != ".py":
        return [], [{"file": str(root), "error": "Input must be a .py file or a directory containing Python files"}]
    files: list[tuple[str, str]] = []
    for file in paths:
        label = file.name if root.is_file() else str(file.relative_to(root))
        try:
            if file.stat().st_size > max_bytes:
                errors.append({"file": label, "error": f"File exceeds {max_bytes} byte limit"})
                continue
            files.append((label, file.read_text(encoding="utf-8")))
        except (OSError, UnicodeError) as exc:
            errors.append({"file": label, "error": f"Could not read file: {exc}"})
    if not files and not errors:
        errors.append({"file": str(root), "error": "No Python files found"})
    return files, errors
