"""Environment secret detection across IaC templates and Lambda code."""
from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass
from itertools import count
from pathlib import Path
from typing import Iterable, Iterator, List, Optional, Sequence, Set, Tuple

from ..result import Finding
from ..severity import Severity
from ..utils import iac

# Suspicious environment variable key names (case-insensitive).
KEY_PATTERN = re.compile(
    r"(?i)(secret|token|api[_-]?key|password|passwd|access[_-]?key|private|key|credential|auth)"
)
# High-risk secret value patterns.
TOKEN_PATTERN = re.compile(r"(?i)[A-Za-z0-9_\-]{24,}")
AWS_ACCESS_KEY_PATTERN = re.compile(r"(?:A3T|AKIA|ASIA)[0-9A-Z]{16}")
JWT_PATTERN = re.compile(r"(?:^|\\s)eyJ[A-Za-z0-9_\-]+\\.[A-Za-z0-9_\-]+\\.[A-Za-z0-9_\-]+(?:\\s|$)")
MIN_LITERAL_LENGTH = 8
DEFAULT_ALLOWLIST_PATH = Path(".guardrails-allow.json")
RECOMMENDATION = (
    "Store this value in AWS Secrets Manager or AWS Systems Manager Parameter Store and "
    "reference it at runtime instead of hardcoding it."
)


@dataclass(frozen=True)
class SecretCandidate:
    """Intermediate representation of a detected secret."""

    key: Optional[str]
    value: str
    location: str
    resource: str
    severity: Severity
    title: str


def load_allowlist(path: Optional[str | Path] = None) -> Set[str]:
    """Return allowed environment variable names from the JSON allowlist."""
    allow_path = Path(path) if path else DEFAULT_ALLOWLIST_PATH
    if not allow_path.exists():
        return set()
    try:
        data = json.loads(allow_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return set()

    env_names: Set[str] = set()
    if isinstance(data, dict):
        env_names.update(_extract_env_names(data))
        allowlist_section = data.get("allowlist")
        if isinstance(allowlist_section, Sequence):
            for entry in allowlist_section:
                if isinstance(entry, dict):
                    env_names.update(_extract_env_names(entry))
    return {name.upper() for name in env_names}


def _extract_env_names(payload: dict) -> Set[str]:
    names: Set[str] = set()
    if "env_names" in payload and isinstance(payload["env_names"], Sequence):
        for name in payload["env_names"]:
            if isinstance(name, str):
                names.add(name)
    if "env_name" in payload and isinstance(payload["env_name"], str):
        names.add(payload["env_name"])
    return names


def scan_template(
    template_path: str,
    allowlist: Optional[Set[str]] = None,
    counter: Optional[Iterator[int]] = None,
) -> List[Finding]:
    """Detect suspicious environment variables defined in SAM/CloudFormation templates."""
    allow = {name.upper() for name in (allowlist or set())}
    sequence = counter if counter is not None else count(1)
    template = iac.load_template(template_path)
    findings: List[Finding] = []

    resources = template.get("Resources", {}) if isinstance(template, dict) else {}
    for resource_name, resource in resources.items():
        if not isinstance(resource, dict):
            continue
        env_vars = _extract_environment_variables(resource)
        for key, value in env_vars:
            if key.upper() in allow:
                continue
            candidate = _evaluate_value(
                key=key,
                value=value,
                location=f"Resources.{resource_name}.Properties.Environment.Variables.{key}",
                resource=template_path,
                context="template",
            )
            if candidate:
                findings.append(_build_finding(candidate, sequence))
    return findings


def scan_code_dir(
    source_dir: str,
    allowlist: Optional[Set[str]] = None,
    counter: Optional[Iterator[int]] = None,
) -> List[Finding]:
    """Traverse Lambda source code for suspicious literals and assignments."""
    allow = {name.upper() for name in (allowlist or set())}
    sequence = counter if counter is not None else count(1)
    path = Path(source_dir).expanduser().resolve()

    if path.is_file():
        files = [path]
        base = path.parent
    else:
        files = sorted(path.rglob("*.py"))
        base = path

    findings: List[Finding] = []
    for file_path in files:
        try:
            contents = file_path.read_text(encoding="utf-8")
        except OSError:
            continue
        try:
            tree = ast.parse(contents, filename=str(file_path))
        except SyntaxError:
            continue

        candidates = list(
            _scan_ast_for_secrets(
                tree=tree,
                file_path=file_path,
                base=base,
                allowlist=allow,
            )
        )
        for candidate in candidates:
            findings.append(_build_finding(candidate, sequence))
    return findings


def scan(
    template_path: Optional[str] = None,
    source_path: Optional[str] = None,
    allowlist_path: Optional[str] = None,
    **_: object,
) -> List[Finding]:
    """Combined scan entry point invoked by the CLI."""
    allow = load_allowlist(allowlist_path)
    sequence = count(1)
    findings: List[Finding] = []
    if template_path:
        findings.extend(scan_template(template_path, allow, sequence))
    if source_path:
        findings.extend(scan_code_dir(source_path, allow, sequence))
    return findings


def _build_finding(candidate: SecretCandidate, counter: Iterator[int]) -> Finding:
    identifier = f"ENV{next(counter):03d}"
    description = f"{candidate.title} ({candidate.location})"
    return Finding(
        rule_id=identifier,
        description=description,
        severity=candidate.severity,
        resource_id=candidate.resource,
        remediation=RECOMMENDATION,
    )


def _extract_environment_variables(resource: dict) -> Iterable[Tuple[str, str]]:
    properties = resource.get("Properties")
    if not isinstance(properties, dict):
        return []
    env_block = properties.get("Environment")
    if not isinstance(env_block, dict):
        return []
    variables = env_block.get("Variables")
    if not isinstance(variables, dict):
        return []
    for key, value in variables.items():
        if isinstance(value, str):
            yield str(key), value


def _evaluate_value(
    key: Optional[str],
    value: str,
    location: str,
    resource: str,
    context: str,
) -> Optional[SecretCandidate]:
    if len(value) < MIN_LITERAL_LENGTH:
        return None

    severity = _classify_value(value)
    if severity == Severity.HIGH:
        return SecretCandidate(
            key=key,
            value=value,
            location=location,
            resource=resource,
            severity=Severity.HIGH,
            title=f"High-risk secret detected for '{key}'",
        )

    if key and KEY_PATTERN.search(key):
        level = severity if severity is not None else Severity.LOW
        title = "Suspicious environment variable name"
        if severity == Severity.MEDIUM:
            title = "Potential secret literal in code" if context == "code" else "Potential secret in template"
        return SecretCandidate(
            key=key,
            value=value,
            location=location,
            resource=resource,
            severity=level,
            title=title,
        )

    if severity == Severity.MEDIUM:
        return SecretCandidate(
            key=key,
            value=value,
            location=location,
            resource=resource,
            severity=Severity.MEDIUM,
            title="Suspicious credential-like literal",
        )

    return None


def _classify_value(value: str) -> Optional[Severity]:
    """Return severity for a secret-like value or None."""
    if AWS_ACCESS_KEY_PATTERN.search(value) or JWT_PATTERN.search(value):
        return Severity.HIGH
    if TOKEN_PATTERN.search(value):
        return Severity.HIGH

    if len(value) >= 12 and _looks_credential_like(value):
        return Severity.MEDIUM
    return None


def _looks_credential_like(value: str) -> bool:
    has_alpha = any(ch.isalpha() for ch in value)
    has_digit = any(ch.isdigit() for ch in value)
    has_special = any(ch in "-_" for ch in value)
    return has_alpha and has_digit and (has_special or len(value) >= 12)


def _scan_ast_for_secrets(
    tree: ast.AST,
    file_path: Path,
    base: Path,
    allowlist: Set[str],
) -> Iterable[SecretCandidate]:
    rel_path = str(file_path.relative_to(base)) if file_path.is_relative_to(base) else str(file_path)
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            yield from _handle_assignment(node, rel_path, file_path, allowlist)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.value, ast.Constant):
            yield from _handle_assignment(node, rel_path, file_path, allowlist, targets=[node.target])
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            candidate = _evaluate_value(
                key=None,
                value=node.value,
                location=f"{rel_path}:{getattr(node, 'lineno', 0)}",
                resource=str(file_path),
                context="code",
            )
            if candidate:
                yield candidate


def _handle_assignment(
    node: ast.AST,
    rel_path: str,
    file_path: Path,
    allowlist: Set[str],
    targets: Optional[Sequence[ast.expr]] = None,
) -> Iterable[SecretCandidate]:
    value_node = getattr(node, "value", None)
    if not isinstance(value_node, ast.Constant) or not isinstance(value_node.value, str):
        return []

    value = value_node.value
    results: List[SecretCandidate] = []
    for target in targets or getattr(node, "targets", []):
        key = _extract_key_name(target)
        if key and key.upper() in allowlist:
            continue
        candidate = _evaluate_value(
            key=key,
            value=value,
            location=f"{rel_path}:{getattr(value_node, 'lineno', 0)}",
            resource=str(file_path),
            context="code",
        )
        if candidate:
            results.append(candidate)
    return results


def _extract_key_name(target: ast.expr) -> Optional[str]:
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    if isinstance(target, ast.Subscript):
        slice_value = target.slice
        if isinstance(slice_value, ast.Constant) and isinstance(slice_value.value, str):
            return slice_value.value
        if hasattr(slice_value, "value") and isinstance(slice_value.value, ast.Constant):
            const = slice_value.value
            if isinstance(const.value, str):
                return const.value
    return None
