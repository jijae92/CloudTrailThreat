"""IAM least privilege rule implementation.

References:
    - NIST SP 800-53 AC-6
    - ISO/IEC 27001 A.9
    - AWS Well-Architected Framework (Security Pillar)
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from itertools import count
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from ..result import Finding
from ..severity import Severity
from ..utils import iac

RULE_NAME = "iam_leastpriv"

# Services requiring strict scoping to avoid privilege escalation.
HIGH_RISK_PREFIXES = {"iam", "kms", "sts", "organizations"}
CRITICAL_ACTIONS = {"iam:*", "kms:*", "sts:*", "*"}
RESOURCE_WILDCARD = "*"
WILDCARD_SUFFIX = ":*"
HIGH_RISK_ACTIONS = {
    "s3:putobject",
    "logs:putretentionpolicy",
    "logs:putlogevents",
    "iam:passrole",
}

# Guidance snippets for right-sizing access.
PRINCIPLE_SNIPPETS = {
    "logs": '["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]',
    "s3": '["s3:GetObject", "s3:PutObject", "s3:ListBucket"]',
    "iam": '["iam:PassRole"] with explicit resource ARN + conditions',
    "kms": '["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey"]',
}


@dataclass(frozen=True)
class PolicyIssue:
    severity: Severity
    description: str
    resource: str
    path: str
    snippet: str


def scan(template_path: Optional[str] = None, **_: object) -> List[Finding]:
    """Examine IAM related resources for least privilege violations."""
    if not template_path:
        return []

    template = iac.load_template(template_path)
    resources = template.get("Resources", {}) if isinstance(template, dict) else {}

    sequence = count(1)
    findings: List[Finding] = []
    for logical_id, resource in resources.items():
        if not isinstance(resource, dict):
            continue
        for path, statement in _iter_statements(logical_id, resource):
            issue = _evaluate_statement(statement, logical_id, path)
            if issue:
                findings.append(_build_finding(issue, next(sequence)))
    return findings


def _iter_statements(logical_id: str, resource: dict) -> Iterable[Tuple[str, dict]]:
    """Yield (path, statement) tuples from various IAM-bearing resources."""
    resource_type = resource.get("Type")
    properties = resource.get("Properties", {})

    if resource_type in {"AWS::IAM::Policy", "AWS::IAM::ManagedPolicy"}:
        document = properties.get("PolicyDocument")
        yield from _yield_statements(document, f"Resources.{logical_id}.Properties.PolicyDocument")

    if resource_type == "AWS::IAM::Role":
        for idx, policy in enumerate(properties.get("Policies", []) or []):
            if isinstance(policy, dict):
                document = policy.get("PolicyDocument")
                base = f"Resources.{logical_id}.Properties.Policies[{idx}].PolicyDocument"
                yield from _yield_statements(document, base)

    if resource_type == "AWS::Serverless::Function":
        policies = properties.get("Policies")
        if isinstance(policies, list):
            for idx, entry in enumerate(policies):
                if isinstance(entry, dict) and "Statement" in entry:
                    base = f"Resources.{logical_id}.Properties.Policies[{idx}]"
                    yield from _yield_statements(entry, base)
        elif isinstance(policies, dict):
            yield from _yield_statements(policies, f"Resources.{logical_id}.Properties.Policies")


def _yield_statements(document: object, base_path: str) -> Iterable[Tuple[str, dict]]:
    if not isinstance(document, dict):
        return []
    statements = document.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, Sequence):
        return []
    for idx, statement in enumerate(statements):
        if isinstance(statement, dict):
            yield f"{base_path}.Statement[{idx}]", statement


def _evaluate_statement(statement: dict, logical_id: str, path: str) -> Optional[PolicyIssue]:
    effect = str(statement.get("Effect", "")).lower()
    if effect != "allow":
        return None

    actions = _normalize_to_list(statement.get("Action"))
    resources = _normalize_to_list(statement.get("Resource"))
    has_condition = isinstance(statement.get("Condition"), dict) and statement["Condition"]

    severity: Optional[Severity] = None
    description_parts: List[str] = []

    if _contains_wildcard_action(actions):
        severity = Severity.CRITICAL
        description_parts.append("Wildcard action scope detected")
    elif _contains_high_risk_wildcard(actions):
        severity = Severity.CRITICAL
        description_parts.append("High-risk service wildcard detected")

    if severity is None and _contains_resource_wildcard(resources):
        severity = Severity.HIGH
        description_parts.append("Resource scope is unbounded")

    if severity is None and not has_condition and _contains_sensitive_action(actions):
        severity = Severity.MEDIUM
        description_parts.append("Allow statement lacks restrictive conditions")

    if severity is None:
        return None

    snippet = json.dumps(statement, indent=2, sort_keys=True)
    description = "; ".join(description_parts)
    recommendation = _build_recommendation(actions)

    return PolicyIssue(
        severity=severity,
        description=f"{description} (resource {logical_id})",
        resource=logical_id,
        path=path,
        snippet=f"{snippet}\nRecommendation: {recommendation}",
    )


def _build_finding(issue: PolicyIssue, counter: int) -> Finding:
    return Finding(
        rule_id=f"IAM{counter:03d}",
        description=f"{issue.description} @ {issue.path}\n{issue.snippet}",
        severity=issue.severity,
        resource_id=issue.resource,
        remediation=(
            "Enforce least privilege per NIST SP 800-53 AC-6 / ISO 27001 A.9. "
            "Restrict actions/resources and apply Conditions where applicable."
        ),
    )


def _normalize_to_list(value: object) -> List[str]:
    if isinstance(value, list):
        return [str(item) for item in value if isinstance(item, (str, int))]
    if isinstance(value, (str, int)):
        return [str(value)]
    return []


def _contains_wildcard_action(actions: Sequence[str]) -> bool:
    return any(action.strip() == "*" for action in actions)


def _contains_high_risk_wildcard(actions: Sequence[str]) -> bool:
    for action in actions:
        lower = action.lower()
        if lower in CRITICAL_ACTIONS:
            return True
        if lower.endswith(WILDCARD_SUFFIX):
            prefix = lower.split(":")[0]
            if prefix in HIGH_RISK_PREFIXES:
                return True
    return False


def _contains_resource_wildcard(resources: Sequence[str]) -> bool:
    for resource in resources:
        value = resource.strip().lower()
        if value == RESOURCE_WILDCARD:
            return True
        if value.endswith(WILDCARD_SUFFIX) or value.endswith(":*"):
            return True
        if value.endswith("/*"):
            return True
    return False


def _contains_sensitive_action(actions: Sequence[str]) -> bool:
    for action in actions:
        lower = action.lower()
        if lower in HIGH_RISK_ACTIONS:
            return True
        prefix = lower.split(":")[0]
        if prefix in HIGH_RISK_PREFIXES:
            return True
    return False


def _build_recommendation(actions: Sequence[str]) -> str:
    services = {action.split(":")[0].lower() for action in actions if ":" in action}
    snippets = [
        f"{service}: {PRINCIPLE_SNIPPETS[service]}"
        for service in services
        if service in PRINCIPLE_SNIPPETS
    ]
    if snippets:
        return "Consider least-privilege set such as " + "; ".join(snippets)
    return (
        "Define only required actions and constrain resources with resource ARNs and condition keys."
    )
