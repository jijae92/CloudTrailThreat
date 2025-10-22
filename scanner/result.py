"""Result schema models for scanner output."""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from .severity import Severity


@dataclass(frozen=True)
class Finding:
    """Represents a single guardrail finding."""

    rule_id: str
    description: str
    severity: Severity
    resource_id: str
    remediation: str

    def to_dict(self) -> dict:
        """Convert to a JSON-serialisable dictionary."""
        payload = asdict(self)
        payload["severity"] = self.severity.value
        return payload


@dataclass
class ScanResult:
    """Aggregate of findings and summary information."""

    findings: List[Finding] = field(default_factory=list)
    summary: Dict[str, int] = field(init=False)
    passed: bool = field(init=False)

    def __post_init__(self) -> None:
        self.summary = _build_summary(self.findings)
        self.passed = (
            self.summary.get("CRITICAL", 0) == 0
            and self.summary.get("HIGH", 0) == 0
            and self.summary.get("MEDIUM", 0) == 0
        )

    def to_dict(self) -> dict:
        """Convert the result into a serialisable payload."""
        return {
            "summary": self.summary,
            "passed": self.passed,
            "findings": [finding.to_dict() for finding in self.findings],
        }

    def to_json(self, out_path: Optional[str] = None) -> str:
        """Serialise the result to JSON and optionally persist to disk."""
        payload = json.dumps(self.to_dict(), indent=2, sort_keys=True)
        if out_path:
            path = Path(out_path).expanduser().resolve()
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("w", encoding="utf-8") as handle:
                handle.write(payload)
        return payload


def _build_summary(findings: Iterable[Finding]) -> Dict[str, int]:
    summary: Dict[str, int] = {severity.name: 0 for severity in Severity}
    total = 0
    for finding in findings:
        summary[finding.severity.name] = summary.get(finding.severity.name, 0) + 1
        total += 1
    summary["TOTAL"] = total
    return summary


def merge_findings(*results: Iterable[Finding]) -> List[Finding]:
    """Flatten multiple finding iterables preserving order."""
    merged: List[Finding] = []
    for iterable in results:
        merged.extend(iterable)
    return merged
