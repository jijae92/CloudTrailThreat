"""Severity levels shared by all scanning rules."""
from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    """Enumeration of supported finding severities."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @classmethod
    def from_cli(cls, value: str) -> "Severity":
        """Normalize CLI-provided severity strings."""
        try:
            return cls[value.upper()]
        except KeyError as exc:
            raise ValueError(f"Unsupported severity: {value}") from exc
