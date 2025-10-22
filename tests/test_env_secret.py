"""Unit tests for enhanced env_secret rule."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Set

from scanner.rules import env_secret
from scanner.severity import Severity


def test_scan_template_detects_hardcoded_access_key(tmp_path) -> None:
    template = tmp_path / "template.yaml"
    template.write_text(
        """
Transform: AWS::Serverless-2016-10-31
Resources:
  DemoFunction:
    Type: AWS::Serverless::Function
    Properties:
      Handler: index.handler
      Runtime: python3.11
      Environment:
        Variables:
          AWS_ACCESS_KEY_ID: AKIA1234567890ABCDEF
        """,
        encoding="utf-8",
    )

    findings = env_secret.scan_template(str(template), allowlist=set())
    assert findings, "Expected a finding for hardcoded AWS key"
    finding = findings[0]
    assert finding.rule_id.startswith("ENV")
    assert finding.severity is Severity.HIGH
    assert "Environment.Variables.AWS_ACCESS_KEY_ID" in finding.description


def test_scan_code_dir_detects_suspicious_literal(tmp_path) -> None:
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    module = source_dir / "handler.py"
    module.write_text(
        "SECRET_TOKEN = 'abcd1234EFGH'\n"
        "SAFE_VALUE = 'hello'\n"
        "def handler(event, context):\n"
        "    return SECRET_TOKEN\n",
        encoding="utf-8",
    )

    findings = env_secret.scan_code_dir(str(source_dir), allowlist=set())
    assert findings, "Expected medium severity finding for suspicious literal"
    severities = {finding.severity for finding in findings}
    assert Severity.MEDIUM in severities
    paths = {finding.description for finding in findings}
    assert any("handler.py" in path for path in paths)


def test_allowlist_skips_exempt_environment_variable(tmp_path) -> None:
    template = tmp_path / "template.yaml"
    template.write_text(
        """
Transform: AWS::Serverless-2016-10-31
Resources:
  AllowedFunction:
    Type: AWS::Serverless::Function
    Properties:
      Handler: index.handler
      Runtime: python3.11
      Environment:
        Variables:
          TEST_TOKEN: "SHOULD_NOT_TRIGGER"
        """,
        encoding="utf-8",
    )

    allowlist_path = tmp_path / ".guardrails-allow.json"
    allowlist_path.write_text(
        json.dumps({"env_names": ["TEST_TOKEN"]}),
        encoding="utf-8",
    )

    allowlist: Set[str] = env_secret.load_allowlist(str(allowlist_path))
    findings = env_secret.scan_template(str(template), allowlist=allowlist)
    assert not findings, "Allowlisted environment name should be ignored"
