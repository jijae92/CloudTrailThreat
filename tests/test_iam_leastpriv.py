"""Tests for the IAM least privilege rule."""
from __future__ import annotations

from scanner.rules import iam_leastpriv
from scanner.severity import Severity


def test_detects_wildcard_action(tmp_path) -> None:
    template = tmp_path / "template.yaml"
    template.write_text(
        """
Resources:
  WildPolicy:
    Type: AWS::IAM::Policy
    Properties:
      PolicyDocument:
        Statement:
          - Effect: Allow
            Action: "*"
            Resource: "*"
        """,
        encoding="utf-8",
    )

    findings = iam_leastpriv.scan(template_path=str(template))
    assert findings, "Expected finding for wildcard action"
    critical = [f for f in findings if f.severity is Severity.CRITICAL]
    assert critical, "Wildcard action should be CRITICAL severity"
    assert critical[0].rule_id.startswith("IAM")


def test_detects_resource_wildcard(tmp_path) -> None:
    template = tmp_path / "template.yaml"
    template.write_text(
        """
Resources:
  ResourceWide:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      PolicyDocument:
        Statement:
          - Effect: Allow
            Action:
              - s3:GetObject
            Resource: "arn:aws:s3:::*"
        """,
        encoding="utf-8",
    )

    findings = iam_leastpriv.scan(template_path=str(template))
    assert findings, "Expected finding for wildcard resource"
    severities = {finding.severity for finding in findings}
    assert Severity.HIGH in severities, "Wildcard resource should be HIGH severity"


def test_conditionless_sensitive_action(tmp_path) -> None:
    template = tmp_path / "template.yaml"
    template.write_text(
        """
Resources:
  LogsRole:
    Type: AWS::IAM::Role
    Properties:
      Policies:
        - PolicyName: LogsPolicy
          PolicyDocument:
            Statement:
              - Effect: Allow
                Action: logs:PutRetentionPolicy
                Resource: arn:aws:logs:us-east-1:123456789012:log-group:my-group
        """,
        encoding="utf-8",
    )

    findings = iam_leastpriv.scan(template_path=str(template))
    assert findings, "Expected finding for conditionless sensitive action"
    assert any(f.severity is Severity.MEDIUM for f in findings)
