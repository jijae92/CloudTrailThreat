"""Pre-deploy hook Lambda stub for validating risky infrastructure changes."""
from __future__ import annotations

import json
import logging
from typing import Any, Dict

import boto3

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)

CLOUDWATCH_NAMESPACE = "ServerlessGuardrails/PreDeploy"


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Entry point for CodePipeline invoke."""
    LOGGER.info("Received pre-deploy hook event: %s", json.dumps(event))

    change_set_name = event.get("changeSetName") or event.get("CodePipeline.job", {}).get("data", {}).get("actionConfiguration", {})
    template_summary = event.get("templateSummary", {})

    high_risk = _detect_high_risk_changes(template_summary)
    _publish_metric(len(high_risk))

    if high_risk:
        message = "; ".join(high_risk)
        LOGGER.error("High-risk change detected: %s", message)
        raise RuntimeError(f"Pre-deploy hook failed: {message}")

    LOGGER.info("No blocking risks detected; proceeding with deployment")
    return {"status": "ok"}


def _detect_high_risk_changes(summary: Dict[str, Any]) -> list[str]:
    risks: list[str] = []
    for resource in summary.get("ResourceChanges", []):
        resource_type = resource.get("ResourceType", "")
        action = resource.get("Action", "")
        if resource_type in {"AWS::IAM::Role", "AWS::IAM::Policy"} and action in {"Modify", "Add"}:
            risks.append(f"IAM change {action} on {resource_type}")
        if resource_type == "AWS::EC2::SecurityGroup" and action in {"Modify", "Add"}:
            risks.append("Security group modification detected")
    return risks


def _publish_metric(count: int) -> None:
    cloudwatch = boto3.client("cloudwatch")
    cloudwatch.put_metric_data(
        Namespace=CLOUDWATCH_NAMESPACE,
        MetricData=[
            {
                "MetricName": "HighRiskChanges",
                "Value": count,
                "Unit": "Count",
            }
        ],
    )
