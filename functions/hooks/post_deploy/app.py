"""Post-deploy hook Lambda stub for validating deployed stack state."""
from __future__ import annotations

import json
import logging
from typing import Any, Dict

import boto3

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)

cfn = boto3.client("cloudformation")
iam = boto3.client("iam")
ec2 = boto3.client("ec2")


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Validate deployed resources after CloudFormation stack update."""
    LOGGER.info("Post-deploy event: %s", json.dumps(event))
    stack_name = event.get("stackName", "serverless-guardrails-demo")

    drift = _describe_stack_resources(stack_name)
    if drift:
        LOGGER.warning("Detected resource drift: %s", drift)

    iam_findings = _inspect_roles(stack_name)
    sg_findings = _inspect_security_groups(stack_name)

    if iam_findings or sg_findings:
        LOGGER.error("Post-deploy validation failed", extra={"iam": iam_findings, "sg": sg_findings})
    else:
        LOGGER.info("Post-deploy validation completed without findings")

    return {
        "stack": stack_name,
        "iam_findings": iam_findings,
        "security_group_findings": sg_findings,
        "drift_summary": drift,
    }


def _describe_stack_resources(stack_name: str) -> list[str]:
    response = cfn.describe_stack_resources(StackName=stack_name)
    findings: list[str] = []
    for resource in response.get("StackResources", []):
        if resource.get("ResourceType") == "AWS::EC2::SecurityGroup":
            findings.append(f"Validate SG {resource.get('PhysicalResourceId')}")
    return findings


def _inspect_roles(stack_name: str) -> list[str]:
    findings: list[str] = []
    paginator = iam.get_paginator("list_roles")
    for page in paginator.paginate(PathPrefix="/"):
        for role in page.get("Roles", []):
            if stack_name in role.get("RoleName", "") and "Wildcard" in role.get("AssumeRolePolicyDocument", {}):
                findings.append(f"Role {role['RoleName']} uses wildcard assume policy")
    return findings


def _inspect_security_groups(stack_name: str) -> list[str]:
    findings: list[str] = []
    response = ec2.describe_security_groups()
    for group in response.get("SecurityGroups", []):
        if stack_name in group.get("GroupName", ""):
            for permission in group.get("IpPermissionsEgress", []):
                cidrs = permission.get("IpRanges", [])
                if any(range_.get("CidrIp") == "0.0.0.0/0" for range_ in cidrs):
                    findings.append(f"Security group {group['GroupId']} allows open egress")
    return findings
