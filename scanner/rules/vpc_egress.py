"""VPC egress exposure detector for serverless workloads.

Limitations:
    - Relies on explicit subnet/route/security group references in-template.
    - Does not resolve dynamic constructs (Fn::If, macros) or cross-stack imports.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from itertools import count
from typing import Dict, Iterable, Iterator, List, Optional, Sequence

from ..result import Finding
from ..severity import Severity
from ..utils import iac

RULE_NAME = "vpc_egress"

# Constants describing insecure patterns.
INTERNET_CIDR_V4 = "0.0.0.0/0"
INTERNET_CIDR_V6 = "::/0"
ANY_PROTOCOL = "-1"
ANY_PORT = -1

# Known AWS gateway identifiers.
INTERNET_GATEWAY_TYPES = {"AWS::EC2::InternetGateway"}
NAT_GATEWAY_TYPES = {"AWS::EC2::NatGateway"}
TARGET_INTERNET = {"igw", "internetgateway"}
TARGET_NAT = {"nat", "natgateway"}

RECOMMENDATION = (
    "Restrict egress by using VPC endpoints, scoped security group rules, and network firewalls."
)


@dataclass(frozen=True)
class VpcIssue:
    severity: Severity
    description: str
    resource: str
    path: str
    snippet: str


def scan(template_path: Optional[str] = None, **_: object) -> List[Finding]:
    """Evaluate SAM/CloudFormation template for unconstrained VPC egress."""
    if not template_path:
        return []

    template = iac.load_template(template_path)
    resources = template.get("Resources", {}) if isinstance(template, dict) else {}

    # Collect infrastructure metadata required for reasoning.
    subnets = _collect_subnets(resources)
    route_tables = _collect_route_tables(resources)
    attachments = _collect_route_table_associations(resources)
    security_groups = _collect_security_groups(resources)

    sequence = count(1)
    findings: List[Finding] = []

    for logical_id, resource in resources.items():
        if not isinstance(resource, dict):
            continue
        if resource.get("Type") not in {"AWS::Serverless::Function", "AWS::Lambda::Function"}:
            continue
        properties = resource.get("Properties", {})
        vpc_config = properties.get("VpcConfig") or properties.get("VpcConfigRef")
        if not isinstance(vpc_config, dict):
            continue

        subnet_ids = _ensure_list(vpc_config.get("SubnetIds") or vpc_config.get("SubnetId"))
        security_group_ids = _ensure_list(
            vpc_config.get("SecurityGroupIds") or vpc_config.get("SecurityGroupId")
        )

        # Analyze subnet exposure based on associated route tables.
        for subnet in subnet_ids:
            issue = _evaluate_subnet(subnet, logical_id, subnets, route_tables, attachments)
            if issue:
                findings.append(_build_finding(issue, next(sequence)))

        # Analyze security group egress.
        for sg in security_group_ids:
            issue = _evaluate_security_group(sg, logical_id, security_groups)
            if issue:
                findings.append(_build_finding(issue, next(sequence)))

    return findings


def _collect_subnets(resources: Dict[str, dict]) -> Dict[str, dict]:
    data: Dict[str, dict] = {}
    for logical_id, resource in resources.items():
        if not isinstance(resource, dict):
            continue
        if resource.get("Type") == "AWS::EC2::Subnet":
            data[logical_id] = resource.get("Properties", {})
    return data


def _collect_route_tables(resources: Dict[str, dict]) -> Dict[str, dict]:
    tables: Dict[str, dict] = {}
    for logical_id, resource in resources.items():
        if not isinstance(resource, dict):
            continue
        if resource.get("Type") == "AWS::EC2::RouteTable":
            tables[logical_id] = resource.get("Properties", {})
        if resource.get("Type") == "AWS::EC2::Route":
            # Flatten standalone route resources under an implicit table bucket.
            table = resource.get("Properties", {}).get("RouteTableId")
            key = str(table)
            route_list = tables.setdefault(key, {}).setdefault("Routes", [])
            route_list.append(resource.get("Properties", {}))
    return tables


def _collect_route_table_associations(resources: Dict[str, dict]) -> Dict[str, str]:
    associations: Dict[str, str] = {}
    for resource in resources.values():
        if not isinstance(resource, dict):
            continue
        if resource.get("Type") == "AWS::EC2::SubnetRouteTableAssociation":
            props = resource.get("Properties", {})
            subnet = props.get("SubnetId")
            table = props.get("RouteTableId")
            if subnet and table:
                associations[str(subnet)] = str(table)
    return associations


def _collect_security_groups(resources: Dict[str, dict]) -> Dict[str, dict]:
    groups: Dict[str, dict] = {}
    for logical_id, resource in resources.items():
        if not isinstance(resource, dict):
            continue
        if resource.get("Type") == "AWS::EC2::SecurityGroup":
            groups[logical_id] = resource.get("Properties", {})
    return groups


def _ensure_list(value: object) -> List[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, (str, int)):
        return [str(value)]
    return []


def _evaluate_subnet(
    subnet_id: str,
    lambda_id: str,
    subnets: Dict[str, dict],
    route_tables: Dict[str, dict],
    associations: Dict[str, str],
) -> Optional[VpcIssue]:
    properties = subnets.get(subnet_id)
    if properties is None:
        return None

    # Identify associated route table routes.
    route_table_id = associations.get(subnet_id) or associations.get(subnet_id.split("/")[-1])
    routes = _extract_routes(route_tables, route_table_id)

    for route in routes:
        if _route_to_internet(route):
            description = (
                "Subnet associated with internet gateway; Lambda traffic can reach the public internet."
            )
            return VpcIssue(
                severity=Severity.HIGH,
                description=description,
                resource=lambda_id,
                path=f"Subnets.{subnet_id}",
                snippet=json.dumps(route, indent=2, sort_keys=True),
            )
        if _route_through_nat(route):
            description = (
                "Subnet routed through NAT gateway allowing unrestricted outbound access."
            )
            return VpcIssue(
                severity=Severity.MEDIUM,
                description=description,
                resource=lambda_id,
                path=f"Subnets.{subnet_id}",
                snippet=json.dumps(route, indent=2, sort_keys=True),
            )
    return None


def _extract_routes(route_tables: Dict[str, dict], route_table_id: Optional[str]) -> List[dict]:
    if not route_table_id:
        return []
    table = route_tables.get(route_table_id) or route_tables.get(str(route_table_id))
    if not isinstance(table, dict):
        return []
    routes = []
    inline_routes = table.get("Routes")
    if isinstance(inline_routes, list):
        routes.extend(route for route in inline_routes if isinstance(route, dict))
    return routes


def _route_to_internet(route: dict) -> bool:
    destination = str(route.get("DestinationCidrBlock", "")).strip()
    target = str(route.get("GatewayId", "")).lower()
    return destination in {INTERNET_CIDR_V4, INTERNET_CIDR_V6} and _is_internet_gateway(target)


def _route_through_nat(route: dict) -> bool:
    destination = str(route.get("DestinationCidrBlock", "")).strip()
    target = str(route.get("NatGatewayId", "")).lower()
    return destination == INTERNET_CIDR_V4 and any(tag in target for tag in TARGET_NAT)


def _is_internet_gateway(target: str) -> bool:
    return any(tag in target for tag in TARGET_INTERNET)


def _evaluate_security_group(
    security_group_id: str,
    lambda_id: str,
    groups: Dict[str, dict],
) -> Optional[VpcIssue]:
    properties = groups.get(security_group_id)
    if properties is None:
        return None
    egress_rules = properties.get("SecurityGroupEgress") or []
    if not isinstance(egress_rules, list):
        return None

    for rule in egress_rules:
        if not isinstance(rule, dict):
            continue
        if _is_any_egress(rule):
            return VpcIssue(
                severity=Severity.HIGH,
                description="Security group allows unrestricted egress to the internet.",
                resource=lambda_id,
                path=f"SecurityGroup.{security_group_id}",
                snippet=json.dumps(rule, indent=2, sort_keys=True),
            )
    return None


def _is_any_egress(rule: dict) -> bool:
    cidr_ipv4 = str(rule.get("CidrIp", "")).strip()
    cidr_ipv6 = str(rule.get("CidrIpv6", "")).strip()
    ip_protocol = str(rule.get("IpProtocol", "")).strip()
    from_port = rule.get("FromPort")
    to_port = rule.get("ToPort")

    any_cidr = cidr_ipv4 == INTERNET_CIDR_V4 or cidr_ipv6 == INTERNET_CIDR_V6
    any_protocol = ip_protocol in {ANY_PROTOCOL, "-1"}
    any_port = (from_port in {ANY_PORT, None} or from_port == -1) and (
        to_port in {ANY_PORT, None} or to_port == -1
    )
    return any_cidr and any_protocol and any_port


def _build_finding(issue: VpcIssue, counter: int) -> Finding:
    return Finding(
        rule_id=f"VPC{counter:03d}",
        description=f"{issue.description} @ {issue.path}\n{issue.snippet}",
        severity=issue.severity,
        resource_id=issue.resource,
        remediation=(
            RECOMMENDATION
            + " Consider VPC endpoints for Secrets Manager/SSM where appropriate and whitelist outbound traffic."
        ),
    )
