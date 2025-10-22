"""Tests for the VPC egress guardrail."""
from __future__ import annotations

from scanner.rules import vpc_egress
from scanner.severity import Severity


def test_detects_public_subnet_lambda(tmp_path) -> None:
    template = tmp_path / "template.yaml"
    template.write_text(
        """
Resources:
  LambdaFunction:
    Type: AWS::Serverless::Function
    Properties:
      Handler: index.handler
      Runtime: python3.11
      VpcConfig:
        SubnetIds:
          - PublicSubnet
        SecurityGroupIds:
          - LambdaSG
  PublicSubnet:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: vpc-1234
  RouteTable:
    Type: AWS::EC2::RouteTable
    Properties:
      VpcId: vpc-1234
      Routes:
        - DestinationCidrBlock: 0.0.0.0/0
          GatewayId: igw-abcdef
  Association:
    Type: AWS::EC2::SubnetRouteTableAssociation
    Properties:
      SubnetId: PublicSubnet
      RouteTableId: RouteTable
  LambdaSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Lambda security group
      SecurityGroupEgress:
        - IpProtocol: -1
          FromPort: -1
          ToPort: -1
          CidrIp: 0.0.0.0/0
        """,
        encoding="utf-8",
    )

    findings = vpc_egress.scan(template_path=str(template))
    severities = {finding.severity for finding in findings}
    assert Severity.HIGH in severities
    ids = {finding.rule_id for finding in findings}
    assert any(rule.startswith("VPC") for rule in ids)


def test_detects_open_security_group(tmp_path) -> None:
    template = tmp_path / "template.yaml"
    template.write_text(
        """
Resources:
  LambdaFunction:
    Type: AWS::Serverless::Function
    Properties:
      Handler: index.handler
      Runtime: python3.11
      VpcConfig:
        SubnetIds:
          - PrivateSubnet
        SecurityGroupIds:
          - OpenEgress
  PrivateSubnet:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: vpc-2345
  RtPrivate:
    Type: AWS::EC2::RouteTable
    Properties:
      VpcId: vpc-2345
      Routes:
        - DestinationCidrBlock: 0.0.0.0/0
          NatGatewayId: nat-xyz
  Association:
    Type: AWS::EC2::SubnetRouteTableAssociation
    Properties:
      SubnetId: PrivateSubnet
      RouteTableId: RtPrivate
  OpenEgress:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Wide open egress
      SecurityGroupEgress:
        - IpProtocol: -1
          FromPort: -1
          ToPort: -1
          CidrIp: 0.0.0.0/0
        """,
        encoding="utf-8",
    )

    findings = vpc_egress.scan(template_path=str(template))
    assert findings, "Expected findings for NAT + open SG egress"
    assert any(f.severity is Severity.MEDIUM for f in findings)
    assert any(f.severity is Severity.HIGH for f in findings)
