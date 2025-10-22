# Guardrails Demo Walkthrough

## 1. Architecture Overview
```mermaid
graph TD
    Developer[Developer Commit]
    Repo[(Git Repository)]
    Pipeline[CodePipeline]
    Build[CodeBuild Static Scan]
    Approval[Manual Approval]
    Deploy[CloudFormation Deploy]
    Hooks[Pre/Post Deploy Hooks]
    Stack[(Serverless
    Stack)]

    Developer --> Repo
    Repo --> Pipeline
    Pipeline --> Build
    Build -->|scan.json| Approval
    Approval -->|approve| Deploy
    Deploy --> Hooks
    Hooks --> Stack
    Build -.scan.json artifacts.-> Pipeline
```

## 2. Local Scan Procedure
```bash
python -m scanner \
  --template templates/app-sam.yaml \
  --source functions/vulnerable \
  --format json \
  --out artifacts/scan.json
```

Sample failure output:
```json
{
  "findings": [
    {
      "description": "High-risk secret detected for 'API_KEY' (Resources.VulnerableFunction.Properties.Environment.Variables.API_KEY)",
      "remediation": "Store this value in AWS Secrets Manager or AWS Systems Manager Parameter Store and reference it at runtime instead of hardcoding it.",
      "resource_id": "templates/app-sam.yaml",
      "rule_id": "ENV001",
      "severity": "HIGH"
    }
  ],
  "passed": false,
  "summary": {
    "CRITICAL": 1,
    "HIGH": 2,
    "INFO": 0,
    "LOW": 0,
    "MEDIUM": 3,
    "TOTAL": 6
  }
}
```

Exit code check:
```bash
echo $?
# 2 (blocked by HIGH finding)
```

## 3. Pipeline Demonstration
- **Failing run:** push the vulnerable sample; CodeBuild stage exits non-zero, approval stage is skipped, and the pipeline stops with the scan summary in logs.
- **Passing run:** fix to the safe variant, push, pipeline runs scan → approval gating (top findings posted) → reviewer approves → CloudFormation deploys successfully.

Example CodeBuild log excerpt:
```
[Container] python -m scanner --template templates/app-sam.yaml --source functions/vulnerable ...
[Container] Exit code 2 - severity threshold exceeded
```

Manual approval comment (sample):
```
Scan Summary (top 3)
- ENV001 | HIGH | templates/app-sam.yaml | Remove hardcoded API_KEY
- IAM001 | CRITICAL | VulnerableFunctionRole | Replace s3:* wildcard
- VPC001 | HIGH | VulnerableFunction | Restrict public egress
```

## 4. scan.json Comparison
| Scenario   | CRITICAL | HIGH | MEDIUM | Passed |
|-----------|----------|------|--------|--------|
| Vulnerable| 1        | 2    | 3      | false  |
| Safe      | 0        | 0    | 0      | true   |

## 5. Security Control Mapping
- **NIST SP 800-53:** AC-6 (least privilege), SC-7 (boundary protection), SA-11 (developer security testing), CM-3 (configuration change control)
- **ISO/IEC 27001:** A.9 (access control), A.12.6 (technical vulnerability management), A.14 (system acquisition, development, maintenance)
- **AWS Well-Architected – Security Pillar:** Identity & Access Management, Infrastructure Protection, Detection

## 6. Limitations & Future Enhancements
- Static analysis only; dynamic runtime or data flow not evaluated.
- Intrinsic functions and cross-stack references partially supported. Complex change sets may require manual review.
- Future ideas: integrate Bandit/cfn-lint, export SARIF for code scanning, ChatOps/PR comment bots, automated exception workflows.

## 7. Local Checklist
- [ ] `python -m venv .venv && source .venv/bin/activate`
- [ ] `pip install -r requirements.txt`
- [ ] Run vulnerable scan (expect failure, verify `echo $?` > 0)
- [ ] Run safe scan `python -m scanner --template templates/app-sam.yaml --source functions/safe --format json` (expect pass)
- [ ] *(Optional)* `sam build && sam deploy --guided` (`serverless-guardrails-demo`)
- [ ] `sam delete` to clean up demo resources
