# Serverless Guardrails Skeleton

## Overview
Serverless Guardrails provides a reproducible scaffold for enforcing security controls on AWS Lambda and SAM/CloudFormation workloads. It combines static scanning, pipeline gates, and manual approval workflows to prevent risky changes from reaching production.

## Quick Start
1. Clone the repository and create a Python 3.11 virtualenv.
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```
2. Run the scanner against the vulnerable sample (expected failure).
   ```bash
   python -m scanner --template templates/app-sam.yaml --source functions/vulnerable --format json --out artifacts/scan.json
   echo $?  # 2
   cat artifacts/scan.json
   ```
3. Run the scanner against the safe sample (expected pass).
   ```bash
   python -m scanner --template templates/app-sam.yaml --source functions/safe --format json
   ```
4. (Optional) Package/deploy with SAM.
   ```bash
   sam build
   sam deploy --guided  # stack name: serverless-guardrails-demo
   sam delete
   ```

## Pipeline Integration
- Deploy `pipeline/sam-pipeline/pipeline_template.yaml` using `sam deploy` with repository parameters.
- CodeBuild uses `pipeline/buildspec.yml` to execute tests and static scans; artifacts include `scan.json` for manual review.
- Manual approval stage references top findings; add Lambda hooks (`functions/hooks/*`) for pre-/post-deploy validation if required.

## Definition of Done & CI Rules
- ✅ `pytest` suite must pass with ≥90% tests executed and ≥80% coverage.
- 🚫 Pull requests containing CRITICAL or HIGH findings may not merge.
- 🔒 `main` branch protected; all deployments occur via pull requests.
- 🤖 Pull request creation triggers automatic scan with a summary comment:
  ```
  Guardrails Scan Summary:
  - {RuleId} | {Severity} | {ResourceId} | {Recommendation}
  ```
- 📝 Exceptions managed via `.guardrails-allow.json`; entries require `env_names` (or resource identifiers) and an `expires_at` ISO timestamp. Expired exceptions fail the build.

## .guardrails-allow.json Usage
```json
{
  "allowlist": [
    {
      "rule_id": "ENV_SECRET_001",
      "resource_id": "path/to/file.py",
      "env_names": ["TEMP_TOKEN"],
      "expires_at": "2025-12-31T00:00:00Z",
      "reason": "Temporary integration test secret"
    }
  ]
}
```
Keep the allowlist small, document the justification, and ensure CI jobs alert when the expiration date is reached.

## Project Layout
```
scanner/       # CLI, result handling, and rules
functions/     # Vulnerable + safe Lambda examples and hook stubs
pipeline/      # CodeBuild buildspec and CodePipeline SAM template
templates/     # SAM application template with contrasting deployments
tests/         # pytest suites covering rules and scenarios
docs/          # README, DEMO walkthrough, supplementary docs
```

## Security Mapping & Limitations
- Controls: NIST SP 800-53 (AC-6, SC-7, SA-11, CM-3), ISO/IEC 27001 (A.9, A.12.6, A.14), AWS Well-Architected Security Pillar.
- Static analysis limitations: intrinsic functions, dynamic references, and runtime configurations may escape detection. Integrate additional tooling (cfn-lint, Bandit) and SARIF exports for richer insights.

## Contributing
- Fork, branch, and run `pytest` locally before submitting PRs.
- Use `.guardrails-allow.json` for temporary exceptions with clear expiry.
- Ensure pipeline parameters configured in `pipeline/sam-pipeline/pipeline_template.yaml` prior to deployment.

Refer to `docs/DEMO.md` for a guided walkthrough of vulnerable vs. safe runs and pipeline behavior.
