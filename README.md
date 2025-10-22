# CloudTrail Threat-Hunt Kit
> **Serverless Guardrails** — AWS CloudTrail∙Serverless 워크로드에 대한 보안 스캐닝 & 파이프라인 게이팅 툴킷

**태그라인:** *“CloudTrail 로그와 IaC·Lambda 아티팩트를 한 번에 스캔하여 위험 변화를 즉시 차단하세요.”*

## 목차
- [프로젝트 소개](#프로젝트-소개)
- [한눈에 보는 핵심 기능](#한눈에-보는-핵심-기능)
- [빠른 시작](#빠른-시작quick-start)
- [구성 및 설정 설명](#구성-및-설정-설명)
- [아키텍처 개요](#아키텍처-개요)
- [운영(운영자) 섹션](#운영운영자-섹션)
- [CI/CD 통합 가이드](#cicd-통합-가이드)
- [보안·컴플라이언스](#보안컴플라이언스)
- [기여 가이드](#기여-가이드)
- [테스트 및 검증](#테스트-및-검증)
- [FAQ](#faq)
- [변경 이력/릴리스 안내](#변경-이력릴리스-안내)
- [라이선스](#라이선스)
- [연락처/지원](#연락처지원)
- [샘플 scan.json 결과](#샘플-scanjson-결과)

---

## 프로젝트 소개
- **문제 정의:** CloudTrail 이벤트·서버리스(IaC/Lambda) 변경이 빠르게 누적되면서, 하드코딩된 시크릿·과도한 IAM 권한·VPC egress 리스크가 파이프라인을 통해 그대로 배포될 수 있습니다.
- **주요 기능:** Python 기반 `scanner` CLI, Athena/Glue 쿼리팩, CodeBuild/CodePipeline 게이팅, Streamlit 대시보드, Pre/Post Deploy Lambda Hook.
- **기대 효과:** 비정상 행위 조기 탐지(의심 리전 로그인, 신규 액세스 키, IAM wildcard), 배포 차단/수동 승인, 운영자 가시성 확보(`artifacts/scan.json` + 대시보드).
- **통합 시나리오:** 개발자 커밋 → 파이프라인 스캔 → 위험 시 차단 후 승인 요청 → 안전 검증 후 프로덕션 반영.
- **보안 준수:** NIST SP 800-53, ISO/IEC 27001, AWS Well-Architected Security Pillar에 맞춘 가드레일 제안.

## 한눈에 보는 핵심 기능
| 영역 | 기능 | 설명 |
|------|------|------|
| 스캐너 | `python -m scanner` | SAM/CloudFormation + Lambda 코드에서 시크릿, IAM, VPC 위험 탐지 |
| 로그 분석 | Athena/Glue Query Pack | CloudTrail S3 로그를 대상으로 의심 이벤트 쿼리 |
| 파이프라인 | CodeBuild + CodePipeline | 스캔 실패 시 Deploy 단계 차단, Manual Approval Gate |
| 훅(Hook) | Pre/Post Deploy Lambda | ChangeSet 사전 검증 및 배포 후 자원 상태 점검 |
| 시각화 | Streamlit 대시보드 | scan.json·Athena 결과를 위젯으로 시각화 (선택 구성) |

## 빠른 시작(Quick Start)
> **⚠️ 비밀값 금지:** `.env`나 환경 변수에 실제 키를 기록하지 말고, *항상* `.env.example`를 복사하여 더미 값으로 채운 뒤 실환경에서는 안전한 Secret Manager를 사용하세요.

```bash
# 1) 가상환경
python3.11 -m venv .venv && source .venv/bin/activate

# 2) 의존성 설치
pip install --upgrade pip
pip install -r requirements.txt

# 3) 환경 변수 기본 템플릿
cp .env.example .env  # 필요한 값만 안전하게 채우고, Git에 커밋 금지

# 4) 로컬 스캔 (취약 버전)
python -m scanner \
  --template templates/app-sam.yaml \
  --source functions/vulnerable \
  --format json \
  --out artifacts/scan.json
echo $?  # 2 → HIGH/CRITICAL 발견으로 실패

# 5) 로컬 스캔 (안전 버전)
python -m scanner \
  --template templates/app-sam.yaml \
  --source functions/safe \
  --format json \
  --out artifacts/scan_safe.json
echo $?  # 0 → 통과

# 6) 테스트
pytest -q

# 7) (옵션) SAM 빌드/배포 — 실제 배포 전 권한 주의
sam build
sam deploy --guided  # StackName=serverless-guardrails-demo
sam delete           # 정리
```

**Makefile 단축 명령** (상세 내용은 아래 [Makefile](#makefile) 참고):
```bash
make up         # 가상환경 + 의존성 설치
make scan       # 기본 취약 스캔 실행
make test       # pytest
make deploy     # sam build && sam deploy --guided
```

---

## 구성 및 설정 설명
### `.env.example`
- `ATHENA_DATABASE`, `ATHENA_OUTPUT_BUCKET`, `STREAMLIT_PORT` 등 로컬 개발용 더미 키 제공.
- 운영환경에서는 AWS Secrets Manager / SSM Parameter Store로 *자동 주입*을 권장합니다.

### `.guardrails-allow.json`
예외 허용 정책:
```json
{
  "allowlist": [
    {
      "id": "ENV_TEMP_001",
      "rule_id": "ENV_SECRET_001",
      "resource_id": "functions/safe/app.py",
      "env_names": ["TEMP_TOKEN"],
      "reason": "QA 환경 임시 토큰",
      "expires_at": "2025-12-31T00:00:00Z",
      "created_by": "security-team"
    }
  ]
}
```
- **`expires_at` 필수** (ISO8601). 만료 시 빌드 실패 → 즉시 제거 또는 연장 업데이트.
- Pull Request 설명에 예외 사유 명시.

### IAM 최소 권한 스니펫
스캐너 실행/아티팩트 저장을 위한 최소 정책 예시 (placeholder ARN 사용):
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadTemplatesAndCode",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::<YOUR_ARTIFACT_BUCKET>",
        "arn:aws:s3:::<YOUR_ARTIFACT_BUCKET>/*"
      ]
    },
    {
      "Sid": "PublishLogs",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "*"
    }
  ]
}
```
> 주석: 배포 계정에서 CloudFormation `Create/UpdateStack` 권한이 추가로 필요하며, 필요 시 리소스 수준 ARN으로 범위를 축소하세요.

---

## 아키텍처 개요
```mermaid
flowchart LR
    CT[CloudTrail S3 Logs] -->|Glue Catalog| Athena[Amazon Athena Query Pack]
    Athena -->|findings| ScannerCLI[Scanner CLI (Python)]
    ScannerCLI -->|scan.json| CodeBuild
    CodeBuild --> CodePipeline
    CodePipeline -->|Manual Approval| Deploy[CloudFormation Deploy]
    CodePipeline --> PreHook[Lambda Pre-Deploy Hook]
    Deploy --> PostHook[Lambda Post-Deploy Hook]
    ScannerCLI -->|metrics| Streamlit[Streamlit Dashboard]
```
- **CloudTrail S3 → Athena/Glue:** 표준 쿼리팩으로 의심 이벤트 추출.
- **Scanner CLI:** IaC/Lambda를 정적 분석하여 `artifacts/scan.json` 생성.
- **CodePipeline:** 빌드 → 스캔 → (옵션) Manual Approval → Deploy.
- **Hooks:** Pre-Deploy는 ChangeSet 확인, Post-Deploy는 실제 리소스 검증.
- **Streamlit:** 운영자가 scan.json/Athena 결과를 시각화.

---

## 운영(운영자) 섹션
- **로그 위치:** 
  - CloudWatch Logs: `/aws/codebuild/cloudtrail-guardrails` (CodeBuild), `/aws/lambda/guardrails-prehook`, `/aws/lambda/guardrails-posthook`.
  - 파일: `artifacts/scan.json`, `artifacts/scan_safe.json`.
- **헬스체크 지표:** `HighRiskChanges` (CloudWatch Metric), `scan_exit_code`.
- **모니터링/알람:** CloudWatch Alarm → SNS `<your-ops-topic>` (CRITICAL/HIGH 발생 시).
- **장애 복구 절차:** 
  1. 파이프라인 중단 확인 (CodePipeline 콘솔).  
  2. `artifacts/scan.json` 분석 → 원인 리소스 파악.  
  3. IaC 수정 또는 예외 승인(만료일 필수) → 재실행.  
  4. 필요 시 `sam delete`로 환경 초기화.  

**운영 워크플로우 예시 — “리전 외부 로그인 탐지”:**
1. Athena 쿼리가 `<untrusted-region>` 로그인 이벤트 탐지.  
2. Scanner CLI가 해당 사용자 액세스 키 생성 기록도 식별 → CRITICAL.  
3. CodePipeline 스캔 실패 → Manual Approval에 상세 코멘트 첨부.  
4. 운영팀: CloudTrail/Athena 세부 로그 조사 → 키 즉시 폐기 → IAM 비밀번호 재설정.  
5. 재발 방지를 위한 `iam_leastpriv` 룰 개선 및 사용자 교육.

---

## CI/CD 통합 가이드
- **CodeBuild buildspec**: [buildspec.yml 예시](#buildspecyml-예시) 참고 — pytest → scanner 실행 → `artifacts/scan.json`.
- **CodePipeline**: 
  - Build 단계 실패 시 Deploy 단계 진입 차단.
  - Approval 단계에서 scan.json 상위 10개 Finding 요약 코멘트 제공 (Lambda Hook 또는 자동화 스크립트 활용).
  - PreDeployHook은 IAM/VPC 고위험 변경 감지 시 `RuntimeError`로 파이프라인 중단.
  - PostDeployHook은 CFN Describe API로 실제 상태 검증 후 경고 로깅.

---

## 보안·컴플라이언스
- **최소 권한:** `Least Privilege` 정책 준수, 함수별 IAM Role 분리, VPC 엔드포인트 사용 권장.
- **시크릿 관리:** AWS Secrets Manager / SSM Parameter Store 사용, `.env`는 로컬 개발용 더미.
- **로그 보존:** CloudTrail 최소 90일, 권장 365일 이상 Glacier/CloudWatch Logs 보관.
- **데이터 분류:** CloudTrail 로그 = 내부 기밀(Internal). Streamlit 대시보드는 VPN 또는 사내 망으로 제한.
- **취약점 신고:** [SECURITY.md](SECURITY.md) 문서 참고. `security@example.com` 으로 PGP 암호화 후 제보 권장.
- **히스토리에 노출된 키 처리:** (1) 즉시 키 폐기 → (2) `git filter-repo` 또는 BFG 로 삭제 → (3) Force push → (4) 협업자 공지 및 키 교체 시행.

---

## 기여 가이드
- 브랜치 전략: `main` 보호, 기능별 `feature/<name>`, 핫픽스는 `hotfix/<name>`.
- 커밋 메시지: [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `chore:` 등).
- PR 필수 체크리스트: `pytest`, scan 결과, 문서(README/DEMO) 업데이트, `.guardrails-allow.json` 변경 시 만료일/사유 기재.
- 상세 절차: [CONTRIBUTING.md](CONTRIBUTING.md) 참고.

---

## 테스트 및 검증
```bash
pytest -q
```
샘플 시나리오:
1. **하드코딩 시크릿** → `ENV_SECRET` 룰 트리거, scan.json의 severity=HIGH, `rule_id=ENV001`.
2. **IAM wildcard** → `iam_leastpriv` 룰 CRITICAL.
3. **VPC egress open** → `vpc_egress` 룰 HIGH/MEDIUM.

`artifacts/scan.json` 구조:
```json
{
  "summary": { "CRITICAL": 1, "HIGH": 2, "MEDIUM": 1, "LOW": 0, "INFO": 0, "TOTAL": 4 },
  "passed": false,
  "findings": [
    {
      "rule_id": "IAM001",
      "severity": "CRITICAL",
      "resource_id": "VulnerableFunctionRole",
      "description": "...",
      "remediation": "..."
    }
  ]
}
```

---

## FAQ
1. **Q:** Guardrails 예외는 어떻게 신청하나요?  
   **A:** `.guardrails-allow.json`에 항목 추가(만료일 필수) → PR 설명에 사유 작성 → 보안 승인 후 병합.
2. **Q:** scan.json을 다른 보안 도구와 연동할 수 있나요?  
   **A:** JSON 포맷은 SARIF 변환이 용이하며, GitHub Code Scanning 업로드를 권장합니다.
3. **Q:** Streamlit 대시보드는 반드시 사용해야 하나요?  
   **A:** 선택 사항입니다. 내부 보안 모니터링 포털과 연동하거나 CloudWatch 대시보드로 대체 가능합니다.

---

## 변경 이력/릴리스 안내
- [CHANGELOG.md](CHANGELOG.md) 참조 — 가드레일 규칙 추가/변경 사항 기록.

## 라이선스
- 프로젝트 라이선스: [LICENSE](LICENSE) 참조 (예: Apache-2.0).
- 기업 내 배포 시 라이선스 조항 준수 필수.

## 연락처/지원
- 일반 문의: `devrel@example.com`
- 보안 취약점 신고: `security@example.com` (PGP 사용 권장). 자세한 절차는 [SECURITY.md](SECURITY.md) 참고.

---

## 샘플 scan.json 결과
```json
{
  "summary": {
    "CRITICAL": 1,
    "HIGH": 2,
    "MEDIUM": 2,
    "LOW": 0,
    "INFO": 1,
    "TOTAL": 6
  },
  "passed": false,
  "findings": [
    {
      "rule_id": "IAM001",
      "severity": "CRITICAL",
      "resource_id": "VulnerableFunctionRole",
      "description": "Wildcard action scope detected (resource VulnerableFunctionRole) @ Resources.VulnerableFunctionRole.Properties.Policies[0].PolicyDocument.Statement[0]",
      "remediation": "Enforce least privilege per NIST SP 800-53 AC-6 / ISO 27001 A.9. Restrict actions/resources and apply Conditions where applicable."
    },
    {
      "rule_id": "VPC001",
      "severity": "HIGH",
      "resource_id": "VulnerableFunction",
      "description": "Subnet associated with internet gateway; Lambda traffic can reach the public internet. @ Subnets.PublicSubnet",
      "remediation": "Restrict egress by using VPC endpoints, scoped security group rules, and network firewalls. Consider VPC endpoints for Secrets Manager/SSM where appropriate and whitelist outbound traffic."
    },
    {
      "rule_id": "ENV002",
      "severity": "HIGH",
      "resource_id": "templates/app-sam.yaml",
      "description": "High-risk secret detected for 'API_KEY' (Resources.VulnerableFunction.Properties.Environment.Variables.API_KEY)",
      "remediation": "Store this value in AWS Secrets Manager or AWS Systems Manager Parameter Store and reference it at runtime instead of hardcoding it."
    },
    {
      "rule_id": "ENV003",
      "severity": "MEDIUM",
      "resource_id": "functions/vulnerable/app.py",
      "description": "Potential secret literal in code (functions/vulnerable/app.py:7)",
      "remediation": "Store this value in AWS Secrets Manager or AWS Systems Manager Parameter Store and reference it at runtime instead of hardcoding it."
    },
    {
      "rule_id": "ATH001",
      "severity": "MEDIUM",
      "resource_id": "athena/query/access_key_rotation.sql",
      "description": "Athena query flagged new access key creation from unusual IP range.",
      "remediation": "Validate the IAM user activity and revoke unused keys."
    },
    {
      "rule_id": "OBS001",
      "severity": "INFO",
      "resource_id": "streamlit/dashboard.py",
      "description": "Dashboard ready to ingest scan.json artifacts.",
      "remediation": "None."
    }
  ]
}
```
