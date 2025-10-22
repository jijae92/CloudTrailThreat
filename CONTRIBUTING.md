# Contributing Guide

## Branch Strategy
- `main`: 보호 브랜치, 직접 커밋 금지.
- `feature/<topic>`: 신규 기능 작업.
- `hotfix/<issue>`: 긴급 수정.
- 릴리스 브랜치 필요 시 `release/<version>`.

## Pull Request Workflow
1. `pytest -q` 및 `python -m scanner ...` 실행 결과 첨부.
2. `.guardrails-allow.json` 변경 시 사유·만료일 명시.
3. README/DEMO 문서가 최신 상태인지 확인.
4. 최소 1명 이상의 보안 리뷰 승인 필요.

## Commit Message 스타일
- [Conventional Commits](https://www.conventionalcommits.org/) 규칙:
  - 예) `feat(scanner): add new iam wildcard detector`
  - `fix`, `chore`, `docs`, `refactor`, `test` 등 카테고리 사용.

## PR Template (요약)
```
## Summary
- 

## Testing
- [ ] pytest
- [ ] scanner (template=..., source=...)

## Impact
- 

## Allowlist Changes
- [ ] N/A
- 상세:
```
