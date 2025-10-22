"""Command-line interface orchestrating rule execution."""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from .result import Finding, ScanResult
from .rules import env_secret, iam_leastpriv, vpc_egress

LOGGER = logging.getLogger("scanner")

RuleInvoker = Callable[[Optional[str], Optional[str]], Sequence[Finding]]
RULES: Sequence[Tuple[str, RuleInvoker]] = (
    (
        "env_secret",
        lambda template, source: env_secret.scan(
            template_path=template,
            source_path=source,
        ),
    ),
    ("iam_leastpriv", lambda template, _: iam_leastpriv.scan(template_path=template)),
    ("vpc_egress", lambda template, _: vpc_egress.scan(template_path=template)),
)


def _configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )


def _parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Serverless guardrails scanner")
    parser.add_argument("--template", help="Path to SAM/CloudFormation template", required=False)
    parser.add_argument("--source", help="Path to Lambda source directory for code analysis", required=False)
    parser.add_argument("--format", choices=["json", "text"], default="text", help="Output format")
    parser.add_argument("--out", help="Optional JSON output file path")
    parser.add_argument("--fail-on", default="MEDIUM", help="(Deprecated) maintained for compatibility")
    parser.add_argument("--dry-run", action="store_true", help="Run without writing outputs")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--json", action="store_true", help="Shortcut for --format json")
    return parser.parse_args(list(argv))


def _render_summary_table(summary: Dict[str, int], passed: bool) -> str:
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    header = "Severity | Count"
    separator = "---------+-------"
    rows = [header, separator]
    for severity in order:
        rows.append(f"{severity:<8} | {summary.get(severity, 0):>5}")
    rows.append(separator)
    rows.append(f"{'TOTAL':<8} | {summary.get('TOTAL', 0):>5}")
    rows.append("")
    rows.append(f"Result: {'PASSED' if passed else 'FAILED'}")
    return "\n".join(rows)


def _determine_exit_code(summary: Dict[str, int]) -> int:
    if summary.get("CRITICAL", 0) > 0 or summary.get("HIGH", 0) > 0:
        return 2
    if summary.get("MEDIUM", 0) > 0:
        return 1
    return 0


def _execute_rules(template: Optional[str], source: Optional[str]) -> List[Finding]:
    findings: List[Finding] = []
    for name, invoker in RULES:
        try:
            produced = list(invoker(template, source))
            LOGGER.debug("Rule %s produced %d findings", name, len(produced))
            findings.extend(produced)
        except Exception as exc:  # pragma: no cover - defensive logging
            LOGGER.error("Rule %s failed: %s", name, exc)
    return findings


def run_cli(argv: Iterable[str] | None = None) -> None:
    args = _parse_args(argv or sys.argv[1:])
    if args.json:
        args.format = "json"
    _configure_logging(args.verbose)

    LOGGER.debug("CLI arguments parsed: %s", args)
    template = args.template
    source = args.source

    findings = _execute_rules(template, source)
    scan_result = ScanResult(findings=findings)

    if args.out and not args.dry_run:
        output_path = Path(args.out).expanduser().resolve()
        scan_result.to_json(str(output_path))
        LOGGER.info("Results written to %s", output_path)

    if args.format == "json":
        payload = scan_result.to_json(None)
        print(payload)
    else:
        table = _render_summary_table(scan_result.summary, scan_result.passed)
        print(table)

    exit_code = _determine_exit_code(scan_result.summary)
    if exit_code != 0:
        LOGGER.info("Scan failed with exit code %d", exit_code)
    sys.exit(exit_code)
