"""Command line interface for pyregexshield."""

from __future__ import annotations

import argparse
import json
import re
import sys

from ._display import terminal_safe
from .analyzer import analyze_regex
from .policy import DEFAULT_POLICY
from .scanner import scan_directory


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pyregexshield",
        description="Static ReDoS analysis and safe regex compilation checks",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    check = subparsers.add_parser("check", help="analyze one regex pattern")
    check.add_argument("pattern", help="regex pattern to analyze")
    check.add_argument("--ignorecase", action="store_true", help="enable re.IGNORECASE")
    check.add_argument("--dotall", action="store_true", help="enable re.DOTALL")
    check.add_argument("--multiline", action="store_true", help="enable re.MULTILINE")
    check.add_argument("--verbose", action="store_true", help="enable re.VERBOSE")
    check.add_argument("--ascii", action="store_true", help="enable re.ASCII")
    check.add_argument("--strict", action="store_true", help="treat low severity findings as unsafe")
    check.add_argument("--json", action="store_true", help="emit machine readable JSON")

    scan = subparsers.add_parser("scan", help="scan Python source files")
    scan.add_argument("path", help="Python file or directory to scan")
    scan.add_argument("--format", choices=("text", "json", "sarif"), default="text", help="output format")
    scan.add_argument("--strict", action="store_true", help="treat low severity findings as unsafe")
    scan.add_argument("--max-files", type=int, default=10000, help="maximum Python files to scan")
    return parser


def _check_flags(args) -> int:
    flags = 0
    if args.ignorecase:
        flags |= re.IGNORECASE
    if args.dotall:
        flags |= re.DOTALL
    if args.multiline:
        flags |= re.MULTILINE
    if args.verbose:
        flags |= re.VERBOSE
    if args.ascii:
        flags |= re.ASCII
    return flags


def _check_command(args) -> int:
    policy = DEFAULT_POLICY.strict() if args.strict else DEFAULT_POLICY
    result = analyze_regex(args.pattern, flags=_check_flags(args), policy=policy)
    syntax_error = any(finding.code == "REDOS_SYNTAX_ERROR" for finding in result.findings)

    if args.json:
        payload = {
            "pattern": args.pattern,
            "safe": result.safe,
            "risk_level": result.risk_level,
            "score": result.score,
            "attack_hint": result.attack_hint,
            "stats": dict(result.stats),
            "findings": [
                {
                    "code": finding.code,
                    "severity": finding.severity,
                    "message": finding.message,
                    "span": list(finding.span),
                    "remediation": finding.remediation,
                }
                for finding in result.findings
            ],
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        display_pattern = terminal_safe(args.pattern)
        if result.safe:
            print("SAFE %s (risk %s, score %d)" % (display_pattern, result.risk_level, result.score))
        else:
            print("UNSAFE %s (risk %s, score %d)" % (display_pattern, result.risk_level, result.score))
        for finding in result.findings:
            print(
                "  %s %s at %d..%d: %s" % (
                    finding.severity,
                    finding.code,
                    finding.span[0],
                    finding.span[1],
                    finding.message,
                )
            )
            print("    fix: %s" % finding.remediation)
        if result.attack_hint and not result.safe:
            print("  attack hint: %s" % result.attack_hint)

    if syntax_error:
        return 2
    return 0 if result.safe else 1


def _scan_command(args) -> int:
    if args.max_files < 1:
        print("pyregexshield scan: --max-files must be positive", file=sys.stderr)
        return 2
    policy = DEFAULT_POLICY.strict() if args.strict else DEFAULT_POLICY
    try:
        report = scan_directory(args.path, policy=policy, strict=False, max_files=args.max_files)
    except (OSError, ValueError) as error:
        print("pyregexshield scan: %s" % terminal_safe(error), file=sys.stderr)
        return 2

    if args.format == "json":
        print(report.to_json())
    elif args.format == "sarif":
        print(report.sarif_json())
    else:
        print(report.to_text())
    return 1 if report.blocking_findings(policy) else 0


def main(argv=None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "check":
        return _check_command(args)
    if args.command == "scan":
        return _scan_command(args)
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
