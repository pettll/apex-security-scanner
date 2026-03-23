"""CLI entry point."""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
from .scanner import scan_directory, scan_file, severity_exit_code
from .rules import Severity


SEVERITY_COLOURS = {
    Severity.CRITICAL: "\033[91m",
    Severity.HIGH:     "\033[93m",
    Severity.MEDIUM:   "\033[94m",
    Severity.LOW:      "\033[92m",
}
RESET = "\033[0m"


def _colour(text: str, severity: Severity, use_colour: bool) -> str:
    if not use_colour:
        return text
    return f"{SEVERITY_COLOURS[severity]}{text}{RESET}"


def run() -> None:
    parser = argparse.ArgumentParser(
        prog="apex-scan",
        description="OWASP-based static security scanner for Salesforce Apex code.",
    )
    parser.add_argument("path", help="Apex .cls file or directory to scan")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--min-severity", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], default="LOW")
    parser.add_argument("--no-colour", action="store_true")
    args = parser.parse_args()

    target = Path(args.path)
    use_colour = not args.no_colour and sys.stdout.isatty()

    if target.is_file():
        results = {target: scan_file(target)}
    elif target.is_dir():
        results = scan_directory(target)
    else:
        print(f"Error: {target} is not a file or directory", file=sys.stderr)
        sys.exit(1)

    severity_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    min_idx = severity_order.index(args.min_severity)
    results = {
        path: [f for f in findings if severity_order.index(f.severity) >= min_idx]
        for path, findings in results.items()
        if any(severity_order.index(f.severity) >= min_idx for f in findings)
    }

    if args.format == "json":
        output = [
            {
                "file": str(path),
                "findings": [
                    {
                        "rule_id": f.rule_id,
                        "title": f.title,
                        "owasp": f.owasp,
                        "severity": f.severity,
                        "line": f.line,
                        "column": f.column,
                        "snippet": f.snippet,
                        "remediation": f.remediation,
                    }
                    for f in findings
                ],
            }
            for path, findings in results.items()
        ]
        print(json.dumps(output, indent=2))
    else:
        total = sum(len(v) for v in results.values())
        if total == 0:
            print("✓ No findings.")
            sys.exit(0)

        for path, findings in results.items():
            print(f"\n{path}")
            for f in findings:
                label = _colour(f"[{f.severity}]", f.severity, use_colour)
                print(f"  {label} Line {f.line}: {f.title} ({f.rule_id})")
                print(f"         OWASP: {f.owasp}")
                print(f"         {f.snippet}")
                print(f"         Fix: {f.remediation}")

        print(f"\n{'─' * 60}")
        print(f"  {total} finding(s) across {len(results)} file(s).")

    sys.exit(severity_exit_code(results))


if __name__ == "__main__":
    run()
