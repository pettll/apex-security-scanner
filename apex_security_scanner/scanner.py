"""Core scanner — walks Apex files and applies rules."""
from __future__ import annotations
import os
from pathlib import Path
from .rules import Finding, RULES, Severity


def scan_file(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return findings

    for line_number, line in enumerate(lines, start=1):
        # Skip single-line comments
        stripped = line.lstrip()
        if stripped.startswith("//"):
            continue
        for rule in RULES:
            finding = rule.check(line, line_number)
            if finding:
                findings.append(finding)
    return findings


def scan_directory(root: Path) -> dict[Path, list[Finding]]:
    results: dict[Path, list[Finding]] = {}
    for dirpath, _, filenames in os.walk(root):
        for filename in filenames:
            if filename.endswith(".cls") or filename.endswith(".trigger"):
                path = Path(dirpath) / filename
                findings = scan_file(path)
                if findings:
                    results[path] = findings
    return results


def severity_exit_code(results: dict[Path, list[Finding]]) -> int:
    """Return exit code: 0=clean, 1=medium+, 2=high+, 3=critical."""
    all_findings = [f for findings in results.values() for f in findings]
    if any(f.severity == Severity.CRITICAL for f in all_findings):
        return 3
    if any(f.severity == Severity.HIGH for f in all_findings):
        return 2
    if any(f.severity == Severity.MEDIUM for f in all_findings):
        return 1
    return 0
