"""Security rules mapped to OWASP Top 10 categories."""
from __future__ import annotations
import re
from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class OWASPCategory(str, Enum):
    A01_BROKEN_ACCESS_CONTROL = "A01:2021 Broken Access Control"
    A02_CRYPTO_FAILURES = "A02:2021 Cryptographic Failures"
    A03_INJECTION = "A03:2021 Injection"
    A04_INSECURE_DESIGN = "A04:2021 Insecure Design"
    A05_SECURITY_MISCONFIG = "A05:2021 Security Misconfiguration"
    A07_AUTH_FAILURES = "A07:2021 Identification and Authentication Failures"
    A09_LOGGING_FAILURES = "A09:2021 Security Logging and Monitoring Failures"
    A10_SSRF = "A10:2021 SSRF"


@dataclass
class Finding:
    rule_id: str
    title: str
    description: str
    owasp: OWASPCategory
    severity: Severity
    line: int
    column: int
    snippet: str
    remediation: str


@dataclass
class Rule:
    rule_id: str
    title: str
    description: str
    owasp: OWASPCategory
    severity: Severity
    pattern: re.Pattern
    remediation: str

    def check(self, line: str, line_number: int) -> Finding | None:
        match = self.pattern.search(line)
        if match:
            return Finding(
                rule_id=self.rule_id,
                title=self.title,
                description=self.description,
                owasp=self.owasp,
                severity=self.severity,
                line=line_number,
                column=match.start(),
                snippet=line.strip(),
                remediation=self.remediation,
            )
        return None


RULES: list[Rule] = [
    Rule(
        rule_id="APEX-A03-001",
        title="SOQL Injection via String Concatenation",
        description="Dynamic SOQL query built with string concatenation may allow SOQL injection.",
        owasp=OWASPCategory.A03_INJECTION,
        severity=Severity.CRITICAL,
        pattern=re.compile(
            r"Database\.query\s*\(\s*['\"].*\+|Database\.query\s*\(\s*\w+\s*\+",
            re.IGNORECASE,
        ),
        remediation="Use bind variables (:variable) instead of string concatenation in dynamic SOQL.",
    ),
    Rule(
        rule_id="APEX-A03-002",
        title="String.format() Used to Build SOQL",
        description="String.format() with user input can lead to SOQL injection.",
        owasp=OWASPCategory.A03_INJECTION,
        severity=Severity.CRITICAL,
        pattern=re.compile(r"String\.format\s*\(.*SELECT|String\.format\s*\(.*WHERE", re.IGNORECASE),
        remediation="Never use String.format() to build SOQL queries. Use bind variables.",
    ),
    Rule(
        rule_id="APEX-A01-001",
        title="Class Declared without sharing",
        description="Class declared 'without sharing' bypasses record-level security.",
        owasp=OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
        severity=Severity.HIGH,
        pattern=re.compile(r"\bwithout\s+sharing\b", re.IGNORECASE),
        remediation="Use 'with sharing' or 'inherited sharing'. Document any exceptions with justification.",
    ),
    Rule(
        rule_id="APEX-A02-001",
        title="Hardcoded Credential or Token",
        description="Hardcoded secret, password, or API key detected.",
        owasp=OWASPCategory.A02_CRYPTO_FAILURES,
        severity=Severity.CRITICAL,
        pattern=re.compile(
            r"(password|secret|api_key|apikey|token|bearer)\s*=\s*['\"][^'\"]{8,}['\"]",
            re.IGNORECASE,
        ),
        remediation="Store credentials in Named Credentials or Custom Metadata with encryption. Never hardcode.",
    ),
    Rule(
        rule_id="APEX-A02-002",
        title="Weak Random Number Generation",
        description="Math.random() is not cryptographically secure.",
        owasp=OWASPCategory.A02_CRYPTO_FAILURES,
        severity=Severity.MEDIUM,
        pattern=re.compile(r"Math\.random\(\)", re.IGNORECASE),
        remediation="Use Crypto.getRandomInteger() or Crypto.generateAesKey() for security-sensitive randomness.",
    ),
    Rule(
        rule_id="APEX-A09-001",
        title="Sensitive Data in Debug Log",
        description="Potentially sensitive data written to System.debug().",
        owasp=OWASPCategory.A09_LOGGING_FAILURES,
        severity=Severity.MEDIUM,
        pattern=re.compile(
            r"System\.debug\s*\(.*?(password|token|secret|ssn|credit.?card)",
            re.IGNORECASE,
        ),
        remediation="Never log sensitive fields. Use masking or omit from logs entirely.",
    ),
    Rule(
        rule_id="APEX-A10-001",
        title="Unvalidated URL in HTTP Callout",
        description="HTTP callout endpoint may be set from user-controlled input.",
        owasp=OWASPCategory.A10_SSRF,
        severity=Severity.HIGH,
        pattern=re.compile(
            r"req\.setEndpoint\s*\(\s*(?!.*callout:)(?!.*'https?://)",
            re.IGNORECASE,
        ),
        remediation="Validate endpoints against an allowlist. Use Named Credentials where possible.",
    ),
    Rule(
        rule_id="APEX-A05-001",
        title="isTest(SeeAllData=true) Detected",
        description="Test class accesses live org data, which can cause non-deterministic tests and data leaks.",
        owasp=OWASPCategory.A05_SECURITY_MISCONFIG,
        severity=Severity.MEDIUM,
        pattern=re.compile(r"@isTest\s*\(\s*SeeAllData\s*=\s*true", re.IGNORECASE),
        remediation="Create test data in the test class itself. Never rely on live org data.",
    ),
    Rule(
        rule_id="APEX-A01-002",
        title="SOSL Injection via String Concatenation",
        description="Dynamic SOSL query built with string concatenation.",
        owasp=OWASPCategory.A03_INJECTION,
        severity=Severity.HIGH,
        pattern=re.compile(r"Database\.search\s*\(\s*\w+\s*\+|FIND\s*\{.*\+", re.IGNORECASE),
        remediation="Use String.escapeSingleQuotes() and bind variables for dynamic SOSL.",
    ),
]
