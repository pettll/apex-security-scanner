# apex-security-scanner

OWASP Top 10 static analysis for Salesforce Apex code. Finds SOQL injection, hardcoded credentials, broken access control, and more — before they reach production.

## Install

```bash
pip install apex-security-scanner
```

## Usage

```bash
# Scan a directory
apex-scan force-app/

# Scan a single file
apex-scan force-app/main/default/classes/AccountService.cls

# JSON output for CI integration
apex-scan force-app/ --format json > results.json

# Only show HIGH and CRITICAL
apex-scan force-app/ --min-severity HIGH
```

## Rules

| Rule ID | Title | OWASP | Severity |
|---------|-------|-------|----------|
| APEX-A03-001 | SOQL Injection via String Concatenation | A03 Injection | CRITICAL |
| APEX-A03-002 | String.format() Used to Build SOQL | A03 Injection | CRITICAL |
| APEX-A02-001 | Hardcoded Credential or Token | A02 Cryptographic Failures | CRITICAL |
| APEX-A01-001 | Class Declared without sharing | A01 Broken Access Control | HIGH |
| APEX-A10-001 | Unvalidated URL in HTTP Callout | A10 SSRF | HIGH |
| APEX-A01-002 | SOSL Injection | A03 Injection | HIGH |
| APEX-A02-002 | Weak Random Number Generation | A02 Cryptographic Failures | MEDIUM |
| APEX-A09-001 | Sensitive Data in Debug Log | A09 Logging Failures | MEDIUM |
| APEX-A05-001 | isTest(SeeAllData=true) | A05 Security Misconfiguration | MEDIUM |

## CI Integration

```yaml
- name: Apex Security Scan
  run: |
    pip install apex-security-scanner
    apex-scan force-app/ --min-severity HIGH --format json > apex-security-results.json
    apex-scan force-app/ --min-severity HIGH
```

Exit codes: `0` = clean, `1` = medium findings, `2` = high findings, `3` = critical findings.

## License

MIT
