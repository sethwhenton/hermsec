# VulnTest Ruby Rails App - Vulnerable Test Case

**Language:** Ruby (WEBrick)
**Framework:** WEBrick HTTP server
**Planted Vulnerabilities:** 12

## Vulnerability Categories

| # | Type | CWE | Severity |
|---|------|-----|----------|
| 1 | Hardcoded DB credentials | CWE-798 | High |
| 2 | Hardcoded API key | CWE-798 | High |
| 3 | SQL Injection (interpolation) | CWE-89 | Critical |
| 4 | SQL Injection (concatenation) | CWE-89 | Critical |
| 5 | Command Injection (backticks) | CWE-78 | Critical |
| 6 | Command Injection (system) | CWE-78 | Critical |
| 7 | Command Injection (exec) | CWE-78 | Critical |
| 8 | Path Traversal (file read) | CWE-22 | High |
| 9 | Path Traversal (require) | CWE-22 | High |
| 10 | XSS (interpolation) | CWE-79 | Medium |
| 11 | Unsafe YAML Deserialization | CWE-502 | Critical |
| 12 | Information Exposure | CWE-209 | Medium |

## Expected Scanner Coverage

- **Semgrep:** system/exec rule
- **Gitleaks:** Hardcoded secrets
- **OSV-Scanner:** Dependency vulnerabilities
