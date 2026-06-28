# Ghazal Go Web App - Vulnerable Test Case

**Language:** Go (net/http)
**Framework:** Standard library HTTP server
**Planted Vulnerabilities:** 12

## Vulnerability Categories

| # | Type | CWE | Severity |
|---|------|-----|----------|
| 1 | Hardcoded DB credentials | CWE-798 | High |
| 2 | Hardcoded API key | CWE-798 | High |
| 3 | Hardcoded credentials in DSN | CWE-798 | High |
| 4 | SQL Injection (Sprintf) | CWE-89 | Critical |
| 5 | Command Injection (exec.Command) | CWE-78 | Critical |
| 6 | Command Injection (sh -c) | CWE-78 | Critical |
| 7 | Path Traversal (file read) | CWE-22 | High |
| 8 | Path Traversal (download) | CWE-22 | High |
| 9 | XSS (template injection) | CWE-79 | Medium |
| 10 | Weak Hash (MD5) | CWE-328 | Medium |
| 11 | Weak Random | CWE-330 | Medium |
| 12 | Information Exposure | CWE-209 | Medium |

## Expected Scanner Coverage

- **Semgrep:** Command injection (exec.Command rule)
- **Gitleaks:** Hardcoded secrets
- **OSV-Scanner:** Dependency vulnerabilities
- **No Go-specific heuristics** in Hermsec
