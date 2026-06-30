# VulnTest Rust Web App - Vulnerable Test Case

**Language:** Rust
**Framework:** Standard library
**Planted Vulnerabilities:** 12

## Vulnerability Categories

| # | Type | CWE | Severity |
|---|------|-----|----------|
| 1 | Hardcoded DB credentials | CWE-798 | High |
| 2 | Hardcoded API key | CWE-798 | High |
| 3 | Command Injection (Command::new) | CWE-78 | Critical |
| 4 | Command Injection (sh -c) | CWE-78 | Critical |
| 5 | Path Traversal (file read) | CWE-22 | High |
| 6 | Path Traversal (absolute path) | CWE-22 | High |
| 7 | XSS (format!) | CWE-79 | Medium |
| 8 | SQL Injection (format!) | CWE-89 | Critical |
| 9 | SQL Injection (concat) | CWE-89 | Critical |
| 10 | Information Exposure | CWE-209 | Medium |
| 11 | Hardcoded Credentials in Config | CWE-798 | High |
| 12 | Unsafe Deserialization | CWE-502 | Medium |

## Expected Scanner Coverage

- **Semgrep:** Command::new rule
- **Gitleaks:** Hardcoded secrets
- **No Rust SAST** installed (would catch command injection, unsafe patterns)
