# VulnTest C/C++ App - Vulnerable Test Case

**Language:** C
**Framework:** Standard library
**Planted Vulnerabilities:** 12

## Vulnerability Categories

| # | Type | CWE | Severity |
|---|------|-----|----------|
| 1 | Hardcoded DB credentials | CWE-798 | High |
| 2 | Hardcoded API key | CWE-798 | High |
| 3 | Buffer Overflow (gets) | CWE-120 | Critical |
| 4 | Buffer Overflow (strcpy) | CWE-120 | Critical |
| 5 | Buffer Overflow (strcat) | CWE-120 | Critical |
| 6 | Format String | CWE-134 | Critical |
| 7 | Command Injection (popen) | CWE-78 | Critical |
| 8 | Command Injection (system) | CWE-78 | Critical |
| 9 | Path Traversal | CWE-22 | High |
| 10 | XSS (sprintf) | CWE-79 | Medium |
| 11 | Weak Random | CWE-330 | Medium |
| 12 | Information Exposure | CWE-209 | Medium |

## Expected Scanner Coverage

- **Semgrep:** gets/strcpy/strcat/sprintf rule
- **Gitleaks:** Hardcoded secrets
- **Flawfinder/Cppcheck:** Not installed (would catch buffer overflows)
