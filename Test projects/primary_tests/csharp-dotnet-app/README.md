# VulnTest C# .NET App - Vulnerable Test Case

**Language:** C# (.NET)
**Framework:** Console application
**Planted Vulnerabilities:** 12

## Vulnerability Categories

| # | Type | CWE | Severity |
|---|------|-----|----------|
| 1 | Hardcoded DB credentials | CWE-798 | High |
| 2 | Hardcoded API key | CWE-798 | High |
| 3 | SQL Injection (concatenation) | CWE-89 | Critical |
| 4 | SQL Injection (interpolation) | CWE-89 | Critical |
| 5 | Command Injection (Process.Start) | CWE-78 | Critical |
| 6 | Command Injection (cmd.exe) | CWE-78 | Critical |
| 7 | Path Traversal (file read) | CWE-22 | High |
| 8 | Path Traversal (File.ReadAllText) | CWE-22 | High |
| 9 | XSS (interpolation) | CWE-79 | Medium |
| 10 | Weak Hash (MD5) | CWE-328 | Medium |
| 11 | Hardcoded Connection String | CWE-798 | High |
| 12 | Information Exposure | CWE-209 | Medium |

## Expected Scanner Coverage

- **Semgrep:** Process.Start rule
- **Gitleaks:** Hardcoded secrets
- **No .NET SAST** installed (would catch SQL injection, command injection)
