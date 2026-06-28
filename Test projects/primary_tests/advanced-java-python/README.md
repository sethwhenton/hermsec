# VulnTest Advanced Java/Python Project - Vulnerable Test Case

**Languages:** Java + Python
**Focus:** Gap-filling for Java taint heuristics and Python specific rules
**Planted Vulnerabilities:** 12

## Vulnerability Categories

| # | Type | CWE | Hermsec Rule | Severity |
|---|------|-----|-------------|----------|
| 1 | Weak crypto (DES) | CWE-327 | hermsec.java.crypto | High |
| 2 | Weak random | CWE-330 | hermsec.java.weakrand | Medium |
| 3 | Path traversal (Java) | CWE-22 | hermsec.java.pathtraver | High |
| 4 | SQL Injection (Java) | CWE-89 | hermsec.java.sqli | Critical |
| 5 | Command Injection (Java) | CWE-78 | hermsec.java.cmdi | Critical |
| 6 | XSS (Java) | CWE-79 | hermsec.java.xss | Medium |
| 7 | verify=False (Python) | CWE-295 | hermsec.python.verify-false | High |
| 8 | Unpinned dependencies | CWE-1104 | hermsec.python.unpinned-python | Medium |
| 9 | SQL Injection (Python) | CWE-89 | hermsec.python.eval-exec | Critical |
| 10 | Command Injection (Python) | CWE-78 | hermsec.python.subprocess-shell | Critical |
| 11 | Path Traversal (Python) | CWE-22 | none | High |
| 12 | Unsafe eval (Python) | CWE-95 | hermsec.python.eval-exec | Critical |

## Purpose

Tests gap-filling Java rules (crypto, weakrand, pathtraver) and Python-specific rules (verify-false, unpinned-python) not covered by the original 3 projects.
