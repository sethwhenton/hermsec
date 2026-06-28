# Ghazal Advanced JS/TS App - Vulnerable Test Case

**Languages:** JavaScript + TypeScript
**Framework:** Express.js
**Planted Vulnerabilities:** 12

## Vulnerability Categories

| # | Type | CWE | Hermsec Rule | Severity |
|---|------|-----|-------------|----------|
| 1 | innerHTML | CWE-79 | hermsec.js.inner-html | Medium |
| 2 | Function constructor | CWE-95 | hermsec.js.function-constructor | Critical |
| 3 | shell:true | CWE-78 | hermsec.js.shell-true | Critical |
| 4 | Unsanitized HTML | CWE-79 | hermsec.js.unsanitized-html-response | Medium |
| 5 | Command injection (query) | CWE-78 | hermsec.js.command-injection-input | Critical |
| 6 | Command injection (body) | CWE-78 | hermsec.js.command-injection-input | Critical |
| 7 | eval | CWE-95 | hermsec.js.eval | Critical |
| 8 | SQL injection | CWE-89 | hermsec.js.sql-dynamic-string | Critical |
| 9 | Path traversal | CWE-22 | none | High |
| 10 | Hardcoded secret | CWE-798 | hermsec.secret.generic | High |
| 11 | CORS wildcard | CWE-942 | hermsec.js.cors-wildcard | Medium |
| 12 | TLS disabled | CWE-295 | hermsec.js.tls-disabled | High |

## Purpose

Tests ALL JavaScript/TypeScript heuristic rules in Hermsec, including rules not covered by the original Node.js Express project. Both .js and .ts files present for TypeScript rule coverage.
