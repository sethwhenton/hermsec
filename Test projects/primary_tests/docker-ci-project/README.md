# VulnTest Docker/CI Config Project - Vulnerable Test Case

**Languages:** Dockerfile, GitHub Actions YAML, .env
**Focus:** Configuration and CI/CD vulnerabilities
**Planted Vulnerabilities:** 12

## Vulnerability Categories

| # | Type | CWE | Hermsec Rule | Severity |
|---|------|-----|-------------|----------|
| 1 | Docker privileged | CWE-250 | hermsec.config.docker-privileged | High |
| 2 | Docker exposed ports | CWE-284 | hermsec.config.docker-exposed-ports | Medium |
| 3 | Docker latest tag | CWE-1104 | hermsec.config.docker-latest-tag | Medium |
| 4 | Dockerfile secrets | CWE-798 | hermsec.config.dockerfile-secrets | High |
| 5 | Missing permissions | CWE-284 | hermsec.config.github-actions-permissions | High |
| 6 | Untrusted action | CWE-829 | hermsec.config.github-actions-untrusted | High |
| 7 | .env secrets | CWE-798 | hermsec.config.env-secrets | High |
| 8 | TLS disabled | CWE-295 | hermsec.config.tls-disabled | High |
| 9 | Hardcoded in config | CWE-798 | hermsec.config.hardcoded-secrets-in-code | High |
| 10 | Stripe secret | CWE-798 | hermsec.secret.generic | Medium |
| 11 | AWS secret | CWE-798 | hermsec.secret.generic | Critical |
| 12 | GitHub token | CWE-798 | hermsec.secret.github-token | High |

## Purpose

Tests ALL configuration heuristics in Hermsec (hermsec.config.*) covering Docker, GitHub Actions, and .env file security.
