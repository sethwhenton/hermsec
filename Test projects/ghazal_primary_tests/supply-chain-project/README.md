# Ghazal Supply Chain Project - Vulnerable Test Case

**Language:** JavaScript (npm)
**Focus:** Package manager and supply chain vulnerabilities
**Planted Vulnerabilities:** 12

## Vulnerability Categories

| # | Type | CWE | Hermsec Rule | Severity |
|---|------|-----|-------------|----------|
| 1 | Lifecycle scripts (preinstall) | CWE-95 | hermsec.package.lifecycle-scripts | Critical |
| 2 | Lifecycle scripts (postinstall) | CWE-798 | hermsec.package.lifecycle-scripts | Critical |
| 3 | Git SSH dependency | CWE-829 | hermsec.package.git-dependency | High |
| 4 | GitHub hosted dependency | CWE-829 | hermsec.package.github-hosted-dependency | High |
| 5 | Unpinned version (latest) | CWE-1104 | hermsec.package.unpinned-version | High |
| 6 | Wildcard version (*) | CWE-1104 | hermsec.package.unpinned-version | Medium |
| 7 | GitHub token exposure | CWE-798 | hermsec.secret.github-token | High |
| 8 | Slack token exposure | CWE-798 | hermsec.secret.slack-token | High |
| 9 | Private key file | CWE-321 | hermsec.secret.private-key | Critical |
| 10 | Shell command for install | CWE-78 | none | High |
| 11 | Dynamic require | CWE-95 | hermsec.js.eval | Critical |
| 12 | Remote code eval | CWE-95 | hermsec.js.eval | Critical |

## Purpose

Tests ALL package manager heuristics in Hermsec (hermsec.package.*) plus secret detection rules for GitHub tokens, Slack tokens, and private keys.
