# VulnTest Benchmark Test Suite

Deliberately vulnerable projects for testing Hermsec V3's vulnerability detection capabilities across all supported languages and vulnerability categories.

## What This Is

13 intentionally vulnerable projects + 7 clean counterparts, planted with **184 known vulnerabilities** across 11 languages. Used to measure Hermsec's detection rate, precision, and coverage gaps.

## Projects

### Vulnerable Projects (13)

| # | Project | Language | Vulns | Focus |
|---|---------|----------|-------|-------|
| 1 | `nodejs-express-app` | JavaScript | 20 | Core JS vulnerabilities |
| 2 | `python-flask-app` | Python | 21 | Core Python vulnerabilities |
| 3 | `java-servlet-app` | Java | 20 | Core Java taint analysis |
| 4 | `go-web-app` | Go | 12 | Go (Semgrep + Gitleaks only) |
| 5 | `php-web-app` | PHP | 12 | PHP (Semgrep + Gitleaks only) |
| 6 | `ruby-rails-app` | Ruby | 12 | Ruby (Semgrep + Gitleaks only) |
| 7 | `c-cpp-app` | C | 12 | C/C++ buffer overflows, format strings |
| 8 | `csharp-dotnet-app` | C# | 12 | .NET process execution |
| 9 | `rust-web-app` | Rust | 12 | Rust command construction |
| 10 | `advanced-js-ts-app` | JS + TS | 12 | innerHTML, Function constructor, shell:true, etc. |
| 11 | `supply-chain-project` | JavaScript | 12 | npm lifecycle scripts, tokens, risky specifiers |
| 12 | `docker-ci-project` | Config | 12 | Docker, GitHub Actions, .env files |
| 13 | `advanced-java-python` | Java + Python | 12 | DES crypto, verify=False, unpinned deps |

### Clean Counterparts (7)

| Project | Language | Purpose |
|---------|----------|---------|
| `nodejs-express-clean` | JavaScript | False positive baseline |
| `python-flask-clean` | Python | False positive baseline |
| `java-servlet-clean` | Java | False positive baseline |
| `go-clean` | Go | False positive baseline |
| `php-clean` | PHP | False positive baseline |
| `ruby-clean` | Ruby | False positive baseline |
| `c-cpp-clean` | C | False positive baseline |

## Vulnerability Categories Covered

| Category | CWE | Planted | Detected | Rate |
|----------|-----|---------|----------|------|
| Command Injection | CWE-78 | 20 | 15 | 75% |
| Code Injection (eval) | CWE-95 | 7 | 4 | 57% |
| Buffer Overflow | CWE-120 | 3 | 2 | 67% |
| TLS Disabled | CWE-295 | 3 | 2 | 67% |
| Supply Chain | CWE-829 | 8 | 4 | 50% |
| Hardcoded Secrets | CWE-798 | 20 | 10 | 50% |
| SQL Injection | CWE-89 | 14 | 4 | 29% |
| Path Traversal | CWE-22 | 12 | 0 | **0%** |
| XSS | CWE-79 | 8 | 0 | **0%** |
| **Total** | | **184** | **89** | **48%** |

## How to Run

```bash
cd /Users/poures/Desktop/PC/insider-lab/hermsec
export PATH="$HOME/.local/bin:$PATH"

# Scan any project
npx hermsec scan "Test projects/primary_tests/go-web-app" --no-model --json --out .hermsec/benchmark

# Scan all 13
for dir in Test\ projects/primary_tests/*-app Test\ projects/primary_tests/*-project; do
  npx hermsec scan "$dir" --no-model --json --out .hermsec/benchmark
done
```

## Scoring Methodology

- **Detection Rate** = True Positives / Total Planted Vulnerabilities
- **Precision** = True Positives / (True Positives + False Positives)
- **F1 Score** = 2 x (Precision x Recall) / (Precision + Recall)
- Matching: by file path + CWE ID against `ground-truth.json`

## Files

- `BENCHMARK-REPORT.md` - General report (what was tested, results, improvements)
- `AGENT-STATISTICS.md` - Agent execution statistics
- `benchmark-results.json` - Machine-readable scoring data
- Each project has: source code, `ground-truth.json`, `README.md`
