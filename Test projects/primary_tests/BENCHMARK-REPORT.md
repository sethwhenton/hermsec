# Hermsec V3 Benchmark Report

## What We Did

We tested Hermsec V3's ability to detect security vulnerabilities by creating **13 deliberately vulnerable projects** across 11 programming languages, planting **184 known vulnerabilities**, and running Hermsec scans against them. We also created **7 clean projects** with zero vulnerabilities to measure false positive rates.

The goal: understand what Hermsec catches, what it misses, and where to improve.

## How We Tested

1. **Created vulnerable projects** - Each project has 12 planted vulnerabilities with a `ground-truth.json` file documenting exact file, line, CWE, and severity
2. **Created clean counterparts** - Secure versions of projects to test false positive rates
3. **Ran Hermsec scans** - Scanner-only mode (no AI model), all available tools enabled
4. **Scored results** - Matched findings against ground truth by file path + CWE ID
5. **Generated reports** - Detection rates, precision, F1 scores per language and category

## Results at a Glance

| Metric | Value |
|--------|-------|
| **Detection Rate** | **48.4%** (89 of 184 found) |
| **Precision** | **85.6%** (low false positives) |
| **F1 Score** | **61.8%** |
| **False Positives** | 15 total (all from original 3 projects) |

### By Language

| Language | Detection Rate | Notes |
|----------|---------------|-------|
| Node.js | 85% | Strong - heuristics + Semgrep + Gitleaks |
| Python | 86% | Strong - Bandit integration works well |
| Java | 75% | Good - taint heuristics catch unique vulns |
| JS/TS (Advanced) | 58% | Good - innerHTML, Function constructor, shell:true |
| Supply Chain | 58% | Good - lifecycle scripts, GitHub/Slack tokens |
| Java/Python (Mixed) | 60% | Good - DES crypto, verify=False, unpinned deps |
| C/C++ | 33% | Fair - buffer overflows only |
| Go | 25% | Low - only command injection via Semgrep |
| Ruby | 25% | Low - only command injection via Semgrep |
| C# | 25% | Low - only Process.Start via Semgrep |
| Rust | 17% | Low - only Command::new via Semgrep |
| Docker/CI | 25% | Low - only .env and Dockerfile secrets |
| PHP | 8% | Very Low - only hardcoded API key |

### By Vulnerability Type

| What Works Well | Rate | What Doesn't Work | Rate |
|----------------|------|-------------------|------|
| Command Injection | 75% | Path Traversal | **0%** |
| Buffer Overflow | 67% | XSS (new projects) | **0%** |
| TLS Disabled | 67% | Format Strings | **0%** |
| Code Injection (eval) | 57% | CORS Misconfiguration | **0%** |
| Supply Chain | 50% | SSRF/XXE | **0%** |
| Hardcoded Secrets | 50% | SQL Injection (non-JS/Py) | 0% |

## Why New Projects Scored Lower

The original 3 projects (Node.js, Python, Java) scored 78% because Hermsec has **dedicated heuristic rules** for those languages. The 10 new projects target languages where Hermsec only has **1 Semgrep rule** or **no language-specific rules at all**.

This is the real-world picture: Hermsec is excellent for JavaScript/Python/Java, but limited for Go, PHP, Ruby, C/C++, C#, Rust, and configuration files.

## How to Improve

### Priority 1: Critical Gaps (0% Detection)

| Gap | Recommendation |
|-----|----------------|
| **Path Traversal** | Add heuristics for `path.join(userInput)`, `os.path.join(userInput)`, `Path.Combine(userInput)` across all languages |
| **XSS** | Add heuristics for template injection in PHP (`echo $var`), Ruby (`#{var}`), Go (`fmt.Sprintf` with HTML) |
| **Format Strings** | Add C/C++ format string detection (`printf(userInput)`) |

### Priority 2: Language Coverage

| Language | What's Needed |
|----------|--------------|
| **PHP** | SQL injection, command injection, path traversal, XSS, deserialization heuristics |
| **Go** | SQL injection, path traversal, XSS, command injection heuristics |
| **Ruby** | SQL injection, path traversal, XSS, deserialization heuristics |
| **C#** | SQL injection, path traversal, XSS heuristics |
| **Rust** | SQL injection, path traversal, XSS heuristics |

### Priority 3: Install Missing Scanners

These tools would immediately improve coverage:

| Scanner | Language | Installs With |
|---------|----------|---------------|
| gosec | Go | `go install github.com/securego/gosec/v2/cmd/gosec@latest` |
| Brakeman | Ruby | `gem install brakeman` |
| Flawfinder | C/C++ | `pip install flawfinder` |
| cargo-audit | Rust | `cargo install cargo-audit` |
| Trivy | All | `brew install trivy` |
| Checkov | IaC | `pip install checkov` |

### Priority 4: Config Detection

Improve Docker/GitHub Actions detection:
- Docker privileged containers
- Exposed SSH ports in Dockerfiles
- Missing GitHub Actions permissions
- Untrusted third-party actions
- TLS disabled in config files

## Bottom Line

Hermsec is **production-ready for JavaScript, Python, and Java** with high detection rates and low false positives. For other languages, it provides basic coverage through Semgrep and Gitleaks but needs dedicated heuristic rules to be truly effective. The path forward is clear: add path traversal and XSS heuristics, expand PHP/Go/Ruby/C#/Rust support, and install the missing external scanners.

---

*Full machine-readable data: `benchmark-results.json`*
