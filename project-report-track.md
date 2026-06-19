# Hermsec Project Report Track

This file is the running engineering ledger for Hermsec. Use it to record meaningful product changes, scanner/harness changes, benchmark runs, known issues, fixes, and decisions so future sessions do not need to reconstruct history from chat.

## Current Snapshot

- Active app: `v2/hermsec-v3`.
- Reusable scanner/report engine: root TypeScript CLI and harness.
- Current product direction: local-first desktop security agent for Vibecoders, with deterministic scanner evidence first and optional model explanations only after scanner/report evidence exists.
- Current scanner base: built-in Hermsec heuristics, Semgrep, Gitleaks, Bandit, OSV-Scanner, pip-audit, SafeDep PMG npm audit.
- Current priority: improve Java accuracy with taint tracking, then broaden scanner coverage with Trivy and Checkov.

## 2026-06-09 - V3 Doctor And Provider Readiness

### Changes

- Added a V3 Doctor flow that can be launched from chat.
- Doctor now runs through Electron IPC and returns a structured result to the renderer.
- Added a compact Hermsec-themed Doctor card in chat for readiness summaries.
- Doctor checks include scanner/tool readiness, internet/network checks, provider settings, and local path readiness.
- V3 Doctor can account for desktop provider settings, including saved OpenCode Go configuration, instead of relying only on root CLI environment variables.

### Issues Encountered

- Root CLI provider checks originally showed scanner-only/fallback because the OpenCode Go key existed in V3 desktop settings, not root process environment.
- OpenCode Go `/models` health could return HTTP 200 separately from actual chat readiness, so readiness needs to distinguish endpoint reachability from authenticated model use.

### Result

- User confirmed OpenCode Go API works after fixing local API settings.
- V3 Doctor is ready to become the user-facing scanner/tool/network health dashboard in chat.

## 2026-06-09 - OWASP BenchmarkJava Harness Evaluation

### Baseline

- Benchmark repo: `OWASP-Benchmark/BenchmarkJava`.
- Local clone: `.hermsec-benchmarks/BenchmarkJava`.
- Expected labels: `.hermsec-benchmarks/BenchmarkJava/expectedresults-1.2.csv`.
- Expected total tests: `2740`.
- Expected vulnerable tests: `1415`.
- Expected safe tests: `1325`.
- Baseline Hermsec result: `0 / 1415` vulnerable Java cases caught.

### Root Cause

- Root file discovery did not include `.java`, `.jsp`, `pom.xml`, XML, properties, or Gradle files.
- External Semgrep gating only considered JS/TS/Python.
- Built-in heuristics only covered secrets, JS/TS, Python, package files, and config.

### Changes

- Added Java/JSP/XML/properties/Gradle/Maven file discovery.
- Added Maven/Gradle package-manager detection.
- Added Java servlet/security heuristics for:
  - Command injection
  - SQL injection
  - XSS
  - LDAP injection
  - XPath injection
  - Path traversal
  - Weak crypto
  - Weak hash
  - Weak randomness
  - Insecure cookie flags
  - Session/trust-boundary misuse
- Added Java/JSP eligibility for optional Semgrep scans.
- Added starter Java Semgrep rules for process execution, SQL construction, and servlet response writing.
- Added `scripts/benchmark-java-score.mjs` to score Hermsec scan JSON against OWASP BenchmarkJava expected results.
- Added focused tests for Java/Maven discovery and Java servlet findings.

### Post-Change Result

- Scan wall time: about `11.3s`.
- Hermsec scan duration: about `9.8s`.
- Findings: `3247`.
- True positives: `1220`.
- False positives: `708`.
- False negatives: `195`.
- True negatives: `617`.
- Precision: `0.6328`.
- Recall: `0.8622`.
- F1: `0.7299`.

### Category Notes

- Strong: crypto, hash, weak random, secure cookie.
- Needs precision work: command injection, LDAP injection, XPath injection, path traversal, SQL injection, XSS, trust-boundary/session cases.
- Current Java rules are sink-heavy. They catch many true vulnerabilities but also flag safe variants because they do not yet track source-to-sink flow or sanitizers.

### Artifacts

- Scan JSON: `.hermsec/benchmark-java-after-java-result.json`.
- Score JSON: `.hermsec/benchmark-java-after-java-score.json`.
- HTML report: `.hermsec/benchmark-java-after-java/benchmarkjava/2026-06-09T17-30-45-803Z/report.html`.

## 2026-06-09 - Test And Local Environment Notes

### Verification

- `npm run typecheck` passed.
- `npm test` passed with `61 / 61` tests.
- V3 typecheck/build had passed during Doctor work.

### Issues Encountered

- Root `node_modules/electron` was missing generated `path.txt`, causing the desktop smoke test to fail with `Electron failed to install correctly`.
- The generated dependency state was repaired locally so the smoke test could run. This was not a source-code behavior change.
- Initial BenchmarkJava scan showed JS/support-file noise from minified/bootstrap files; minified JS assets are now skipped by the JS heuristic scanner.
- Optional external scanners can be absent from PATH and should remain skips/warnings, not ordinary scan failures.

## 2026-06-19 - Live V3 Doctor Dashboard

### Changes

- Changed the V3 Doctor chat flow so the Doctor card appears immediately when a Doctor run starts.
- Added typed `DoctorProgressEvent` updates over Electron IPC/preload.
- Main process now emits progress for:
  - Hermsec CLI readiness start/finish
  - Individual CLI Doctor checks after the CLI payload returns
  - Internet connectivity targets as each ping starts and resolves
  - Desktop provider readiness checks
- The Doctor chat item now supports `running`, `progress`, `result`, and `error` states.
- The Doctor card now renders waiting/checking/ready/warn/fail states for scanner rows, internet chips, group summaries, and a compact live-check trace.
- Added timeout fallbacks:
  - CLI Doctor child process timeout: `20s`
  - Existing connectivity request timeout: `7s`
  - Renderer watchdog timeout: `35s`

### Verification

- `cd v2\hermsec-v3 && npm.cmd run typecheck` passed.
- `cd v2\hermsec-v3 && npm.cmd run build` passed after rerunning outside the sandbox because Electron/Vite config resolution hit a sandbox read boundary.
- `node dist\src\bin\hermsec.js doctor --json` returned valid JSON.

### Issues Encountered

- PowerShell blocked `npm` through `npm.ps1`; using `npm.cmd` avoided the local execution-policy wrapper.
- The first build attempt failed inside the sandbox with `Cannot read directory "../../../../..": Access is denied`; rerunning the same build with approved unsandboxed execution passed.
- The June 19 root Doctor smoke reported `SafeDep PMG npm audit` as a warning because `pmg` was not found on PATH in that shell. Treat Doctor as the source of truth for the process environment that launches the app.

## Harness Gap Analysis From Grok Recommendation

### Already Present

- Semgrep adapter.
- Gitleaks adapter.
- OSV-Scanner adapter.
- Bandit adapter for Python.
- pip-audit adapter for Python requirements.
- PMG-wrapped npm audit for npm lockfiles.
- Built-in heuristics for secrets, JS/TS, Python, package files, config, and now Java.
- Normalized Hermsec `Finding` model.
- Doctor readiness checks.
- Evaluation/metrics foundation.

### Not Yet Present

- Trivy adapter.
- Checkov adapter.
- TruffleHog adapter.
- Syft/Grype SBOM and vulnerability workflow.
- OWASP Dependency-Check adapter.
- SonarQube CE integration.
- Git-history secrets mode as a first-class scan option.
- SARIF import/export as a first-class interface.
- Broader language/project detection for PHP, Ruby, .NET, Go, Rust, C/C++, Swift, Dart, Kotlin, Terraform, Kubernetes, Helm, and CloudFormation.
- OpenSSF CVE Benchmark runner for JS/TS.
- Benchmark CI threshold gates.

## Recommended Roadmap

### Phase 1 - Java Accuracy

- Add lightweight intra-file Java taint tracking.
- Track servlet/request sources, aliases, simple transformations, sanitizers, and category-specific sinks.
- Preserve recall at or above the current `86%`.
- Raise precision from `63%` toward `75%+`.
- Wire BenchmarkJava scorer into CI with initial gates:
  - Recall >= `85%`
  - Precision >= `63%`
  - F1 >= `72%`
- Raise precision gate after taint tracking stabilizes.

### Phase 2 - Scanner Breadth

- Add Trivy for dependency, filesystem/container, IaC, and SBOM-capable scanning.
- Add Checkov for Terraform/Kubernetes/CloudFormation/Helm/Docker-style config depth.
- Extend OSV lockfile/manifest coverage beyond npm/Python/Go/Rust to Maven, Gradle, Composer, .NET, Ruby, Swift, Dart, and Elixir where supported.
- Add Doctor checks and parser tests for every new adapter.

### Phase 3 - Deep Optional Coverage

- Add TruffleHog for verified secrets and git-history mode.
- Add Syft/Grype for SBOM + vulnerability workflows.
- Add Dependency-Check for Java-heavy Maven/Gradle projects where users accept heavier scans.
- Defer SonarQube CE because setup/server weight is high for the Vibecoder desktop flow.
- Keep Nuclei future/optional because it is closer to DAST/template probing than static repo analysis.

## Open Issues

- Java false positives remain high until taint tracking exists.
- Java SQL/XSS/path traversal precision especially needs source/sanitizer/sink modeling.
- BenchmarkJava scorer is a standalone script; it is not wired into CI yet.
- Current benchmark clone/artifacts live under ignored local paths and should not be treated as committed source.
- Scanner binary availability is machine-local. Doctor remains the source of truth for each device.

## Update Rules For This File

- Add a new dated section for every meaningful milestone.
- Record command results when they prove a capability or expose a regression.
- Keep secrets out of the file.
- Prefer concise metrics over long command output.
- Link or list local artifact paths when a report/score was generated.
