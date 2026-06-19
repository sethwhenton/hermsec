# Hermsec Project Report Track

This file is the running engineering ledger for Hermsec. Use it to record meaningful product changes, scanner/harness changes, benchmark runs, known issues, fixes, and decisions so future sessions do not need to reconstruct history from chat.

## Current Snapshot

- Active app: `v2/hermsec-v3`.
- Reusable scanner/report engine: root TypeScript CLI and harness.
- Current product direction: local-first desktop security agent for Vibecoders, with deterministic scanner evidence first and two scan-assist modes: `Scanner + model summary` and `Deep assisted scan`.
- Current scanner base: built-in Hermsec heuristics, Semgrep, Gitleaks, Bandit, OSV-Scanner, pip-audit, SafeDep PMG npm audit.
- Current priority: improve Java accuracy with taint tracking, then broaden scanner coverage with Trivy and Checkov.

## 2026-06-19 - Complete Windows App Package With Bundled CLI And Scanners

### Changes

- Added `v2/hermsec-v3/scripts/prepare-cli-bundle.mjs`.
  - Builds the root CLI core.
  - Copies `dist/src` into `v2/hermsec-v3/resources/hermsec-cli`.
  - Writes a minimal bundled CLI `package.json`.
- Added `v2/hermsec-v3/scripts/prepare-runtime-tools.mjs`.
  - Downloads and checksum-verifies official Gitleaks, OSV-Scanner, and SafeDep PMG release assets.
  - Uses `uv tool install` for pinned Semgrep, Bandit, and pip-audit versions.
  - Copies the uv-managed Python tool environments into `resources/runtime-tools/<platform>-<arch>/python`.
  - Writes `resources/runtime-tools/<platform>-<arch>/manifest.json`.
- Added V3 runtime bundle configuration in `src/main/runtimeBundle.ts`.
  - Packaged app startup points `HERMSEC_CLI_ROOT` to bundled `resources/hermsec-cli`.
  - Packaged app startup points scanner env overrides to bundled scanner executables.
  - Scanner resolution now checks `HERMSEC_*_BIN`, `HERMSEC_TOOLS_DIR`, `HERMSEC_BUNDLED_TOOLS_DIR`, bundled Python tool folders, then normal PATH.
- Updated V3 packaging scripts:
  - `prepare:cli-bundle`
  - `prepare:runtime-tools`
  - `build:packaged`
  - `dist:win`
  - `dist:mac`
  - `dist:linux`
- Removed `resources/**/*` from Electron Builder `files` so runtime tools are copied as executable `extraResources` instead of being duplicated inside `app.asar`.
- Changed default packaged scan/report output away from app resources and into the user's `Documents\Hermsec` tree.
- Updated root GitHub `README.md` and V3 `README.md` with the complete Windows installer/portable `.exe` workflow and bundled scanner list.

### Package Artifacts

- Installer: `v2/hermsec-v3/release/Hermsec Setup 0.1.0.exe`
- Portable app: `v2/hermsec-v3/release/Hermsec 0.1.0.exe`
- Unpacked app: `v2/hermsec-v3/release/win-unpacked/Hermsec.exe`
- Approximate size: `~200 MB`, because the app includes the CLI plus scanner runtime.
- These `.exe` files are ignored build artifacts and should be uploaded as GitHub Release assets, not committed directly to git.

### Bundled Runtime Contents

- Hermsec CLI/report engine.
- Semgrep `1.167.0`.
- Gitleaks `v8.30.1`.
- Bandit `1.9.4`.
- OSV-Scanner `v2.4.0`.
- pip-audit `2.10.1`.
- SafeDep PMG `v0.19.1`.

### Verification

- Root typecheck: `npm.cmd run typecheck` passed.
- V3 typecheck: `npm.cmd run typecheck` passed.
- Root build: `npm.cmd run build` passed.
- V3 build: `npm.cmd run build` passed.
- Bundled scanner resolver check: root Doctor with `HERMSEC_TOOLS_DIR=v2\hermsec-v3\resources\runtime-tools\win32-x64` reported Semgrep, Gitleaks, Bandit, OSV-Scanner, pip-audit, and PMG from the generated runtime bundle.
- Packaged-style V3 Doctor smoke with generated `HERMSEC_CLI_ROOT` and `HERMSEC_BUNDLED_TOOLS_DIR` passed at `100%`.
- Packaged-style V3 dashboard smoke with generated CLI/tools passed and generated dashboard HTML plus one-page PDF.
- `npm.cmd run dist:win` completed and produced installer plus portable `.exe`.
- Unpacked packaged executable Doctor smoke passed with status `ready`, health score `100`, required `7/7`, scanners `6/6`, internet `5/5`, providers `1/1`.
- Unpacked packaged executable dashboard smoke passed with bundled CLI/scanners and wrote reports to `C:\Users\whent\Documents\Hermsec\smoke-reports\...`.

### Notes And Follow-Ups

- The Windows package is now self-contained for the current scanner stack, but macOS/Linux packages still need platform-specific verification.
- `uv` is required on the build machine to create the bundled Python scanner environments.
- Release `.exe` files exceed normal source-control comfort and should be attached to a GitHub Release.

## 2026-06-19 - V3 Scan Assist Modes And Scanner Evidence Merge

### Changes

- Collapsed the product scan-assist UX into two modes:
  - `Scanner + model summary`: scanner stack remains authoritative; model use is limited to report-level explanation from scanner findings.
  - `Deep assisted scan`: scanner stack still runs first; Hermsec asks the model to support deeper prioritization and relationship notes using only supplied scanner evidence.
- Added a scan-mode choice card in V3 chat. Any scan request now asks the user to choose a mode before running the scan, similar to Codex-style plan choice cards.
- Added a shared `ScanModeSegmentedControl` and wired it into:
  - Settings > General default scan mode.
  - Top-right automation popover.
  - Automations manager/editor.
  - Manual automation Run Now.
  - Dashboard `Scan again`.
  - Background scheduled automation checks.
- Added `assistMode` to V3 scan request/result types, settings normalization, scan metadata, smoke-dashboard path, and scan progress copy.
- Added root CLI support for `hermsec scan --assist-mode scanner-model-summary|deep-assisted`.
- Passed the assist mode from V3 into the root CLI harness so the model prompt differs for deep assisted scans while the existing evidence validator still rejects unsupported model output.
- Added `scan-assist.json` report artifact generation in V3. It deterministically groups similar findings, records scanner matching pairs, and marks groups as scanner-confirmed or multi-scanner.
- Updated the interactive dashboard:
  - Header and metadata show the user-facing assist mode rather than internal `online` transport mode.
  - Pipeline tab shows a compact Assist Mode dashboard card.
  - Adjudication tab shows a Scanner-confirmed merge map before per-finding verdicts.
- Updated the one-page report to show assist mode.
- Updated V3 report normalization to handle structured dependency package objects and nested identifiers from the root harness.

### Issues Encountered

- `app-v4.js` and `app-onepager.js` contain older mojibake separator text around `Â·`, so direct patches around those lines failed. Patched around stable neighboring lines instead.
- `AgentQuestions.tsx` had a mojibake checkmark, so the component was replaced wholesale with a clean Lucide check icon and richer option-card layout.
- Root TypeScript with `exactOptionalPropertyTypes` rejected an explicitly optional `assistMode`; fixed by making the CLI parser return a concrete default.

### Verification

- Root typecheck: `npm.cmd run typecheck` passed.
- Root build: `npm.cmd run build` passed and refreshed `dist/src/bin/hermsec.js`.
- Root CLI assist-mode smoke passed with `HERMSEC_HOME=.hermsec\mode-smoke-home` and `hermsec scan ... --assist-mode deep-assisted --no-model`; the scan found 8 expected lab findings.
- V3 typecheck: `npm.cmd run typecheck` passed.
- V3 build: `npm.cmd run build` passed.
- V3 Electron dashboard smoke was attempted with model disabled, but the local runner crashed before app startup with Electron GPU process failures (`GPU process isn't usable`) even when retrying with GPU-disable switches.

### Follow-Ups

- Deep assisted mode now changes prompt behavior and report evidence presentation, but the next major improvement should add a bounded repository context gatherer for model-assisted triage so the model can inspect nearby source snippets without creating new findings.
- Java taint tracking remains the highest-impact scanner improvement: model servlet request sources, aliases, sanitizers such as ESAPI encoding, and sinks across SQL/LDAP/XPath/file/response/session APIs.
- Add CI gates for benchmark recall/precision thresholds so future scanner changes cannot silently reduce Java coverage.

## 2026-06-19 - Doctor Readiness Follow-Up And Card Polish

### Changes

- Updated the V3 Doctor chat card to match the app shell more closely:
  - Uses `bg-surface-elevated`, `border-border`, compact rounded panels, and restrained Hermsec status colors.
  - Keeps the live readiness ring, but with less decorative gradient treatment.
  - Adds a dedicated `Readiness blockers` panel for warnings, failures, missing scanner tools, and connectivity issues.
  - Keeps scanner stack and connectivity chips compact enough to work inside chat.
- Changed V3 Doctor NVD connectivity to check `https://nvd.nist.gov/vuln` as the general reachability target. The NVD API can transiently return `503`, so it should not make the chat Doctor card report broken internet when the NVD site is reachable.
- Added smoke-run graphics fallback hooks:
  - V3 main can disable hardware acceleration during `--smoke-dashboard` or `HERMSEC_DISABLE_GPU=true`.
  - The smoke-dashboard launcher now passes additional Chromium GPU-disable switches.
- Added `npm.cmd run smoke:doctor` for V3. It launches Electron in Doctor smoke mode, runs the real app-side Doctor path without opening a window, asserts required/scanner/internet readiness, prints group/connectivity JSON, and exits non-zero on smoke failures.
- Fixed V3 desktop Doctor CLI spawning. The Electron app previously used `process.execPath`, which is `electron.exe`; it now launches `node.exe` so the root CLI Doctor command completes normally.

### Readiness Result

- Installed the missing scanner CLIs into `C:\Users\whent\.local\bin`, which is on PATH:
  - Semgrep `1.167.0` via `uv tool install semgrep`
  - Bandit `1.9.4` via `uv tool install bandit`
  - pip-audit `2.10.1` via `uv tool install pip-audit`
  - Gitleaks `8.30.1` from official GitHub release zip with checksum verification
  - OSV-Scanner `2.4.0` from official GitHub release exe with checksum verification
  - SafeDep PMG `0.19.1` from official GitHub release zip with checksum verification
- Root Doctor now completes with `15 passed`, `0 warnings`, `0 failed`, and `6 skipped` optional provider/GitHub CLI checks.
- V3 Doctor smoke against the normal V3 profile completed with:
  - status: `ready`
  - health score: `100`
  - required: `7/7`
  - scanners: `6/6`
  - internet: `5/5`
  - providers: `1/1`
- Connectivity latencies from the verified run:
  - GitHub: HTTP 200 in `187ms`
  - npm: HTTP 200 in `277ms`
  - OSV: HTTP 200 in `475ms`
  - CISA KEV: HTTP 200 in `148ms`
  - NVD website: HTTP 200 in `532ms`

### Verification

- V3 typecheck: `npm.cmd run typecheck` passed.
- V3 build: `npm.cmd run build` passed after the Doctor backend/card changes.
- V3 Doctor smoke: `npm.cmd run smoke:doctor` passed against the normal V3 profile with Doctor at `100%`.
- V3 dashboard smoke: `npm.cmd run smoke:dashboard` passed and generated a fresh dashboard plus non-empty one-page PDF.
- Root typecheck: `npm.cmd run typecheck` passed.
- Root build: `npm.cmd run build` passed.
- Tool execution smoke:
  - V3 scan exercised Semgrep, Gitleaks, OSV-Scanner, and PMG successfully.
  - Python lab scan exercised Semgrep, Gitleaks, Bandit, and pip-audit successfully.

### Notes And Follow-Ups

- The focused V3 scan found Gitleaks hits inside generated local smoke app-data folders under `v2/hermsec-v3/.hermsec*`. Those folders are ignored by git but should be excluded from default scan targets or moved outside project roots to avoid noisy local findings.
- NVD API availability should be checked separately from general NVD website reachability if future online-intel diagnostics need source-specific API health.

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
