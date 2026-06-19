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

## 2026-06-19 - Real Deep-Assisted BenchmarkJava Validation

### Changes / Runs

- Re-ran OWASP BenchmarkJava in online deep-assisted mode with OpenCode Go and DeepSeek Flash after the routing/chunking fixes.
- Used process-only model environment variables and kept the repo/config free of raw credential values.
- Enabled `HERMSEC_BENCHMARK_EXPORT_RAW=1` for the successful run so benchmark scoring could use raw, unredacted testcase identifiers without weakening normal user-facing report redaction.
- Successful output directory: `.hermsec\benchmark-runs\BenchmarkJava-deep-assisted-model-real-20260619-155145\benchmarkjava\2026-06-19T13-56-07-856Z\`.
- Saved scorer output to `benchmark-score.json` in that output directory.

### Verification

- Successful full scan summary: `9384` findings, `1784` high, `7600` medium, `0` scanner failures.
- Model report status: `generatedWithModel=true`, provider `opencode-go`.
- Model explanation scope: top `10` prioritized findings were model-explained; the remaining `9374` findings used fallback evidence-bound explanations.
- Tool counts: Semgrep `6572`, Hermsec offline heuristics `2810`, Gitleaks `2`.
- OWASP BenchmarkJava metrics: TP `1238`, FP `728`, FN `177`, TN `597`, precision `0.6297`, recall `0.8749`, F1 `0.7323`, accuracy `0.6697`.
- CLI config was restored afterward: `preferredModelProvider=none`, `privacyMode=local-only`.

### Issues Encountered

- First full model-backed attempt completed static scanning but model generation fell back with `provider-failed`; the first model chunk was too large/slow for the original settings.
- Plain text provider smoke returned no message content, while JSON-mode completion succeeded. Hermsec's structured JSON explanation path is the reliable path for OpenCode Go.
- A relaunch failed because Windows `Start-Process` split the BenchmarkJava path at the space in `Personal Proj`; quoting the target and output paths fixed the launch.

### Follow-Ups

- Add a clearer provider failure detail field so future reports do not collapse first-chunk model errors into only `provider-failed`.
- Keep deep-assisted top-N configurable and cost-visible in the UI/CLI.
- Continue Java precision work: command injection, LDAP, XPath, path traversal, SQLi, trust boundary, and XSS still produce high false positives.

## 2026-06-19 - Planned Adaptive Scanner Harness And Scan Tracker

### Direction

- Add an adaptive scanner harness before the scan starts.
- The harness should inspect the repository, infer languages/frameworks/manifests/lockfiles, choose the minimum scanner set needed for that project, verify or install missing scanner tools into the Hermsec-managed runtime, and then run only the relevant scanners.
- The UI should use the simpler Hermsec theme: no extra logo/title inside the card, no green/blue glow, and no decorative visual treatment. Use the quiet dark card style from the current mode-selection card.
- Keep the richer information density from the detailed concept: tool readiness, install state, scanner plan, detected languages, skipped-tool reasons, live scanner lanes, finding counts, and logs should be available from expandable step details.

### Proposed Flow

1. Inspecting project.
2. Choosing scanner tools.
3. Preparing tools.
4. Running scans.
5. Model summary.
6. Report ready.

### UI Rules

- Keep the existing top buffer/spinner animation as the main motion element.
- The comment beside or under the buffer should update by stage, for example: `Scanning to see which tools this project needs...`.
- Very fast steps should still remain visible for about `2s` so progress feels readable rather than flickery.
- Each timeline step can expand inline to show details. Avoid nested floating cards.
- Completed/active/inactive states should use neutral Hermsec styling, not colored glow.

### Harness Rules

- Do not install every scanner for every user.
- Do not install scanner tools inside the scanned project.
- Do not run package lifecycle scripts.
- Prefer lockfile and manifest scanning where possible.
- Install optional scanners only into a versioned Hermsec runtime directory.
- Scanner selection should be capability-driven: languages, manifests, lockfiles, IaC files, and user scan mode decide which tools run.
- If a scanner is unavailable or skipped, the scan should continue with remaining tools and the card should explain why.

### Initial Scanner Targets

- Always consider secrets: Gitleaks.
- JS/TS/React: Semgrep, OSV/Trivy, npm audit where lockfiles exist.
- Java: Semgrep, Hermsec Java taint heuristics, OSV/Trivy or Dependency-Check for Maven/Gradle.
- Rust: Semgrep where supported plus OSV/Trivy/cargo-audit for Cargo files.
- PHP: Semgrep plus Composer audit/OSV/Trivy for Composer files.
- Go: gosec, govulncheck, OSV/Trivy for Go modules.
- IaC/config: Checkov and/or Trivy when Terraform/Kubernetes/Docker/GitHub Actions files are detected.

### Implemented First Pass

- Added the V3 adaptive pre-scan phase to inspect the selected project before launching the CLI scan.
- Added project profiling for languages, frameworks, manifests, lockfiles, and IaC markers.
- Added scanner planning/readiness rows for current runnable tools and planned/skipped future tools.
- Replaced the old chat progress disclosure with the simple neutral six-step timeline card.
- Added expandable inline step details and the neutral top buffer strip.
- Preserved honesty: future scanners are shown as planned/skipped until their adapters/installers exist.

## 2026-06-19 - Scanner-Managed Harness Expansion

### Changes

- Introduced a scanner catalog model for the root harness with each scanner's id, label, category, command, version, install kind, supported languages, input types, parser, default enabled state, auto-install behavior, and risk notes.
- Mirrored that catalog shape in V3 main-process scanner management so the desktop app can list scanner status, track per-scanner settings, and manage installs outside scanned repositories.
- Added scanner settings to V3 app settings:
  - `autoInstallMissing`
  - `allowOnlineUpdates`
  - `labInstallAll`
  - per-scanner `enabled`
  - per-scanner `autoInstall`
- Added V3 main-process scanner handlers for list/status/install/uninstall/update flows.
- Added managed scanner tool roots under Electron `userData\managed-scanners\<platform>-<arch>`, with managed `bin`, Python tool, npm prefix, and Go `GOBIN` locations.
- Expanded root external scanner coverage and parser coverage beyond the original baseline. The current catalog includes Hermsec heuristics, Semgrep, Gitleaks, TruffleHog, OSV-Scanner, Trivy, Checkov, Bandit, pip-audit, SafeDep PMG npm audit, Retire.js, FindSecBugs/SpotBugs, OWASP Dependency-Check, Psalm, Composer audit, gosec, govulncheck, cargo-audit, Brakeman, Flawfinder, Cppcheck, and .NET vulnerable package checks.
- Root scanner execution now respects `HERMSEC_ENABLED_SCANNERS`, allowing V3 settings to narrow which external scanners run for the selected project.
- The adaptive scan tracker from the previous pass remains the user-facing progress surface and should receive richer scanner-managed details: selected tools, managed/PATH readiness, install attempts, skipped reasons, failure messages, and finding counts.

### Adaptive Workflow

1. Inspect the selected project without running dependency installs or build scripts.
2. Detect languages, frameworks, manifests, lockfiles, Docker/IaC/workflow markers, and benchmark/lab profile needs.
3. Match the project profile against scanner capabilities from the catalog.
4. Verify each selected scanner from Hermsec managed tools first, then PATH/system locations.
5. If the user enabled auto-install and the scanner has a safe installer, install it into the Hermsec managed scanner root, not the scanned project.
6. Pass scanner enablement and managed executable paths into the root CLI.
7. Run only relevant scanners; continue on optional scanner skips/failures and record why.
8. Generate reports with scanner status, assist mode, model summary/deep-assisted metadata, and scanner-confirmed merge evidence.

### Settings > Scanners Handoff

- Intended user surface: `Settings > Scanners` should show the catalog, status, managed/system path, enable toggle, auto-install toggle, install/update/uninstall actions, and whether each scanner applies to the current project.
- Current source state observed by this documentation pass: V3 settings data, main-process IPC handlers, preload scanner APIs, Settings sidebar entry, and `ScannersSettings` renderer panel are wired in the current tree.
- Treat the visible Settings > Scanners tab as the next verification/polish task: run typecheck/build, open the UI, exercise list/status/filter/toggle/install/update/remove paths, and confirm scan launches receive the expected scanner env.

### Benchmark Plan

- Keep OWASP BenchmarkJava as the standing Java recall/precision gate.
- Add OpenSSF CVE Benchmark for JS/TS dependency and application vulnerability coverage.
- Add focused small fixture projects for Go, Rust, PHP, Ruby/Rails, C/C++, .NET, Terraform, Kubernetes, Docker, and GitHub Actions where possible.
- Track scanner-specific runtime, status, skipped reasons, failed command details, finding counts, TP/FP/FN/TN, precision, recall, F1, and duplicate-noise rates.
- Keep benchmark raw exports opt-in with `HERMSEC_BENCHMARK_EXPORT_RAW=1`; normal app reports should remain redacted.
- Start new scanner gates as advisory/non-blocking until managed installs and platform behavior stabilize on Windows, macOS, and Linux.

### Known Limitations And Struggles

- Root and V3 currently duplicate scanner catalog content. This can drift unless V3 consumes the root catalog or code generation is added.
- Managed installers are partial. Python/npm/Go install paths exist, but native release download/checksum installers still need durable implementation for tools such as Trivy and other binaries.
- The Settings > Scanners user interface is newly wired and still needs runtime UI verification.
- Some tools have intrinsic setup constraints: FindSecBugs/SpotBugs needs compiled classes, Dependency-Check needs database/cache strategy, Psalm needs project config, Composer audit needs Composer available, and Checkov/Trivy may require online data setup.
- Large scans can still be slow or noisy. Semgrep chunking helps, but scanner timeouts/output caps need per-tool tuning.
- PATH versus managed-tool precedence must stay predictable and visible in the UI.
- macOS/Linux managed scanner behavior has not yet been verified.

### Next Steps

- Verify the renderer Settings > Scanners tab and preload scanner API with typecheck/build plus a manual UI pass.
- Deduplicate scanner catalog data between root and V3.
- Feed scanner settings and managed executable overrides into every V3 scan launch path, including manual scans, dashboard Scan again, automation Run Now, and scheduled due checks.
- Add checksum-backed native installers and update/uninstall tests.
- Add unit tests for scanner enable/disable filtering, install failure handling, managed path precedence, and parser coverage for the expanded scanner stack.
- Run root typecheck/tests and V3 typecheck/build after the scanner-managed flow is fully wired.

## 2026-06-19 - Scanner Harness Verification And Prep Wiring

### Changes

- Fixed root TypeScript blockers introduced by the expanded scanner stack:
  - added source counters for the expanded language union
  - corrected Cargo audit parser typing
  - corrected SARIF parser exact-optional-property typing
  - parsed .NET transitive package vulnerabilities
  - routed cppcheck stderr into parser normalization
- Tightened scanner command validation for the expanded tool list so each scanner only runs the safe argument shape HermSec builds.
- Changed disabled scanner behavior so disabled tools are omitted from scanner statuses instead of showing as skipped lanes.
- Clarified scanner env semantics:
  - unset `HERMSEC_ENABLED_SCANNERS` uses default-enabled catalog tools
  - `all` enables lab/all-scanners mode
  - `__none__` or empty means no external scanners
- Wired V3 scan preparation to `prepareScannersForProject()` so auto-install can run during the Preparing tools stage and failed installs show as failed detail rows.
- Added row-level action messages in Settings > Scanners so failed/manual install attempts are visible.
- Expanded packaged runtime scanner command lookup to include the new scanner command names.
- Made Trivy and OWASP Dependency-Check respect `HERMSEC_SCANNER_ONLINE_UPDATES=false` with no-update flags.

### Issues Encountered

- Root typecheck initially failed from exact TypeScript typing issues after adding new parsers and languages.
- External scanner tests still assumed the old six-scanner world.
- The first `npm test -- tests/...` command ran the compiled suite and then tried to execute source `.ts` test files directly, causing extra module-resolution failures unrelated to the implementation.
- V3 initially only displayed scanner readiness but did not actually consume auto-install settings in the scan prep stage.

### How We Solved Them

- Fixed the TypeScript errors and parser shapes directly.
- Pinned legacy scanner tests with a six-scanner `HERMSEC_ENABLED_SCANNERS` control group.
- Ran scanner tests directly from `dist` after build to avoid direct source `.ts` execution.
- Added the V3 prep function and re-rendered the plan after install attempts.

### Verification

- `npm.cmd run typecheck` passed at the root.
- `npm.cmd run typecheck` passed in `v2\hermsec-v3`.
- `npm.cmd run build` passed at the root.
- `npm.cmd run build` passed in `v2\hermsec-v3`.
- `node --test dist\tests\unit\scanners\externalScanners.test.js` passed `7/7`.
- `node --test dist\tests\unit\scanners\scannerHeuristics.test.js` passed `10/10`.
- CLI smoke scan completed with `10` findings and wrote artifacts under `.hermsec\smoke-runs\scanner-harness-expansion\node-express-vulnerable\2026-06-19T15-25-00-868Z`.

### Remaining Work

- Deduplicate root/V3 scanner catalog data.
- Add checksum-backed native binary installers.
- Manually verify Settings > Scanners in the running V3 app.
- Add tests for scanner settings persistence, installer failure rows, managed path precedence, and automation scan launch env.
- Add ecosystem benchmarks beyond OWASP BenchmarkJava.

## 2026-06-19 - End-To-End Verification Goal Run

### What Was Verified

- Root full suite passed after rebuild: `70/70`.
- Root typecheck passed.
- V3 typecheck passed.
- V3 production build passed.
- V3 Doctor smoke passed with healthScore `100`, required `7/7`, scanners `6/6`, internet `5/5`, provider warning tolerated.
- V3 dashboard smoke passed, generated dashboard HTML and a non-empty one-page PDF.
- Real Electron Settings > Scanners UI was opened through Chrome DevTools Protocol with the actual preload API present.
- Electron UI scanner catalog returned `22` scanner rows and rendered auto-install, online update, benchmark lab, filters, status chips, project chips, and scanner rows.
- Browser renderer shell loaded at `http://localhost:5173`; only browser console error was missing `favicon.ico`.
- CLI scan fallbacks passed for no external scanners, deep-assisted without model, and all/lab scanner selection with advisory updates disabled.

### Added Coverage

- Added a regression test in `tests\unit\scanners\externalScanners.test.ts` for scanner env selection:
  - unset/default scanner set
  - `__none__`
  - explicit scanner list
  - `all` lab scanner set

### Artifacts

- Electron UI screenshot: `output\playwright\v3-electron-scanners-verified.png`.
- Dashboard smoke artifact: `.hermsec\v3-dashboard-smoke\hermsec-node-express-vuln-lab\2026-06-19T15-30-41-878Z\dashboard\index.html`.
- No-external scan artifacts: `.hermsec\e2e-runs\none-scanners`.
- Deep-assisted no-model artifacts: `.hermsec\e2e-runs\deep-no-model`.
- All/lab offline-update artifacts: `.hermsec\e2e-runs\all-offline-updates`.

### Issues And Resolutions

- Playwright browser binary was missing; installed Chrome for Testing and reran the probe.
- Browser-only renderer cannot validate Electron preload; used real Electron CDP automation for Settings > Scanners.
- First CDP cleanup waited on a browser-close response too long; reran with strict cleanup and verified successfully.

### Remaining Caveats

- Doctor scanner group still checks the legacy six scanner commands, not all `22` Settings scanner catalog entries.
- Provider readiness warning does not fail Doctor smoke in isolated smoke homes.
- `scanners:list` may create managed scanner directories while checking status.
- Native checksum-backed installers and direct parser fixtures for the full expanded scanner stack are still future work.

## 2026-06-19 - Desktop Release CI And macOS Installer Link

### Changes

- Added `.github\workflows\desktop-release.yml`.
- Workflow triggers:
  - `push` tags matching `v*`
  - manual `workflow_dispatch` with `tag_name`
- Workflow builds:
  - Windows x64 via `npm run dist:win`
  - macOS via `npm run dist:mac`
- Workflow uploads desktop artifacts and creates or updates a GitHub Release with those assets.
- Root README now links macOS users to `https://github.com/sethwhenton/hermsec/releases/latest`.
- Root README documents local macOS packaging with `npm run dist:mac`.
- V3 README documents macOS packaging and the release workflow.

### Verification

- Root `npm.cmd run typecheck` passed.
- V3 `npm.cmd run typecheck` passed.

### Caveats

- macOS builds are unsigned until Apple Developer ID signing and notarization secrets are configured.
- The actual macOS package build must run on GitHub's macOS runner; it cannot be validated from this Windows machine.
- No live GitHub Release was created locally because `gh` is not installed and the workflow is not on GitHub until committed/pushed.

### Publish Flow

1. Commit and push the release workflow and app changes to `main`.
2. Push a version tag, for example `git tag v0.1.0 && git push origin v0.1.0`.
3. GitHub Actions builds Windows and macOS packages.
4. The release job creates or updates the GitHub Release for that tag.

## Update Rules For This File

- Add a new dated section for every meaningful milestone.
- Record command results when they prove a capability or expose a regression.
- Keep secrets out of the file.
- Prefer concise metrics over long command output.
- Link or list local artifact paths when a report/score was generated.
