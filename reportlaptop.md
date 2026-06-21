# Hermsec Laptop Work Report

Date: 2026-06-19
Workspace: `C:\Users\whent\Documents\Personal Proj\Hermsec`
Active app: `desktop`
Current committed context: prior commit `42d87c9` (`Bundle scanner runtime with V3 app`) was pushed to `main`. No new commit is documented here.

## Executive Summary

Hermsec has moved from a root CLI plus early desktop experiments into a substantially working V3 Electron app. The current V3 app can run scanner-backed project scans, show a live Doctor readiness dashboard in chat, generate local dashboard and one-page reports, expose scan modes through manual and automation flows, and package a self-contained Windows executable with the scanner runtime bundled.

The scanner stack validated on this laptop includes Semgrep, Gitleaks, Bandit, OSV-Scanner, pip-audit, SafeDep PMG npm audit, built-in Hermsec heuristics, and internet/provider readiness checks. The packaged Windows app smoke-tested successfully with Doctor reporting `100%` health.

BenchmarkJava work also progressed meaningfully: Java/JSP/Maven discovery and Java servlet heuristics were added, producing thousands of OWASP BenchmarkJava findings and a useful tools-only score. Agent-assisted benchmark attempts exposed important next-fix areas: deep-assisted intent misrouting, large model summary stalls, Semgrep timeout behavior, and scoring fragility when redacted reports are used.

## Scope And Ownership

This report documents work completed so far. It does not modify project source and does not create a new commit.

Security note: a temporary OpenCode Go credential was used during testing. The raw key is intentionally not included here. A tiny provider smoke test succeeded using `opencode-go/deepseek-v4-flash`.

## V3 App Work

| Area | Work completed | Important paths |
| --- | --- | --- |
| Doctor card and live dashboard | The Doctor chat card now appears immediately, streams progress from Electron main, updates scanner/internet/provider rows, and has timeout fallbacks so it cannot spin forever. | `v2\hermsec-v3\src` |
| Scan modes | V3 now exposes two user-facing assist modes: `Scanner + model summary` and `Deep assisted scan`. Scan requests ask for a mode before running. | `v2\hermsec-v3` and root CLI |
| Model summary and deep-assisted plans | The root CLI accepts `--assist-mode scanner-model-summary|deep-assisted`; V3 passes the mode through and report artifacts record assist-mode metadata. | `dist\src\bin\hermsec.js`, V3 main process |
| Automation scan-mode toggles | The same scan-mode segmented control is used in Settings, the automation popover, the Automations manager/editor, manual Run Now, dashboard Scan again, and background due checks. | `v2\hermsec-v3` |
| Report UI updates | V3 writes scanner-backed dashboard and one-page report artifacts and now shows assist mode and scanner-confirmed merge information in report views. | Generated reports under `.hermsec\...` and `C:\Users\whent\Documents\Hermsec\...` |
| Packaged runtime tools | The Windows package bundles the root Hermsec CLI plus scanner runtime tools, resolving them from packaged resources before falling back to PATH. | `v2\hermsec-v3\resources\runtime-tools\win32-x64`, `v2\hermsec-v3\resources\hermsec-cli` |
| README updates | Root and V3 README content was updated to describe Windows packaging, bundled scanners, Doctor checks, and provider-key handling. | `README.md`, `v2\hermsec-v3\README.md` |
| EXE packaging | `npm.cmd run dist:win` produced the installer and portable Windows app. These are ignored build artifacts intended for GitHub Release assets, not git. | `v2\hermsec-v3\release\Hermsec Setup 0.1.0.exe`, `v2\hermsec-v3\release\Hermsec 0.1.0.exe` |

## Tools Bundled And Validated

| Tool/check | Version or status | Validation note |
| --- | --- | --- |
| Semgrep | `1.167.0` | Installed locally via `uv tool install`; bundled into V3 runtime. Timed out on large BenchmarkJava run. |
| Gitleaks | `8.30.1` / `v8.30.1` | Installed from official release zip with checksum verification; bundled into V3 runtime. |
| Bandit | `1.9.4` | Installed locally via `uv tool install`; bundled into V3 runtime. |
| OSV-Scanner | `2.4.0` / `v2.4.0` | Installed from official release exe with checksum verification; bundled into V3 runtime. |
| pip-audit | `2.10.1` | Installed locally via `uv tool install`; bundled into V3 runtime. |
| SafeDep PMG | `0.19.1` / `v0.19.1` | Installed from official release zip with checksum verification; bundled into V3 runtime. |
| Internet checks | GitHub, npm, OSV, CISA KEV, NVD website | Doctor reached all expected sources in the verified V3 smoke. |
| Provider checks | OpenCode Go path verified | Temporary OpenCode Go credential was verified without exposing the key. |

## Verification Completed

| Verification | Result |
| --- | --- |
| Root typecheck | `npm.cmd run typecheck` passed. |
| Root build | `npm.cmd run build` passed and refreshed `dist\src\bin\hermsec.js`. |
| V3 typecheck | `cd v2\hermsec-v3 && npm.cmd run typecheck` passed. |
| V3 build | `cd v2\hermsec-v3 && npm.cmd run build` passed. |
| Windows package | `cd v2\hermsec-v3 && npm.cmd run dist:win` completed. |
| Packaged exe Doctor smoke | `release\win-unpacked\Hermsec.exe --smoke-doctor` passed with status `ready`, health score `100`, required `7/7`, scanners `6/6`, internet `5/5`, providers `1/1`. |
| Packaged dashboard smoke | Passed with bundled CLI/scanners and wrote reports under `C:\Users\whent\Documents\Hermsec\smoke-reports\...`. |
| V3 Doctor smoke | Passed against the normal V3 profile with Doctor at `100%`. |
| V3 dashboard smoke | Passed and generated dashboard HTML plus non-empty one-page PDF. |
| V3 app localhost testing | V3 was run locally during testing, including localhost/browser-style development validation. |
| Root Doctor | Returned `15 passed`, `0 warnings`, `0 failed`, with optional checks skipped where appropriate. |

## Git Status And Commit Context

- Latest relevant commit: `42d87c9 Bundle scanner runtime with V3 app`.
- That commit was previously pushed to `main`.
- No new commit should be invented for this report.
- Current notable local status before this report: `v2\hermsec-v3\package-lock.json` was untracked and intentionally left unstaged.

## Benchmark Work

### OWASP BenchmarkJava Setup

| Item | Value |
| --- | --- |
| Benchmark repo | `OWASP-Benchmark/BenchmarkJava` |
| Local clone | `.hermsec-benchmarks\BenchmarkJava` |
| Expected labels | `.hermsec-benchmarks\BenchmarkJava\expectedresults-1.2.csv` |
| Expected total tests | `2740` |
| Expected vulnerable tests | `1415` |
| Expected safe tests | `1325` |

### Earlier Tools-Only Java Result

The first Java harness improvement made BenchmarkJava visible to Hermsec and added Java/JSP/XML/properties/Gradle/Maven discovery, Java servlet heuristics, and starter Java Semgrep rules.

| Metric | Result |
| --- | --- |
| Findings | `3247` |
| True positives | `1220` |
| False positives | `708` |
| False negatives | `195` |
| True negatives | `617` |
| Precision | `0.6328` |
| Recall | `0.8622` |
| F1 | `0.7299` |
| Main artifacts | `.hermsec\benchmark-java-after-java-result.json`, `.hermsec\benchmark-java-after-java-score.json`, `.hermsec\benchmark-java-after-java\benchmarkjava\2026-06-09T17-30-45-803Z\report.html` |

### June 19 Benchmark Runs

| Run | Result |
| --- | --- |
| Tools-only BenchmarkJava run | Generated `3249` findings: `1190` high, `2059` medium, `2` secrets, `1` scanner failure. Artifact path: `.hermsec\benchmark-runs\BenchmarkJava-tools-20260619-150653\benchmarkjava\2026-06-19T13-09-08-614Z\summary.json`. |
| Attempted agent-assisted run | Produced the same broad finding shape, but report metadata showed `generatedWithModel=false`; `agent-summary.json` said to route the request to the scanner harness and did not produce model-backed priority actions. |
| OpenCode Go smoke | A tiny provider smoke passed using provider `opencode-go` and model `deepseek-v4-flash`; the credential was verified from the environment without printing the key. |
| Deep-assisted routing bug | The attempted agent-assisted/deep path misrouted back to scanner-only behavior instead of producing a model-supported benchmark report. |
| Large model summary stall | Large BenchmarkJava model summary attempts stalled or produced no useful console output, indicating the need for chunked summarization and a watchdog. |
| Semgrep timeout | Semgrep timed out after `45000ms` during BenchmarkJava scanning; the scan continued and recorded the failure. |

### Post-Fix Implementation Pass

After the benchmark issues were identified, a follow-up implementation pass fixed the scanner/model harness while keeping benchmark-specific behavior opt-in and outside the normal Hermsec user flow.

| Fix | Status | Notes |
| --- | --- | --- |
| Deep-assisted routing | Implemented | The harness now forces completed scanner evidence into `explain_findings`, and the intent router prioritizes explain/summarize/findings language before scan routing. |
| Chunked model summarization | Implemented | Model explanations are prioritized and chunked; fallback explanations remain available for every scanner finding. Default cap is controlled by `HERMSEC_MODEL_FINDING_LIMIT`, chunk size by `HERMSEC_MODEL_CHUNK_SIZE`. |
| Model watchdog | Implemented | Per-chunk and total model watchdogs prevent large provider calls from stalling indefinitely. |
| Semgrep large-repo behavior | Implemented | Large source sets are split into Semgrep chunks with larger safe timeouts and per-chunk `--output` JSON files to reduce stdout truncation. |
| Java taint tracking | Implemented initial pass | Java heuristics now track servlet request/cookie sources, aliases/builders, common sanitizers, and sinks for SQL, LDAP, XPath, file, response, session, and process APIs. This is lightweight intraprocedural taint tracking, not a full Java compiler. |
| Benchmark-safe scoring export | Implemented | `HERMSEC_BENCHMARK_EXPORT_RAW=1` writes `benchmark-findings.raw.json` beside a report. Normal user-facing reports remain redacted. |
| OWASP CI gate | Implemented | `scripts\eval-owasp-benchmark.mjs`, `npm run eval:owasp`, and `.github\workflows\owasp-benchmark.yml` provide opt-in BenchmarkJava gates. The local script skips cleanly when the benchmark repo is missing. |

Post-fix verification completed successfully: `npm.cmd test` rebuilt the root project and passed `69/69` tests.

### Post-Fix OWASP BenchmarkJava Gate

The follow-up gate was run locally in offline mode against `.hermsec-benchmarks\BenchmarkJava`.

| Metric | Result |
| --- | --- |
| Output directory | `.hermsec\benchmark-runs\owasp-benchmarkjava-after-fixes\benchmarkjava\2026-06-19T13-28-18-850Z` |
| Raw benchmark export | `benchmark-findings.raw.json` |
| Total findings | `2810` |
| True positives | `1209` |
| False positives | `650` |
| False negatives | `206` |
| True negatives | `675` |
| Precision | `0.6503` |
| Recall | `0.8544` |
| F1 | `0.7385` |
| Gate | Passed with recall threshold `0.70` and precision threshold `0.55` |

The post-fix run reduced raw findings from `3249` to `2810` while preserving strong recall. Precision improved modestly, but false positives remain high in command injection, LDAP, XPath, path traversal, trust boundary, and SQLi. These are now measurable through the benchmark gate.

## Struggles And Issues

| Issue | Impact | Recommendation |
| --- | --- | --- |
| PowerShell quoting with spaces in paths | Commands involving `C:\Users\whent\Documents\Personal Proj\Hermsec` were fragile unless paths were quoted carefully. | Prefer `-LiteralPath`, quoted paths, `npm.cmd`, and explicit `workdir` usage. |
| Benchmark report redaction breaking scoring | Redacted report artifacts can remove or alter evidence needed by the BenchmarkJava scorer. | Implemented opt-in `benchmark-findings.raw.json`; keep normal reports redacted. |
| Semgrep timeout | BenchmarkJava is large enough that a single Semgrep invocation hit the `45000ms` cap and recorded a scanner failure. | Implemented Semgrep chunking and per-chunk output files; continue tuning thresholds with real CI data. |
| Deep-assisted intent misrouting | Agent-assisted benchmark attempt ended with `generatedWithModel=false` and a scanner-harness routing message. | Implemented forced explain routing from the harness plus explain-first intent routing. |
| Large model summary stall | Full BenchmarkJava evidence is too large for one naive model pass. | Implemented prioritized chunking and watchdogs; next step is hierarchical summary synthesis across chunks. |
| Untracked V3 package-lock | `v2\hermsec-v3\package-lock.json` remains untracked and intentionally unstaged. | Leave it unstaged unless a future packaging/dependency task explicitly wants to own it. |

## Recommendations And Remaining Next Fixes

1. Run the new CI BenchmarkJava gate on GitHub and tune stable thresholds after a few real CI samples.
2. Raise Java precision next: command injection, LDAP, XPath, path traversal, trust boundary, and SQLi still have high false positive rates.
3. Add deeper Java taint modeling for helper classes, interprocedural flows, collection/map flows, and category-specific sanitizers.
4. Add a second-stage model synthesis step that merges chunk summaries into one concise executive summary without sending all raw findings at once.
5. Add OpenSSF CVE Benchmark for JS/TS after BenchmarkJava stabilizes.
6. Add CASTLE only when Hermsec intentionally supports C/C++ scanning.
7. Keep benchmark/eval exports opt-in so the original Hermsec desktop and report experience remains user-friendly and redacted.

## Key Logs / Evidence

| Evidence | Summary |
| --- | --- |
| Doctor readiness | Packaged and V3 smoke Doctor reported `100%`, required `7/7`, scanners `6/6`, internet `5/5`, providers `1/1`. |
| BenchmarkJava findings | June 19 tools run generated `3249` findings. |
| Post-fix BenchmarkJava gate | Offline opt-in gate generated `2810` findings with precision `0.6503`, recall `0.8544`, F1 `0.7385`. |
| Semgrep timeout | Benchmark logs recorded: `Semgrep timed out after 45000ms`; the scan continued with one scanner failure. |
| Agent-assisted report metadata | Agent run summary reported `generatedWithModel=false`. |
| Agent summary fallback | `agent-summary.json` said: `Route this request to the scanner harness. The agent itself does not create findings or mutate scanner evidence.` |
| OpenCode Go smoke | Provider smoke passed with provider `opencode-go` and model `deepseek-v4-flash`; credential details were redacted. |
| Windows package artifacts | `v2\hermsec-v3\release\Hermsec Setup 0.1.0.exe` and `v2\hermsec-v3\release\Hermsec 0.1.0.exe` were produced by `dist:win`. |

## Current State

Hermsec V3 is the active product surface. The root CLI remains the reusable scanner/report engine, and the Windows desktop package is now self-contained for the current scanner stack. The biggest next engineering gains are now precision and benchmarking maturity: tuning Java taint tracking, making CI benchmark thresholds stable, and adding the next benchmark suites without changing the original Hermsec desktop experience.

## Iteration Log

This section is append-only. New work should be added as another iteration instead of rewriting earlier notes. The goal is to preserve what happened, what went wrong, how it was solved, and what should happen next.

### Iteration 1 - V3 Doctor, Runtime Packaging, And App Readiness

| Item | Notes |
| --- | --- |
| Goal | Make Hermsec V3 feel like the main app surface and ensure a user can install it with the scanner runtime ready. |
| What we changed | Added the live Doctor chat dashboard, Doctor IPC progress events, scanner/internet/provider rows, timeout fallbacks, V3 scan-mode controls, automation scan-mode controls, report UI updates, and packaged runtime resolution for the bundled CLI/scanner tools. |
| How we approached it | Kept the root CLI as the scanner/report engine and made V3 call into it. The Electron app now resolves bundled tools from packaged resources before falling back to PATH. |
| What went wrong | Early Doctor checks could run too quietly or appear late in chat. The packaged app initially risked using Electron's executable path instead of Node for CLI tasks. NVD API checks were noisy/transient. |
| How we solved it | The Doctor card now appears immediately and streams status. Packaged execution uses the bundled/runtime Node path correctly. NVD was treated through a website reachability check instead of making the entire Doctor fragile around API availability. |
| Verification | Root typecheck/build passed, V3 typecheck/build passed, `dist:win` completed, packaged Doctor smoke reported `100%`, required `7/7`, scanners `6/6`, internet `5/5`, providers `1/1`. |
| Remaining next | Keep Doctor checks stable as more tools are bundled and add clearer remediation text for missing optional tools. |

### Iteration 2 - Complete Windows Package And GitHub Push

| Item | Notes |
| --- | --- |
| Goal | Make the app installable as a complete Windows package and push the current work to GitHub. |
| What we changed | Added packaging scripts for the root CLI bundle and runtime scanner tools. Updated README files, project context, project report tracking, and package scripts. |
| How we approached it | Generated the root CLI bundle and runtime-tools folder before Electron Builder runs, then used Electron Builder `extraResources` for packaged resources. |
| What went wrong | Generated package/release artifacts are large and should not be committed. A V3 `package-lock.json` stayed untracked and was intentionally left out because it was pre-existing/unowned. |
| How we solved it | Kept generated release/runtime artifacts ignored. Committed only source/docs/scripts and pushed commit `42d87c9` to `main`. |
| Verification | Commit `42d87c9 Bundle scanner runtime with V3 app` was pushed to `origin/main`. The V3 app was also run locally for user testing at `http://localhost:5173`. |
| Remaining next | Publish `.exe` artifacts through a GitHub Release flow rather than storing them in git. |

### Iteration 3 - OWASP BenchmarkJava Baseline

| Item | Notes |
| --- | --- |
| Goal | Test how good the Hermsec harness is against OWASP BenchmarkJava using tools-only first, then agent-plus-tools. |
| What we ran | Local benchmark target: `.hermsec-benchmarks\BenchmarkJava`. Tools-only scan generated `3249` findings: `1190` high, `2059` medium. |
| How we approached it | Ran the root CLI against the local BenchmarkJava clone in online mode with scanner tools enabled. Used expected labels from `expectedresults-1.2.csv` to estimate performance. |
| What went wrong | The first foreground scan hit the shell command timeout even though the report artifact was produced. Semgrep timed out after `45000ms`, so most detections came from Hermsec Java heuristics. Report redaction changed Benchmark test filenames to `[REDACTED_SECRET].java`, making direct scoring from user-facing reports fragile. |
| How we solved it | Parsed generated artifacts and reconstructed/scored results where possible. Documented the need for raw benchmark-safe exports that do not weaken normal report redaction. |
| Baseline result | Tools-only/raw benchmark result was useful but noisy: high recall, high false positives, and one scanner failure from Semgrep timeout. |
| Remaining next | Add Semgrep chunking, raw benchmark exports, and CI gates so this benchmark can be repeated reliably. |

### Iteration 4 - Agent-Assisted Benchmark Attempt

| Item | Notes |
| --- | --- |
| Goal | Compare tools-only against agent-plus-tools using OpenCode Go and DeepSeek Flash. |
| What we ran | Attempted deep-assisted scan/report on the same BenchmarkJava target. A separate tiny OpenCode Go smoke call succeeded with provider `opencode-go` and model `deepseek-v4-flash`. |
| How we approached it | Temporarily configured the CLI for model use during the benchmark. The credential was passed through the environment only and was not written to repo files. After testing, CLI config was restored to `preferredModelProvider=none` and `privacyMode=local-only`. |
| What went wrong | Deep-assisted prompt text contained the word `scan`, so the intent router classified it as `scan_target`. The model was skipped and `agent-summary.json` showed `provider: none`, `generatedWithModel=false`. A later direct model-backed scan could stall on the large `3249`-finding payload. |
| How we solved it | Confirmed the provider/API itself worked with a tiny JSON smoke request. Identified the true failures as scan-assist routing and large-payload model orchestration. No raw credential was persisted. |
| Result | The attempted agent-plus-tools benchmark did not outperform tools-only because it did not actually use the model. This was a harness bug, not an OpenCode Go/API failure. |
| Remaining next | Force completed scanner evidence into explanation mode, chunk model summaries, and add watchdogs. |

### Iteration 5 - Scanner/Model Harness Fixes

| Item | Notes |
| --- | --- |
| Goal | Fix the benchmark blockers without changing the original Hermsec app experience. Benchmark behavior should remain opt-in and temporary. |
| What we changed | Added forced `explain_findings` routing from the harness, explanation-first intent routing, chunked/prioritized model explanations, model watchdogs, Semgrep chunking with per-chunk JSON output, Java taint tracking, raw benchmark export, `npm run eval:owasp`, and an OWASP BenchmarkJava GitHub workflow. |
| How we approached it | Kept normal reports redacted and user-friendly. Added `HERMSEC_BENCHMARK_EXPORT_RAW=1` so benchmark runs can write `benchmark-findings.raw.json` only when explicitly requested. |
| What went wrong | The first implementation needed a TypeScript exact-optional-property fix. The model-limit behavior also needed a correction so successful chunked model summaries still count as model-generated instead of being treated as a skipped model run. |
| How we solved it | Fixed the optional type, adjusted model skipped/fallback semantics, and added unit tests for forced explanation routing, chunk limits, and watchdog fallback. |
| Java taint changes | Added lightweight intraprocedural tracking for servlet request/cookie sources, aliases, builder-style propagation, sanitizer expressions such as ESAPI/OWASP Encoder/StringEscapeUtils/HtmlUtils, and sinks for SQL, LDAP, XPath, file, response, session, and process APIs. |
| Semgrep changes | Large source sets are split into chunks with longer safe timeouts and per-chunk `--output` JSON files to avoid stdout truncation. |
| Benchmark export changes | `benchmark-findings.raw.json` is written beside the report only when `HERMSEC_BENCHMARK_EXPORT_RAW=1`. Normal report artifacts continue to use redaction. |
| CI changes | Added `.github\workflows\owasp-benchmark.yml`, which clones BenchmarkJava and runs `npm run eval:owasp`. The local script skips cleanly if BenchmarkJava is missing. |
| Verification | `npm.cmd test` rebuilt the root project and passed `69/69` tests. `node scripts/eval-owasp-benchmark.mjs --mode offline --out .hermsec\benchmark-runs\owasp-benchmarkjava-after-fixes --min-recall 0.70 --min-precision 0.55` passed. |
| Post-fix score | Offline gate produced `2810` findings, precision `0.6503`, recall `0.8544`, F1 `0.7385`. Raw findings dropped from `3249` to `2810` while preserving strong recall. |
| Remaining next | Tune false positives in command injection, LDAP, XPath, path traversal, trust boundary, and SQLi. Add deeper helper/interprocedural taint handling later. |

### Iteration 6 - Documentation And Reporting Discipline

| Item | Notes |
| --- | --- |
| Goal | Keep a durable laptop-side record of what changed, what failed, how it was solved, and what comes next. |
| What we changed | Created this root-level `reportlaptop.md` file and then appended this iteration log. |
| How we approached it | Used subagents for parallel work: one documentation-only agent and one xhigh implementation agent. The main thread reviewed, verified, and reconciled the work. |
| What went wrong | The first report draft was useful but read like a summarized status report. The user clarified that new work should be appended as iterations and should list the full process, not overwrite history. |
| How we solved it | Appended this `Iteration Log` section with goals, changes, approach, problems, solutions, verification, and next steps. Future updates should add new iterations here. |
| Security note | The temporary OpenCode Go credential is not included in this file. A repo scan for the raw key pattern returned no matches. |
| Current uncommitted state | Source changes, tests, `.github\workflows\owasp-benchmark.yml`, `scripts\eval-owasp-benchmark.mjs`, `tests\unit\agentRuntime.test.ts`, and `reportlaptop.md` are present. The unrelated `v2\hermsec-v3\package-lock.json` remains untracked and intentionally untouched. |

### Current Next Steps

1. Review the new OWASP workflow thresholds after it runs on GitHub.
2. Commit the implementation and `reportlaptop.md` when ready.
3. Re-run BenchmarkJava in online mode with Semgrep chunking to see whether Semgrep now completes.
4. Add a true model-assisted benchmark run after confirming chunked model summaries mark `generatedWithModel=true`.
5. Add OpenSSF CVE Benchmark for JS/TS once Java benchmark gates are stable.
6. Keep app-facing Hermsec behavior unchanged: benchmark exports stay opt-in, normal reports stay redacted, and local/default privacy remains local-only unless the user chooses otherwise.

### Iteration 7 - Real Model-Backed BenchmarkJava Deep-Assisted Run

| Item | Notes |
| --- | --- |
| Goal | Re-run OWASP BenchmarkJava with a real model-backed deep-assisted report after the routing/chunking fixes, then compare the actual score and document anything that failed along the way. |
| First full attempt | Ran BenchmarkJava with `--assist-mode deep-assisted`, OpenCode Go, DeepSeek Flash, and model chunking set to a larger top-N. The static scan completed and produced `9384` findings, but `agent-summary.json` reported `provider: none`, `generatedWithModel=false`, and `fallbackReason: provider-failed`. |
| What went wrong | The provider credential was valid, but the first real model chunk failed before any chunk completed. The earlier top-N/chunk settings were too aggressive for this provider/run shape. |
| How we diagnosed it | Restored config to `local-only`/`none`, then ran temporary process-only provider smoke tests. OpenCode Go JSON-mode completion succeeded with model `deepseek-v4-flash`; plain text returned no message content. A model-only summary smoke test over the completed BenchmarkJava findings succeeded with `providerUsed: opencode-go` for top 5 findings, then succeeded again for top 10 findings with chunk size 2. |
| Tuning that worked | Used `HERMSEC_MODEL_FINDING_LIMIT=10`, `HERMSEC_MODEL_CHUNK_SIZE=2`, `HERMSEC_MODEL_CHUNK_TIMEOUT_MS=60000`, and `HERMSEC_MODEL_SUMMARY_WATCHDOG_MS=300000`. This kept the model phase bounded and successful. |
| Launch issue | A relaunch failed immediately because Windows `Start-Process` split the target path at the space in `Personal Proj`, so Hermsec saw `C:\Users\whent\Documents\Personal` as the target. |
| How we solved launch issue | Relaunched with explicit quoted target and output paths. This was a test harness launch mistake, not a Hermsec scanner bug. |
| Successful run | Full BenchmarkJava deep-assisted online scan completed with `generatedWithModel=true`, provider `opencode-go`, full scanner findings `9384`, and model explanations generated for the top 10 prioritized findings while fallback evidence-bound explanations covered the remaining `9374`. |
| Raw benchmark export | Enabled `HERMSEC_BENCHMARK_EXPORT_RAW=1` for the successful run. Raw export was written to `.hermsec\benchmark-runs\BenchmarkJava-deep-assisted-model-real-20260619-155145\benchmarkjava\2026-06-19T13-56-07-856Z\benchmark-findings.raw.json`. |
| Score file | Saved scorer output to `.hermsec\benchmark-runs\BenchmarkJava-deep-assisted-model-real-20260619-155145\benchmarkjava\2026-06-19T13-56-07-856Z\benchmark-score.json`. |
| Final score | OWASP BenchmarkJava score: `1238` TP, `728` FP, `177` FN, `597` TN, precision `0.6297`, recall `0.8749`, F1 `0.7323`, accuracy `0.6697`, false positive rate `0.5494`. |
| Category strengths | `crypto`, `hash`, `securecookie`, and `weakrand` were strongest. `crypto` scored precision `1.0`, recall `1.0`; `securecookie` scored precision `1.0`, recall `0.9167`; `weakrand` scored precision `0.8074`, recall `1.0`. |
| Category weaknesses | False positives remain high for `cmdi`, `ldapi`, `pathtraver`, `sqli`, `trustbound`, `xpathi`, and `xss`. SQLi recall is still weak at `0.6360`, and XSS recall is `0.7724`. |
| Tool counts | Successful run findings by tool: `semgrep` `6572`, `hermsec-offline` `2810`, `gitleaks` `2`. Severities: `1784` high, `7600` medium. |
| Config cleanup | After the run finished, CLI config was restored to `preferredModelProvider=none` and `privacyMode=local-only`. The temporary API key was process-only and not written to repo files or this report. |
| What this means | Deep-assisted mode is now proven to run model-backed on the full BenchmarkJava target, but it currently improves report explanation and prioritization, not raw vulnerability detection. Detection score is still driven by scanners and Java heuristics. |
| Next fixes | Tune Java taint tracking and Semgrep rules to reduce false positives, especially command injection/path traversal/LDAP/XPath/XSS. Add a durable provider failure detail field so future model fallback reasons are easier to diagnose than generic `provider-failed`. Consider a cost-controlled top-N setting in UI/CLI for deep-assisted benchmark runs. |

### Iteration 8 - Adaptive Scan Tracker And Pre-Scan Harness UI

| Item | Notes |
| --- | --- |
| Goal | Build the simple Hermsec-themed adaptive scan tracker in V3 and wire it to a real pre-scan harness phase. |
| What changed | Replaced the old generic chat scan progress disclosure with a neutral timeline card using the existing top buffer animation, a live stage comment, six scan stages, and expandable inline details. |
| Harness behavior | Before launching the root CLI scan, V3 now inspects the selected project, detects languages/frameworks/manifests/lockfiles/IaC markers, builds a scanner plan, verifies current Hermsec scanner tool readiness, and emits the profile/tool plan into the chat card. |
| UI behavior | The card has no internal logo/title, no green/blue glow, and follows the app's simple dark card theme. Steps are readable for at least about `2s` when they complete very quickly. Active/completed/skipped details can be expanded inline per step. |
| Current scanner honesty | The harness only animates tools that are actually runnable in the current build. Planned scanners such as Trivy, Checkov, Composer audit, cargo-audit, gosec, and govulncheck are shown as skipped/planned when relevant rather than pretending they ran. |
| Files changed | V3 scan progress types, main scan orchestration, scan progress component, chat message list visibility, and global CSS for the neutral buffer strip. |
| Verification | `npm.cmd run typecheck` passed. `npm.cmd run build` passed. V3 dev app was restarted and is running for user testing. |
| Remaining next | Add real managed installers/adapters for Trivy, Checkov, PHP/Composer, Rust/cargo-audit, Go/gosec/govulncheck, then let the same card show real install progress instead of planned/skipped status. |

### Iteration 9 - 2026-06-19 Scanner-Managed Harness Expansion

| Item | Notes |
| --- | --- |
| Goal | Expand Hermsec from a fixed scanner bundle into a scanner-managed harness that can catalog tools, let users control them, choose the right scanners per project, install/verify missing tools into Hermsec-managed locations, and run only the relevant lanes. |
| Shared scanner catalog | Added a root scanner catalog shape covering scanner id, label, category, command, version, install kind, languages, input types, parser, default enabled state, auto-install preference, and risk notes. V3 now mirrors that catalog shape for scanner status/settings; the next cleanup is to make the V3 app consume the root catalog directly if the build boundary allows it. |
| Settings > Scanners | The settings model now includes scanner preferences: global auto-install, online update allowance, lab/install-all mode, and per-scanner enabled/auto-install flags. V3 main process exposes scanner list/status/install/uninstall/update handlers, the preload bridge exposes the scanner API, and the renderer has a Scanners settings tab with filters, toggles, install/update/remove actions, and project-applicability status. This still needs build/runtime UI verification. |
| Adaptive install/verify/run workflow | The intended flow is now inspect project, match languages/manifests/lockfiles/IaC markers to scanner capabilities, verify managed or PATH tools, install eligible missing tools into `userData\managed-scanners\<platform>-<arch>` when auto-install is enabled, pass enabled scanner env to the root CLI, run scanner lanes, and keep the scan going when optional tools are missing or fail. |
| Managed install safety | Managed installs are outside the scanned repo. Python tools use `uv tool install` into the Hermsec managed tool root, npm tools use `npm install --global --prefix ... --ignore-scripts`, and Go tools use `go install` with `GOBIN` pointed at the Hermsec managed bin directory. System/native/manual scanners are detected and used when present, but not all have managed installers yet. |
| Expanded scanner stack | The catalog now covers Hermsec heuristics, Semgrep, Gitleaks, TruffleHog, OSV-Scanner, Trivy, Checkov, Bandit, pip-audit, SafeDep PMG npm audit, Retire.js, FindSecBugs/SpotBugs, OWASP Dependency-Check, Psalm, Composer audit, gosec, govulncheck, cargo-audit, Brakeman, Flawfinder, Cppcheck, and .NET vulnerable package checks. |
| Root harness adapters/parsers | The root external scanner runner has been expanded beyond the earlier baseline to include safe command builders and parsers for more ecosystems, including Trivy, Checkov, Composer audit, gosec, govulncheck, cargo-audit, and several optional deep scanners. The runner now respects `HERMSEC_ENABLED_SCANNERS` so V3 settings can narrow execution. |
| Adaptive scan tracker relationship | The earlier six-stage V3 scan tracker is still the user-facing progress surface. The scanner-managed harness should feed it richer details: detected profile, selected scanners, install attempts, managed/PATH readiness, skipped reasons, scanner findings, failures, and report/model stages. |
| Benchmark plan | Keep BenchmarkJava as the Java regression gate, then add OpenSSF CVE Benchmark for JS/TS, focused PHP/Rust/Go/IaC fixture repos, and per-scanner smoke fixtures. Track recall, precision, F1, scanner failures, skipped scanners, runtime, and install behavior. Gates should stay opt-in/non-destructive until scanner installers are stable on Windows/macOS/Linux. |
| Known struggles | The catalog is currently duplicated between root and V3. Settings > Scanners is newly wired and still needs typecheck/build/UI verification. Native tool installers for Trivy, Gitleaks, OSV, PMG, and other binaries need a durable download/checksum path. Dependency-Check needs cache strategy, FindSecBugs needs compiled classes, Checkov/Trivy may need online databases, and some scans can be slow/noisy on large repos. |
| Security constraints | Do not install tools inside the scanned project, do not run package lifecycle scripts, keep secret scanners redacted, keep model output evidence-bound, and treat all benchmark raw exports as opt-in only. |
| Verification status | This documentation pass did not run source tests. It only inspected the uncommitted scanner catalog/settings/scanner-runner work and recorded the current handoff state. Main implementation verification should still run root typecheck/tests and V3 typecheck/build after the scanner UI and installer wiring settle. |
| Next steps | Verify the visible Settings > Scanners panel, deduplicate root/V3 catalog data, implement native managed installers with checksum verification, verify scanner settings flow through every V3 scan launch, add tests for scanner enable/disable and install failures, and extend benchmark coverage per ecosystem. |

### Current Next Steps After Iteration 9

1. Typecheck/build and manually verify the visible Settings > Scanners renderer surface.
2. Confirm V3 scan launches pass scanner settings and managed tool paths into the root CLI in manual, dashboard, and automation flows.
3. Deduplicate the scanner catalog so root CLI and V3 cannot drift.
4. Add checksum-backed managed installers for native scanner binaries.
5. Run root tests plus V3 typecheck/build after the scanner-managed workflow is fully wired.
6. Add benchmark fixtures for JS/TS OpenSSF CVE Benchmark, Go, Rust, PHP, and IaC scanner lanes.

### Iteration 10 - Scanner Harness Verification And Prep-Stage Wiring

| Item | Notes |
| --- | --- |
| Goal | Finish the scanner-managed harness pass by making the new scanner catalog compile, making V3 scan preparation actually install/verify tools, and proving the harness still runs end to end. |
| What changed | Fixed root typecheck issues from expanded languages/parsers, added missing repository language counters, tightened parser typing for Cargo audit/SARIF, added .NET transitive package parsing, and made cppcheck parse stderr output. |
| Scanner selection fix | `HERMSEC_ENABLED_SCANNERS` now has clear behavior: unset means default-enabled scanner catalog, `all` means lab/all-scanners mode, `__none__` or an empty value means no external scanners, and disabled scanners are omitted instead of reported as skipped lanes. |
| Safe execution fix | Added argument-shape validators for the expanded scanner command set so tools like Trivy, Checkov, TruffleHog, gosec, govulncheck, Brakeman, Flawfinder, Cppcheck, and others are still constrained to HermSec-built scanner commands. |
| V3 prep-stage fix | V3 scan preparation now calls `prepareScannersForProject()`. If auto-install is enabled, it attempts safe managed installs for eligible missing scanners, records failed installs as `failed` detail rows, and continues the scan with ready tools. |
| Settings polish | Settings > Scanners now surfaces install/update/remove results in the row instead of silently refreshing, and V3 now sends `__none__` when no scanners are selected so the CLI does not accidentally run everything. |
| Runtime lookup | Expanded bundled runtime scanner command discovery so packaged Electron builds can detect more scanner names under `resources/runtime-tools/<platform>-<arch>` if those tools are bundled. |
| Online update toggle | Root scanner builders now consume `HERMSEC_SCANNER_ONLINE_UPDATES=false` for Trivy and OWASP Dependency-Check by adding their no-update flags. |
| What went wrong | Initial root typecheck failed because parser exact typing and the expanded `SourceLanguage` union were not fully reflected. The first scanner test command also exposed old tests that assumed exactly six scanner statuses and treated disabled scanners as skipped rows. `npm test -- tests/...` also tried to execute source `.ts` test paths after the compiled suite, causing module resolution noise. |
| How we solved it | Fixed the TypeScript errors, changed disabled scanner handling to omit disabled lanes, pinned the old scanner test control group with `HERMSEC_ENABLED_SCANNERS`, and reran tests directly from compiled `dist` files after building. |
| Verification | `npm.cmd run typecheck` passed at the root. `npm.cmd run typecheck` passed in `v2/hermsec-v3`. Root `npm.cmd run build` passed. V3 `npm.cmd run build` passed. `node --test dist\tests\unit\scanners\externalScanners.test.js` passed `7/7`. `node --test dist\tests\unit\scanners\scannerHeuristics.test.js` passed `10/10`. |
| End-to-end smoke | Ran `node dist\src\bin\hermsec.js scan tests\fixtures\repos\node-express-vulnerable --mode offline --assist-mode scanner-model-summary --out .hermsec\smoke-runs\scanner-harness-expansion --json --no-model` with the six-tool control env. It completed successfully with `10` findings and wrote a report under `.hermsec\smoke-runs\scanner-harness-expansion\node-express-vulnerable\2026-06-19T15-25-00-868Z`. |
| Current limitation | Native/checksum installers for tools like Trivy, Gitleaks, OSV-Scanner, and PMG are still not implemented. System/runtime tools are detected and used when present; Python/npm/Go managed installer paths exist. The root/V3 scanner catalogs are still duplicated. |
| Next fixes | Deduplicate the catalog, add checksum-backed native installers, add UI/runtime verification for Settings > Scanners, test scan prep auto-install with `uv`/npm/Go present, and add per-ecosystem benchmark fixtures beyond BenchmarkJava. |

### Iteration 11 - End-To-End Verification Goal Run

| Item | Notes |
| --- | --- |
| Goal | Verify the V3 UI, scanner harness, report generation, scan fallbacks, Doctor, dashboard smoke, scanner env modes, and regression tests end to end. |
| Multi-agent help | Used two read-only helper agents: one focused on V3 Doctor/dashboard smoke and one focused on scanner env/fallback behavior. Both passed their verification tasks and were closed. |
| Root full suite | `npm.cmd test` passed after rebuilding the root app: `70/70` tests passed. This includes CLI smoke, desktop smoke, Doctor, scheduler, report rendering, model chunk/watchdog fallbacks, Java taint tests, scanner parsers, and scanner fallback tests. |
| New regression test | Added `external scanner selection honors none, explicit, default, and all env modes` to `tests/unit/scanners/externalScanners.test.ts`. It locks down `HERMSEC_ENABLED_SCANNERS=__none__`, explicit scanner lists, unset/default behavior, and `all` lab behavior. |
| Type/build checks | Root `npm.cmd run typecheck` passed. V3 `npm.cmd run typecheck` passed. V3 `npm.cmd run build` passed. |
| V3 Doctor smoke | `npm.cmd run smoke:doctor` passed with healthScore `100`, required `7/7`, scanners `6/6`, internet `5/5`, and `49` progress events. Provider group was `0/1 warn`, which does not fail the smoke because no provider credential is configured in the isolated smoke home. |
| V3 dashboard smoke | `npm.cmd run smoke:dashboard` passed. It generated dashboard HTML and a non-empty one-page PDF. The helper-confirmed artifact was `.hermsec\v3-dashboard-smoke\hermsec-node-express-vuln-lab\2026-06-19T15-30-41-878Z\dashboard\index.html`, with one-page PDF size `791691` bytes. |
| Real Electron UI check | Launched a temporary Electron instance with isolated `HERMSEC_HOME` and Chrome DevTools Protocol. Verified `window.hermsec` preload exists, opened Settings > Scanners, confirmed `22` scanner catalog rows, saw Auto-install, online updates, lab mode, filters, status chips, project chips, Semgrep/Gitleaks rows, and captured `output\playwright\v3-electron-scanners-verified.png`. |
| Browser renderer check | Opened `http://localhost:5173` with Playwright CLI. The browser-only renderer shell and Settings sidebar render, including the Scanners tab. Browser mode cannot validate preload-backed settings data; the real Electron CDP check covers that. The only browser console error was missing `favicon.ico`. |
| Scan fallback smoke - no external scanners | Ran a scan with `HERMSEC_ENABLED_SCANNERS=__none__` against `tests\fixtures\repos\node-express-vulnerable`. It completed with `10` built-in findings and report artifacts under `.hermsec\e2e-runs\none-scanners\...`. |
| Scan fallback smoke - deep assisted without model | Ran deep-assisted mode with `--no-model` and the six-tool scanner control set. It completed with `10` findings and fallback report artifacts under `.hermsec\e2e-runs\deep-no-model\...`. |
| Scan fallback smoke - all/lab plus offline advisory updates | Ran with `HERMSEC_ENABLED_SCANNERS=all` and `HERMSEC_SCANNER_ONLINE_UPDATES=false` against the Python vulnerable fixture. It completed with `3` findings and report artifacts under `.hermsec\e2e-runs\all-offline-updates\...`. Missing optional scanners were skipped without blocking the scan. |
| What went wrong | Playwright's browser binary was initially missing, so the first browser probe failed. The first raw CDP close attempt hung waiting for a browser-close reply after it had already captured a screenshot. Browser-only mode also cannot prove Electron preload APIs. |
| How we solved it | Installed Playwright Chrome for Testing, reran the browser probe, then used direct Electron CDP automation with a stricter cleanup path. Treated browser-only preload absence as expected and validated the real desktop path through Electron. |
| Known caveats | Doctor still proves the legacy six scanner commands, not the entire expanded Settings catalog. Provider warning is tolerated in smoke mode. `scanners:list` can create the managed scanner bin directory as part of status probing. Native checksum-backed installers and expanded parser fixture coverage remain future work. |

### Iteration 12 - GitHub Desktop Release Pipeline And macOS Install Link

| Item | Notes |
| --- | --- |
| Goal | Configure GitHub CI/release automation so Hermsec can publish desktop installers for macOS as well as Windows, and add a macOS install link to the GitHub README. |
| What changed | Added `.github\workflows\desktop-release.yml`. The workflow runs on `v*` tag pushes and manual `workflow_dispatch`, builds Windows and macOS desktop packages, uploads artifacts, then creates or updates a GitHub Release with those assets. |
| Release assets | Windows job publishes `.exe`, blockmap, and latest metadata from `v2\hermsec-v3\release`. macOS job publishes `.dmg`, `.zip`, blockmap, and latest metadata from the same release directory. |
| CI prerequisites | Workflow installs Node `22`, Python `3.12`, root dependencies, V3 desktop dependencies, and `uv` through `python -m pip install --upgrade uv`, because `prepare:runtime-tools` uses `uv` to bundle Python-based scanner tools. |
| Signing policy | Set `CSC_IDENTITY_AUTO_DISCOVERY=false` so CI can produce unsigned macOS builds until Apple signing/notarization secrets are added. README now notes macOS may require first-launch approval from System Settings > Privacy & Security. |
| README update | Root README now has a Desktop Installers section with a macOS installer link to `https://github.com/sethwhenton/hermsec/releases/latest`, plus local `npm run dist:mac` instructions. V3 README also documents `dist:mac` and the release workflow. |
| Verification | Root `npm.cmd run typecheck` passed. V3 `npm.cmd run typecheck` passed. The actual macOS package build must run on a macOS GitHub runner after this workflow is pushed. |
| Local release limitation | The GitHub CLI is not installed locally, and the workflow is not on GitHub until committed/pushed. No live GitHub Release was created from the current local worktree. The configured workflow will create/update releases once pushed and triggered by a tag or manual run. |
| Next release command | After committing/pushing to `main`, publish with a tag such as `git tag v0.1.0 && git push origin v0.1.0`, or run the Desktop Release workflow manually with `tag_name=v0.1.0`. |

### Iteration 13 - V3-Only Repository Cleanup And Desktop Promotion

| Item | Notes |
| --- | --- |
| Goal | Make the repository speak and build around Hermsec V3 only, remove the old fork/experimental UI files, and promote the active app to a clearer top-level `desktop` folder. |
| Desktop app path | Promoted the active V3 Electron app from the old nested `v2\hermsec-v3` path to top-level `desktop`. |
| Old fork cleanup | Removed the tracked old `v2` source tree and earlier experimental UI surfaces from the active repo. |
| Root app cleanup | Removed the legacy root Electron renderer and terminal UI modules so root `src` is now the reusable scanner/CLI/report engine. |
| Root package scripts | Simplified root build/test scripts to the scanner CLI engine and added `desktop:*` convenience scripts for V3 app work. |
| Documentation | Rewrote the root README, desktop README, npm install notes, CLI usage notes, and project context to speak about V3 and `desktop`. |
| Release CI | Updated desktop release workflow paths from `v2/hermsec-v3` to `desktop`. |
| Runtime ignores | Updated ignore rules for `desktop/out`, `desktop/release`, bundled CLI resources, bundled scanner tools, and local V3 runtime state. |
| What went wrong | The cleanup pass removed `reportlaptop.md` and `project-report-track.md` temporarily. A parallel cleanup pass then removed them a second time. |
| How it was solved | Restored both tracking files from git and appended this iteration instead of losing history. |
| Historical path note | Older report entries still mention previous paths as historical audit records. Current headers and this iteration now mark `desktop` as the active app. |
| Verification | Root `npm.cmd run typecheck` passed. Root `npm.cmd test` passed with `59/59`. Desktop `npm.cmd run typecheck` passed. Desktop `npm.cmd run build` passed. Desktop `npm.cmd run smoke:doctor` passed with health score `100`. Desktop `npm.cmd run smoke:dashboard` passed and generated dashboard HTML plus a one-page PDF. Desktop `npm.cmd run prepare:cli-bundle` passed. Desktop `npm.cmd run prepare:runtime-tools` passed. Desktop `npm.cmd run dist:win` passed and produced installer/portable artifacts under `desktop\release`. Packaged `release\win-unpacked\Hermsec.exe --smoke-doctor` passed at health score `100`. Packaged dashboard smoke exited cleanly and generated dashboard/PDF artifacts under `.hermsec\packaged-dashboard-smoke`. Desktop `npm.cmd audit --omit=dev` reported `0` vulnerabilities. |
| Remaining caveat | Full desktop dev audit can still report a low-severity dev-only advisory through Vite/esbuild; production dependency audit is clean. |

### Iteration 14 - Fresh End-To-End Verification After V3 Cleanup

| Item | Notes |
| --- | --- |
| Goal | Re-run the strongest available end-to-end verification from the staged V3-only project state and identify what is broken or still missing. |
| Root verification | `npm.cmd run typecheck` passed. `npm.cmd run test` rebuilt the CLI engine and passed `59/59` tests. `npm.cmd audit --omit=dev` reported `0` production vulnerabilities. |
| Desktop verification | `npm.cmd run typecheck` passed. `npm.cmd run build` passed for main, preload, and renderer bundles. `npm.cmd audit --omit=dev` reported `0` production vulnerabilities. |
| Doctor smoke | `npm.cmd run smoke:doctor` passed with `ok: true`, status `attention`, health score `100`, required `7/7`, scanners `6/6`, internet `5/5`, and `49` progress events. Provider readiness was `0/1 warn` in the isolated smoke environment, which is expected when no provider credential is configured there. |
| Dashboard smoke | `npm.cmd run smoke:dashboard` passed and generated dashboard HTML plus a one-page PDF under `.hermsec\v3-dashboard-smoke\hermsec-node-express-vuln-lab\2026-06-19T16-14-03-052Z`. |
| Packaged Windows build | `npm.cmd run dist:win` passed. It rebuilt the CLI bundle, prepared runtime scanner tools, built the Electron app, and produced `desktop\release\Hermsec Setup 0.1.0.exe` plus `desktop\release\Hermsec 0.1.0.exe`. |
| Packaged Doctor | `desktop\release\win-unpacked\Hermsec.exe --smoke-doctor` passed with status `ready`, health score `100`, required `7/7`, scanners `6/6`, internet `5/5`, and providers `1/1`. |
| Packaged dashboard | Packaged dashboard smoke exited successfully and generated current artifacts under `.hermsec\packaged-dashboard-smoke\hermsec-cli\2026-06-19T16-19-28-215Z`, including `dashboard\index.html` and `onepager\report.pdf`. |
| Packaged startup smoke | Launched `desktop\release\win-unpacked\Hermsec.exe --disable-gpu` with isolated `HERMSEC_HOME`; the process was still alive after `8` seconds and was then terminated cleanly. |
| Broken or risky | Full desktop dev audit still reports one low-severity dev-only advisory: Vite depends on `esbuild@0.27.7`, which is flagged for a Windows dev-server arbitrary file read issue. `npm.cmd audit fix` did not move the dependency. Production audit remains clean. |
| Missing coverage | The current repo has smoke-level desktop verification, but no committed interactive UI automation suite after the V3-only cleanup. Earlier manual/CDP validation proved the Settings > Scanners surface, but it is not yet a repeatable tracked test. |
| Recommended next steps | Add a committed Playwright/Electron UI smoke for launch, scan mode selection, Doctor live card, Settings > Scanners, and dashboard open. Upgrade or override Vite/esbuild once a compatible fixed release is available. Expand Doctor to report all managed scanner catalog entries, not only the six bundled/runtime scanners. Add macOS release verification in GitHub Actions after pushing the release workflow. |

### Iteration 15 - Scanner Auto-Install Defaults And Final PDF Chat Link

| Item | Notes |
| --- | --- |
| Goal | Make adaptive scanner auto-install the default harness behavior, show the final one-page PDF path in chat as a local file link, and double-check the app does not blank after scanning. |
| Scanner default | Fresh desktop settings now default `scanners.autoInstallMissing` to `true`. Per-scanner auto-install toggles still control which supported scanner installers can run, and system-only tools remain manual/path-detected. |
| Chat report link | Scan completion now prefers `onepagerPdfPath` when Electron generates the final PDF. The assistant message shows the final PDF path, includes the report folder, and renders a quiet local-file hyperlink that opens the PDF location in File Explorer. If PDF generation is skipped, the chat falls back to linking the report folder. |
| Black-screen hardening | Dashboard bundle loading is now non-fatal. If dashboard hydration fails after a successful scan, Hermsec keeps the scan result and PDF/report link instead of turning the scan into an uncaught renderer failure. |
| Error handling | Chat scan execution now catches unexpected renderer/IPC errors and writes a visible assistant failure message instead of leaving the interface in a stuck state. |
| Verification | Root `npm.cmd run typecheck` passed. Desktop `npm.cmd run typecheck` passed. Desktop `npm.cmd run build` passed. Desktop `npm.cmd run smoke:doctor` passed with health score `100`. Desktop `npm.cmd run smoke:dashboard` passed and generated a current PDF under `.hermsec\v3-dashboard-smoke\...\onepager\report.pdf`. |
| Default proof | Launched Electron with isolated `HERMSEC_HOME`; generated `settings.json` showed `scanners.autoInstallMissing: true` and the supported default scanner rows set to auto-install. |
| Visual smoke | Launched the real Electron app with remote debugging. The renderer had non-empty DOM text, `window.hermsec` preload was present, and screenshot `output\playwright\electron-v3-startup-smoke.png` was captured. |
| After-scan smoke | From the Electron renderer, invoked `window.hermsec.scan.project()` with `useModel: false` against the Node vulnerable lab. It completed with `10` findings, generated `dashboard\index.html` and `onepager\report.pdf`, and the renderer still had non-empty DOM text plus `window.hermsec` after the scan. Screenshot: `output\playwright\electron-v3-after-scan-smoke.png`. |
| Remaining caveat | The visual after-scan smoke uses the app IPC from the renderer rather than clicking the full chat flow. A committed click-through Playwright/Electron test is still recommended so this stays guarded in CI. |

### Iteration 16 - Report Labels And Chat Scan Handoff Cleanup

| Item | Notes |
| --- | --- |
| Goal | Remove confusing internal scanner names from user-facing reports, make the scan progress card reflect real scan phases, and keep the completed progress card in chat before the final summary. |
| What went wrong | Reports could show `hermsec-offline`, which was an old internal id for built-in heuristic findings. Deep-assisted scan progress also appeared to loop through HermSec heuristics because the UI estimated scanner activity while the CLI was still running. |
| How we solved labels | Added a scanner display-name mapper and changed the built-in heuristic default tool id to `hermsec-heuristics`. Old reports that still contain `hermsec-offline` now render as `HermSec heuristics` in Markdown, HTML, dashboard data, raw-output tables, and one-page data. |
| How we solved progress | Removed the fake scanner-label rotation from the desktop scan runner. The live card now shows a real scanner-engine running row and waits for recorded scanner statuses from `report-document.json` before showing per-tool completion/failure/skipped results. Missing tool rows are no longer invented after the scan. |
| Chat handoff | Scan completion now persists the final progress card as a chat item, then posts a concise assistant summary with the severity hook and two local actions: `Open final PDF location` and `Open report folder`. The assistant bubble no longer prints raw PDF/report paths in the message body. |
| UI detail | The completed progress card headline now uses the latest non-waiting stage, so the persisted card reads like a finished scan instead of falling back to the first completed stage. |
| Regression coverage | Added a report regression test proving legacy `hermsec-offline` does not appear in rendered Markdown/HTML and renders as `HermSec heuristics` instead. Updated an integration assertion to expect friendly scanner display names like `Gitleaks`. |
| Verification | Root `npm.cmd run typecheck` passed. Desktop `npm.cmd run typecheck` passed. Root `npm.cmd test` passed with `60/60`. Desktop `npm.cmd run build` passed. Desktop `npm.cmd run smoke:dashboard` passed and generated `.hermsec\v3-dashboard-smoke\hermsec-node-express-vuln-lab\2026-06-19T20-11-51-595Z\onepager\report.pdf`. Desktop `npm.cmd run smoke:doctor` passed with healthScore `100`, scanners `6/6`, internet `5/5`, and provider warning expected in the isolated shell. |
| Artifact check | Searched the generated dashboard/report output: no `hermsec-offline` remained in user-facing smoke artifacts, while `HermSec heuristics` appeared in dashboard, one-page, and HTML report data. |
| Remaining caveat | The progress card is now truthful at the Electron orchestration level, but scanner-level live updates still arrive after the root CLI writes its report. Streaming per-tool status during the CLI run would require the root scanner engine to emit structured progress events while each adapter runs. |

### Iteration 17 - Deep Scan Progress Mode Label Fix

| Item | Notes |
| --- | --- |
| Goal | Fix the completed scan progress card showing `Scanner + model summary` after the user selected `Deep assisted scan`. |
| What went wrong | The progress card inferred the mode by scanning event text. Later completed events overwrote the earlier deep-mode text, so the bottom chip could fall back to the wrong mode even when the actual scan request used `deep-assisted`. |
| Fix | Progress events now carry explicit `assistMode` and `assistModeLabel` metadata, and the run emits a `scan-assist-mode` marker event. The card reads that metadata first instead of guessing from strings. |
| UI cleanup | For deep runs, step 5 now renders as `Deep model triage`, and the bottom token chip renders `More context, more tokens` instead of `Lowest token use`. |
| Verification | Root `npm.cmd run typecheck` passed. Desktop `npm.cmd run typecheck` passed. Desktop `npm.cmd run build` passed. Desktop `npm.cmd run smoke:dashboard` passed and generated `.hermsec\v3-dashboard-smoke\hermsec-node-express-vuln-lab\2026-06-19T20-44-59-575Z\onepager\report.pdf`. The V3 dev app was restarted successfully after the change. |

### Iteration 18 - Structured Root Progress, Normalization, Java Taint, And Evidence-Bound Deep Mode

| Item | Notes |
| --- | --- |
| Goal | Implement plan items 1-4: truthful structured progress from root scanner events, stricter finding normalization, stronger Java taint tracking, and model explanations that cannot invent evidence. |
| Structured progress | Added root `ScanProgressEvent` typing, a shared progress emitter, callbacks through root scan, external scanner execution, harness model/report phases, CLI JSON mode, and desktop scan runner. |
| CLI behavior | `hermsec scan --json` now streams `HERMSEC_PROGRESS <json>` lines on stderr while keeping the final command result as normal JSON on stdout. |
| Desktop behavior | Desktop now parses progress lines live from stdout/stderr, maps root stages into the existing chat card, nests scanner rows under `Running scans`, and strips any leftover progress lines before final JSON parsing. |
| Finding normalization | Added a single normalization boundary after all scanner parsers/heuristics and before dedupe/reporting. It fills required fields, normalizes repo-relative paths, clamps/redacts evidence, and keeps stable ids/fingerprints. |
| Parser fixtures | Added parser/normalization coverage for Trivy, Checkov, Retire.js, SpotBugs XML, OWASP Dependency-Check, gosec, cargo-audit, Brakeman, Flawfinder SARIF, Cppcheck text, and dotnet vulnerable package JSON. |
| Java taint | Expanded lightweight Java taint to cover request/body/session/cookie/multipart flows, enhanced-for aliases, local aliases, StringBuilder/StringBuffer propagation, LDAP/XPath/file/response/session sinks, and sanitizer families for HTML/URL/SQL/LDAP/XPath/XML/JavaScript. |
| Deep mode guardrails | Deep-assisted explanations now reject invented CWEs, scanner/tool ids, and finding ids, in addition to prior checks for invented file paths, line numbers, packages, CVEs, GHSAs, and OSV ids. Rejected model text falls back to scanner-backed explanations. |
| What went wrong | TypeScript strict optional properties rejected a few newly passed `undefined` option values. A first focused test run also tried to run multiple `build:core` commands in parallel, causing a Windows `EPERM` race while deleting `dist`. One assertion used an unavailable assert helper name. |
| How we solved it | Only include optional fields when present, widened one internal maybe-value options type, switched from parallel builds to one build plus sequential compiled tests, and replaced the assertion with the supported helper. |
| Verification | Root `npm.cmd run typecheck` passed. Root `npm.cmd test` passed with `73/73`. Desktop `npm.cmd run typecheck` passed. Desktop `npm.cmd run smoke:dashboard` passed and generated a dashboard plus one-page PDF. Desktop `npm.cmd run smoke:doctor` passed with healthScore `100`, required `7/7`, scanners `6/6`, internet `5/5`, and `49` progress events. |
| Current result | The scan progress card is now fed by real root scan/scanner/model/report events instead of desktop-side guessing. The app still keeps final report reconciliation as fallback only. |
| Next | Add a committed Electron UI smoke that clicks through mode selection and asserts streamed card updates; continue BenchmarkJava taint precision tuning; deduplicate root/desktop scanner catalog metadata. |

### Iteration 19 - Real Vulnerability Intelligence Matching

| Item | Notes |
| --- | --- |
| Goal | Turn the report's `Vulnerability intelligence` section from a placeholder-style label into a real KEV/CVE/advisory cross-reference step. |
| What changed | Added dependency inventory enrichment for npm, Python requirements, Go modules, Rust Cargo locks, Composer, Ruby Gemfile locks, and Maven POM basics. The root harness now runs vulnerability intelligence after scanner completion and before report writing. |
| Advisory sources | Reuses the existing OSV, GitHub Advisory, NVD, and CISA KEV fetchers through the intel cache. Scan mode and `HERMSEC_SCANNER_ONLINE_UPDATES=false` decide whether it refreshes online feeds or uses cached/offline data. |
| Report data | Added `ReportIntelligenceItem` records to `report-document.json`, Markdown, HTML, dashboard, and one-page report data. Cards include sources, package/version, CVE/GHSA/OSV/CWE identifiers, related finding ids, match reasons, fixed version, priority, and known-exploited status. |
| Empty state | Reports now explicitly say no KEV/advisory intelligence matched the dependency inventory or scanner identifiers when nothing relevant is found. Generic ecosystem-only feed guidance is filtered out so it does not masquerade as a real match. |
| What went wrong | The dashboard previously inferred "intelligence" from finding identifiers and always set `knownExploited` to false, while the one-page copy implied real KEV/dependency matching. The first positive test expected separate KEV and GitHub cards, but the existing deduper correctly merged same-CVE sources into one stronger combined card. |
| How we solved it | Moved matching into the root scan/report path, built a real inventory, merged workspace/finding relevance, preserved deduped multi-source labels, and updated the test to expect one combined urgent item with KEV plus GitHub metadata. |
| Verification | Root `npm run typecheck` passed. Root `npm test` passed with `76/76`. Desktop `npm --prefix desktop run typecheck` passed. Desktop `npm --prefix desktop run build` passed. Desktop `npm --prefix desktop run smoke:doctor` passed at health score `100`. Desktop `npm --prefix desktop run smoke:dashboard` passed and generated dashboard/PDF artifacts. |
| End-to-end proof | The latest dashboard smoke `report-document.json` contains an `intelligence` array with `2` real matches for `express@4.18.2`: `CVE-2024-29041` fixed in `4.19.2` and `CVE-2024-43796` fixed in `4.20.0`, sourced from GitHub Advisory and OSV. |
| Remaining caveat | This first inventory pass is manifest/lockfile based and should keep expanding per ecosystem. CISA KEV matching depends on CVE evidence from scanner/advisory data. Live feed failures are recorded as report limitations and do not fail scans. |

### Iteration 20 - Settings Cleanup, Provider Discovery, Stop Action, And v0.1.4 Release Prep

| Item | Notes |
| --- | --- |
| Goal | Clean up desktop settings behavior, make provider/model setup easier, improve action stopping, update report history, and prepare a new `v0.1.4` release. |
| Privacy mode | Kept Privacy mode off by default for fresh installs. Added a desktop redaction boundary so, when enabled, report-chat/model context redacts sensitive local paths, usernames, secrets, auth headers, and high-entropy values while preserving useful scanner evidence such as relative paths, line numbers, package names, versions, CVEs, rule ids, scanner ids, finding ids, and remediation text. |
| Removed unused setting | Removed the unused `Show reasoning` setting from the General settings screen because no visible reasoning timeline is currently implemented. |
| Language setting | Relabeled Language as a future interface preference by disabling it and explaining that the current desktop interface remains English until full i18n is wired. |
| Automation setting | Replaced the passive Automation `Disabled` pill with a clear `Configure` action that takes the user to the Automations view. |
| Stop action | The composer send button now turns into a stop button while a scan/report/model action is busy, so users can cancel the active action from the same place they started it. The stop path is wired through renderer state, preload IPC, and main-process report cancellation. |
| Provider presets | Added a shared provider catalog for OpenCode Go, OpenAI, Anthropic, Google Gemini, Cursor as coming soon, and custom providers. Presets include base URLs, API format, default model ids, environment-variable names, descriptions, logo URLs, and model discovery capability flags. |
| Provider validation | The provider drawer now debounces URL/API-key changes, shows a validating state, calls the provider model endpoint, records success/error state, and merges discovered models into the provider while preserving user-enabled toggles. |
| Model settings | Rebuilt Settings > Models around provider accordions. Each configured provider can be expanded to show available models, refresh discovery, toggle enabled models, and set the active provider/model pair without collisions between duplicate model ids. |
| Provider runtime | Runtime selection, Doctor checks, chat model status, and context bar model selection now respect `activeProviderId` plus `activeModelId` instead of only matching by model id. |
| Logo polish | Provider logos now render in a clean white tile with a subtle inner border so dark provider marks remain legible on Hermsec's dark settings surface. |
| Agent tone | Updated Hermsec agent prompts to be formal, concise, direct, and scoped to defensive security review instead of ultra-friendly chat. |
| Project/sidebar polish | Added a quick new-chat action beside each project row and kept settings/project loading behavior aligned with visible project state. |
| About modal | Expanded the About Hermsec modal to explain the app promise, scan pipeline, built-in heuristics, scanner harness, security posture, strengths, and growth areas. |
| Versioning | Bumped root and desktop package versions from `0.1.3` to `0.1.4` for the next GitHub release tag. |
| Release workflow hardening | Updated both Windows and macOS release workflows so if both jobs race to create the same GitHub Release, the losing job falls back to upload/edit instead of failing. |
| What went wrong | The first provider logo pass used dark SVGs directly on dark cards, making several logos hard to see. Cursor was also not a normal chat-completions provider, so it would have been misleading to treat it like OpenAI/Anthropic/Gemini. A PowerShell secret-scan command also failed once because of quote escaping. |
| How we solved it | Added a shared logo tile component with a white background and fallback initial. Kept Cursor visible as a `Coming soon` provider/integration card instead of enabling model discovery. Reran the secret scan with corrected quoting. |
| Verification | Root `npm run typecheck` passed. Desktop `npm run desktop:typecheck` passed. Root `npm test` passed with `76/76`. Desktop `npm run desktop:build` passed. Desktop `npm run desktop:smoke:doctor` passed with healthScore `100`, required `7/7`, scanners `6/6`, internet `5/5`, and expected provider warning in the isolated smoke environment. Desktop `npm run desktop:smoke:dashboard` passed and generated `C:\Users\whent\Documents\Personal Proj\Hermsec\.hermsec\v3-dashboard-smoke\hermsec-node-express-vuln-lab\2026-06-21T13-01-09-723Z\onepager\report.pdf`. |
| Secret check | `rg` found only `.env.example` placeholders and intentional fake test keys in redaction/provider tests; no real OpenCode/OpenAI-style key was found in the changed source set. |
| Release path | The local machine does not have `gh` installed. The repository already has tag-triggered Windows and macOS release workflows, so pushing `v0.1.4` will trigger GitHub Actions to build and create/update the GitHub Release assets. |
| Next | Watch the `v0.1.4` Windows and macOS release workflows after tag push. Add a committed Electron click-through UI test for provider setup, model accordions, stop action, and scan completion links. |

### Iteration 21 - Provider Catalog Follow-Up And v0.1.5 Release Prep

| Item | Notes |
| --- | --- |
| Goal | Fold in the provider catalog follow-up edits that appeared after `v0.1.4`, keep the latest release aligned with the final source tree, and avoid shipping unverified provider routes. |
| Provider additions | Added OpenRouter and local Ollama provider presets, plus provider website links shown from the Providers settings cards and connected-provider rows. |
| Local Ollama | Local Ollama is treated as an OpenAI-compatible local endpoint at `http://127.0.0.1:11434/v1` and does not require an API key for Doctor/model routing. |
| Ollama Cloud | Marked Ollama Cloud as `coming soon` because current Ollama Cloud docs expose the cloud Ollama API at `https://ollama.com/api`, while Hermsec's current model route expects OpenAI-compatible `/v1/chat/completions`. |
| Provider checks | Provider discovery and report-chat model calls now tolerate no-key local providers where explicitly allowed. |
| Docs | Added `OLLAMA_API_KEY` to README provider-key examples and updated project context to include OpenRouter/local Ollama plus future Cursor/Ollama Cloud integration notes. |
| Versioning | Bumped root and desktop package versions from `0.1.4` to `0.1.5` so the follow-up release can supersede the already-created `v0.1.4` release cleanly. |
| Source checks | Verified OpenRouter's official docs describe `https://openrouter.ai/api/v1` as the OpenAI-compatible base URL. Verified Ollama's official OpenAI compatibility docs use `http://localhost:11434/v1` locally and official Ollama Cloud docs use `https://ollama.com/api`, not the unverified `/v1` cloud route. |
| Verification | Root `npm run typecheck` passed. Desktop `npm run desktop:typecheck` passed. Root `npm test` passed with `76/76`. Desktop `npm run desktop:build` passed. Desktop `npm run desktop:smoke:doctor` passed with healthScore `100`, required `7/7`, scanners `6/6`, internet `5/5`, and expected provider warning in the isolated smoke environment. |
