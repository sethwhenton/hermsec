# Hermsec Project Context

## Purpose

Hermsec is a local-first, CVE-aware AI security assistant for repositories. The current product target is a Synara-inspired Electron desktop app: a user selects a local workspace, Hermsec runs defensive scanners, normalizes evidence, refreshes trusted vulnerability intelligence, optionally asks a bring-your-own model to explain scanner-backed findings, and writes local HTML, Markdown, and JSON reports.

## Agent Handoff: Current Source Of Truth

`v2/hermsec-v3` is the go-to Hermsec app now. New product work should happen there first unless the user explicitly asks for root CLI/TUI, legacy V1, or older V2 work. The root CLI scan harness remains the reusable scanner/report engine underneath V3, but V3 is the primary desktop user experience, test target, and preview target.

When another agent resumes this project:

- Start by reading this `projectcontext.md`.
- Treat `v2/hermsec-v3` as the active app.
- Preserve the Hermsec security-agent scope: chat, scans, reports, automations, provider/model settings, and scanner-backed fix prompts.
- Do not route users back to the old Blessed TUI unless asked.
- Keep secrets in local ignored `.env.local` files only; never commit provider keys.

## Current Implementation Status

Hermsec now has a hardened local production-readiness milestone plus a desktop shell:

- TypeScript CLI package with `hermsec` bin.
- Electron + React + Vite desktop app with a Synara-style sidebar, chat/investigation surface, findings inspector, intel panel, report list, and settings panel.
- `v2/` is a whole-source Synara fork for the next desktop direction. It keeps Synara's Electron/web/server shell, removes the marketing app, rebrands visible app identity to Hermsec V2, uses the selected H/keyhole mark, and now exposes a live `desktopBridge.hermsec` for state, chat action routing, scans, settings, reports, schedules, Doctor, and Intel actions backed by the existing Hermsec CLI build.
- Hermsec V2 now loads the Hermsec route by default in Electron and browser preview. The inherited Synara chat/settings route is quarantined from the active product flow; the native Settings menu action opens Hermsec's own settings panel.
- Secure desktop boundary: Electron main owns filesystem/scanner/model work; React uses a typed preload bridge with `contextIsolation`, `nodeIntegration: false`, and a CommonJS sandbox-compatible preload.
- Desktop actions are wired to real Hermsec tools: workspace selection, `/scan`, `/intel`, `/doctor`, `/reports`, provider/settings saves, report opening, and session-backed chat messages.
- Hermsec now has a provider-agnostic `hermsec agent` command surface: `agent providers` returns live provider/account status for Scanner-only, OpenCode Go, OpenAI, OpenRouter, Claude, Gemini, Ollama, and OpenAI-compatible endpoints; `agent ask` provides bounded scanner-backed security answers or deterministic scanner-only fallback.
- Desktop provider settings are modeled like Hermes Agent's provider/accounts flow: provider cards, live credential status refresh, selected model, local/custom base URL, env-var reference, and optional local API-key save. Provider, model, and base URL are persisted to ignored `v2/.env.local` plus Hermsec config; raw keys are not written to project config or CLI stdout, and the renderer password field is cleared after handing the value to Electron main.
- Hermsec V2 defaults its bridge home to `v2/.hermsec-v2/hermsec-home`, reads `.env.local` only in the Electron main process for child CLI calls, and keeps provider credentials env-only from the CLI/model layer's point of view.
- Hermsec V2 surfaces are theme-aware for both dark and light Appearance modes; the selected H/keyhole logo variants remain readable in both.
- Hermsec V2's active product shell now keeps the app chrome minimal: the inherited fake web `File/Edit/View/Help` menu and floating center view header were removed from the Hermsec route, while the sidebar, main workspace, centered page content shell, and bottom status bar remain stable and full-width.
- Hermsec V2 chat supports structured assistant choice cards. "What can you do?" returns `Scan repo` and `Set an automation`, and selecting them triggers the live scan or schedule creation flow.
- Hermsec V2 automations are backed by root scheduler CLI commands. Enable/disable, edit, delete, Run Now, and once-per-minute in-app due checks are wired; normal scheduled runs use git-change-aware evaluation and forced runs execute immediately.
- Report rendering has a cleaner HTML design, and v2 manual plus scheduled scans respect the configured local report directory.
- Hermsec V3 now has the same H/keyhole logo system as V2, including light/dark-aware renderer branding.
- Hermsec V3 chat is wired to the root Hermsec CLI scan harness through a typed Electron preload bridge. The `Scan project` quick action and scan-intent chat messages run the configured project through the scanner stack, save an HTML report to the configured report directory, then show only a concise completion message with the saved `report.html` path and an `Open report in File Explorer` button.
- Hermsec V3's Projects sidebar now reads real local folders from `Test projects` through Electron IPC instead of dummy rows. Selecting a project persists its full filesystem path as `defaultProjectDir`, updates the composer project chip, and makes the next chat scan target that folder.
- Hermsec V3 chats are now persistent project-scoped sessions. Electron main stores sessions in user-data `sessions.json`; the sidebar nests saved chats under each project folder, `New chat` starts a draft under the current project, the first message creates a session, every following message updates it, and startup restores the latest saved chat for the active project.
- Hermsec V3 is online-scan-only for the MVP. The old Offline/Auto UI has been removed from V3 settings; report-directory selection remains a native Electron folder picker wired through preload IPC.
- Hermsec V3 generates a scanner-backed interactive v4 dashboard and one-page executive report after desktop scans. Each scan writes `dashboard/index.html`, `dashboard/data.js`, `onepager/index.html`, `onepager/data.js`, and `onepager/report.pdf` beside the existing Hermsec artifacts.
- Hermsec V3 dashboard mode is a real app view beside chat/settings. The top-right app action strip has a Dashboard button that enables only after the current project has a generated dashboard, and dashboard mode has `Chat mode` plus `Scan again`. `Scan again` compares the saved git/filesystem project fingerprint and shows `No project changes since the last scan.` when unchanged.
- Hermsec V3 scan progress is visible during scans with scanner-stage statuses for Hermsec heuristics, Semgrep, Gitleaks, Bandit, OSV dependency checks, pip-audit, SafeDep PMG npm audit, online vulnerability intelligence, report generation, PDF generation, and agent review.
- Hermsec V3 chat now shows scan progress inline below the active `Thinking...` row as a compact collapsible disclosure, so scanner details stay in the conversation flow instead of floating over messages.
- Hermsec V3 scans can be stopped or restarted while running. Electron main owns the active scan process and kills the scan process tree on cancel; chat exposes Stop/Restart controls in the composer, and dashboard exposes the same controls in the top action strip.
- Hermsec V3 reports now write a local `scan-metadata.json` beside each report. The v4 dashboard and one-pager map that local metadata plus `project-state.json` and `report-document.json` into stable path, scan id, branch, commit, dirty tree, started, finished, generated, and duration fields. The dashboard bundle rebuilds report data on load so older report bundles do not show `Invalid Date`.
- Hermsec V3 dashboard styling is pinned to the app's Hermsec dark theme tokens when embedded, using the same near-black/zinc surfaces, blue accent, green success, and red danger palette as the desktop shell.
- Hermsec V3 dashboard reports no longer expose template version switches. The embedded dashboard uses the current Hermsec report template assets when opened, so older generated report folders also stop showing legacy `v1`/`v2`/`v3`/`v4` selector pills. The dashboard section tabs are sticky below the report header for easier navigation while scrolling.
- Hermsec V3 sessions and projects can be cleaned up from the sidebar. Hover or right-click a project/session row to reveal Archive/Delete actions. Session delete removes the local chat record; project archive/delete hides it in Hermsec's local project state without deleting the actual folder from disk.
- Hermsec V3 has an in-app automation popup in the top-right action strip. It supports enabled/disabled state, every day/every 3 days/every week, exact run time, and Run Now. Automations only run while the app is open; on startup and then once per minute the app checks whether the schedule is due, compares project state, and scans only when the project changed.
- Hermsec V3 automation scheduling now supports a flexible `Every N days` interval plus explicit `Every week` and `Every month` options. Legacy saved `daily` and `every-3-days` settings are normalized into the custom day interval so older local settings keep working.
- Hermsec V3 now has a dedicated Automations app view opened from the left sidebar. It shows a centered Codex-style `Automations` page with a current project-scan automation row, hover-revealed Run/Edit/More actions, and an editor popup that uses the same enable/frequency/time/run-now controls as the quick automation panel.
- Hermsec V3 Electron no longer opens DevTools automatically in dev mode. DevTools are opt-in through `HERMSEC_OPEN_DEVTOOLS=true`, V3 supports `--home-dir` / `HERMSEC_HOME`, and package icons use the Hermsec H/keyhole assets.
- Hermsec V3 chat now has a bounded security assistant router instead of a single canned fallback. It answers Hermsec/project-security questions, redirects off-topic prompts back to security work, and can explain the latest generated HTML report by reading the report artifacts next to `report.html` (`summary.json`, `findings.json`, and related files). Questions such as "what did the scan find?" explain the existing report rather than starting another scan.
- Hermsec V3's report explainer now supports conversational follow-ups such as "have you scanned?", "what should I fix first?", and "show me where the issues are in code." It answers from scanner-backed report evidence, includes file/line locations and redacted source snippets when available, and keeps off-topic prompts bounded to security work.
- Hermsec V3 can generate copy-ready security-fix prompts on request. When the user asks for a prompt for another coding agent, the latest report evidence is converted into a bounded defensive prompt with repo path, report path, prioritized findings, file/line evidence, fix constraints, and verification requirements; the chat renders it as a monospaced prompt block with a small Codex-style copy action underneath.
- Hermsec V3 now supports follow-up revisions to those fix prompts. If the user asks to update/rewrite/break the previous prompt into phases, the chat recognizes the previous copyable prompt as context, generates a new scanner-backed prompt variant, returns a fresh copy action, and saves the prompt as a `.txt` file under the latest report's `prompts` directory with an `Open prompt file in File Explorer` link.
- Hermsec V3 report conversations now route through a main-process `reports.converse` bridge. The bridge reads the latest scanner artifacts, builds a compact redacted evidence packet, optionally uses the configured OpenAI-compatible model/provider for a natural security-coach answer, and falls back to local scanner-backed guidance when no provider is available.
- Hermsec V3's model bridge now enforces final-answer-only chat behavior. The system prompt includes a Hermsec action map for normal chat, report reading, scans, automations, fix prompts, and prompt revisions, and the main-process response path blocks obvious internal reasoning leaks such as `The user is asking...` / `I need to...` planning text before it reaches the chat UI.
- Hermsec V3 chat is now model-first after explicit scan/automation/capability/fix-prompt intents. Normal messages such as "hello" go to the configured model with Hermsec's bounded system prompt, selected project context, recent chat history, and report evidence when available instead of being rejected by a security-only keyword router.
- Hermsec V3 chat can set scan automations conversationally. Direct requests such as "set a scan automation every day at 9am" save the in-app automation immediately; incomplete requests ask compact follow-up question cards for cadence and/or exact time, then persist the automation.
- Hermsec V3 chat now exposes model activity more clearly: the thinking row shows what the agent is doing and names the selected model/thinking level when it is reading report evidence and asking the provider. The composer also has a persisted Fast/Balanced/Deep thinking selector that changes model response budget and chat-history context.
- Hermsec V3 OpenCode Go provider defaults now ignore empty env values, load ancestor `.env.local` files, default to `https://opencode.ai/zen/go/v1`, and use `OPENCODE_GO_API_KEY` when no explicit API-key env var is configured. A local provider smoke check returned HTTP 200 from `/models` with the redacted OpenCode Go key.
- Hermsec V3 now also tolerates older saved provider settings that still point OpenCode Go at `HERMSEC_MODEL_API_KEY`: the model resolver tries the saved env var, the configured `HERMSEC_MODEL_API_KEY_ENV` target, `OPENCODE_GO_API_KEY`, and then `HERMSEC_MODEL_API_KEY`. This fixes the scripted fallback behavior when a valid OpenCode Go key exists but the local settings file was stale.
- Hermsec V3 chat no longer forces the transcript to the bottom while the user is reading older messages. When the user scrolls away from the latest message, a small centered down-arrow appears and smoothly returns to the current messages.
- Hermsec V3 chat auto-follow now suppresses the jump-to-latest affordance during programmatic message insertion, avoiding the previous blue-button flash and jumpy scroll behavior while normal send/response messages arrive.
- Hermsec V3 Doctor now renders as a live chat dashboard immediately when the run starts. Electron main streams Doctor progress events for the CLI readiness command, internet connectivity targets, scanner/tool rows, and desktop provider checks; the card updates in place with checking/ready/warn/fail states and has both main-process and renderer-side timeout fallbacks so it cannot spin forever.
- Hermsec V3 Doctor now has a more app-native chat card: it uses the same elevated surface, border, restrained status chips, compact rows, and Hermsec logo treatment as the rest of the V3 chat shell. It also surfaces a dedicated Readiness blockers section so missing scanner binaries, provider warnings, and connectivity source issues are visible instead of hidden behind a single score.
- Hermsec V3 Doctor connectivity now checks NVD website reachability instead of using the NVD API endpoint as the general internet signal. This avoids transient NVD API `503` responses making an otherwise healthy network look broken in the chat card.
- Hermsec V3 packaged builds now bundle the root Hermsec CLI and scanner runtime. `npm.cmd run dist:win` runs `prepare:cli-bundle`, `prepare:runtime-tools`, V3 build, and Electron Builder so the generated Windows installer/portable app includes Semgrep, Gitleaks, Bandit, OSV-Scanner, pip-audit, SafeDep PMG, and the CLI/report engine.
- V3 app startup configures bundled runtime paths before Doctor or scans run. In packaged builds it points `HERMSEC_CLI_ROOT` at `resources/hermsec-cli`, prepends `resources/runtime-tools/<platform>-<arch>` to scanner resolution, and sets scanner-specific env overrides before falling back to machine PATH.
- Hermsec V3 scan assistance is now organized around exactly two user-facing modes: `Scanner + model summary` and `Deep assisted scan`. Chat scan requests no longer launch immediately; they first show a compact choice card explaining the tradeoff, then persist the chosen mode as the default. Dashboard `Scan again`, the quick automation popover, the Automations manager, and the background due-check scheduler all pass the selected assist mode into the scan request.
- Hermsec V3 automations and Settings now expose the two scan modes with a shared polished segmented control. Automation runs store their chosen assist mode so scheduled and manual automation runs stay consistent with the user's selection.
- The root CLI scan command now accepts `--assist-mode scanner-model-summary|deep-assisted`, and V3 passes that flag through when it launches the root scanner. Deep assisted mode uses a stricter model prompt for scanner-backed prioritization and relationship notes, while the existing evidence validator still rejects unsupported model output.
- Hermsec V3 scans now write a deterministic `scan-assist.json` artifact beside each report. It groups similar scanner findings, records matching scanner pairs, labels scanner-confirmed versus multi-scanner groups, and gives the dashboard a concrete scanner-backed merge map for `scanner-confirmed + model-supported` reports.
- The V3 dashboard and one-page report now show the selected assist mode instead of the internal online transport mode. The interactive dashboard includes an Assist Mode card in the pipeline tab and a Scanner-confirmed merge map in the adjudication tab, with model explanations used only when accepted from supplied scanner evidence.
- V3 report normalization now understands root harness dependency findings that store `package` and identifiers as structured objects, so dependency package names, versions, CVEs, GHSAs, and OSV IDs render correctly in the dashboard.
- Hermsec V3 chat composer has two states: the empty-chat composer remains large for the first prompt, while active conversations use a slimmer follow-up composer with a smaller radius, tighter padding, `Ask for follow-up changes` placeholder, and bottom-row project/model/send controls.
- Hermsec V3 chat bubbles render safe lightweight Markdown from model output: fenced code blocks appear as code panels, inline backtick code appears as code chips, bullet lists render as lists, and `**bold**` / `__bold__` render as bold text without allowing arbitrary HTML.
- Hermsec V3's custom title bar now has real File/Edit/View/Window/Help dropdown menus. File omits Quick Chat and Log Out, View omits terminal/file-tree/browser entries and adds Open Dashboard, Window exposes minimize/zoom/close, and Help contains a scrollable About Hermsec modal describing the product, scanner stack, reports, automations, local state, and model/provider behavior.
- Hermsec V3's Projects sidebar header has an Add Project `+` control that opens the native folder picker, selects the chosen local folder, starts a new project-scoped chat, and refreshes the project list.
- Vulnerable MVP lab projects live under `Test projects/hermsec-node-express-vuln-lab` and `Test projects/hermsec-python-flask-vuln-lab` with expected-findings metadata for recall-style validation.
- Blessed-powered keyboard-first terminal chatbot UI with safe non-interactive fallback, fixed input focus, an OpenCode-style centered home screen, live slash-command palette, arrow-key selectable command/settings/model/provider palettes, paste-friendly input, first-run and explicit `hermsec onboard` onboarding, `/help` and `/commands`, `/settings`, `/model`/`/models`, `/provider`/`/connect`, `/history`, `/sessions`, and wiring to the real doctor, scan harness, report index, schedule list, workspace store, session store, and security-intel update tools.
- Local scan harness with repository discovery, built-in heuristics for secrets, JS/TS, Python, package/lockfile, and config/supply-chain patterns, plus optional external scanner execution.
- JSON-backed app data, user config, workspaces, schedules, sessions, report indexes, and security-intel cache.
- Deterministic local JSON/Markdown/HTML reports with redaction, evidence bundles, and delta artifacts.
- Restricted model/provider layer with env-only credentials, safe credential-reference validation, non-secret provider verification fingerprints, and no-model fallback.
- Evaluation matcher/metrics for precision, recall, F1, category/confusion scoring, duplicate-noise classification, and safe vulnerable/clean fixture repos.
- Online security intelligence has deterministic trusted-source fetchers for CISA KEV, OSV.dev, GitHub Advisory Database, and NVD, plus source TTL/cache metadata, offline fallback behavior, and short security-update summaries for CLI/TUI news output.
- Verified model-backed report explanations through the env-only Gemini provider path; OpenAI-compatible, OpenAI, OpenRouter, Claude, OpenCode Go, Ollama, and no-model adapters are wired through the same router.
- npm CLI packaging is verified with a packed tarball and temporary global-prefix install; `hermsec` launches the TUI, while `hermsec doctor`, `hermsec scan`, and `hermsec intel update` remain scriptable.

Latest verified commands:

```text
npm run build
npm test
pmg npm run test:desktop
pmg npm audit --json
node dist/src/bin/hermsec.js doctor --json
node dist/src/bin/hermsec.js agent providers --json
node dist/src/bin/hermsec.js agent ask "what can you do?" --target "Test projects\hermsec-node-express-vuln-lab" --json --no-model
node dist/src/bin/hermsec.js intel update --source cisa-kev
node dist/src/bin/hermsec.js intel update --source nvd
node dist/src/bin/hermsec.js scan tests\fixtures\repos\node-express-vulnerable --mode online --out .hermsec\production-hardening-node --json --md --html --no-model
node dist/src/bin/hermsec.js scan tests\fixtures\repos\python-flask-vulnerable --mode online --out .hermsec\production-hardening-python --json --no-model
node dist/src/bin/hermsec.js scan tests\fixtures\repos\node-express-vulnerable --mode online --out .hermsec\verify-model-reports --json --md --html
node dist/src/bin/hermsec.js intel update --offline
node dist/src/bin/hermsec.js eval run --mode scanner-only --out .hermsec\verify-eval
npm pack --ignore-scripts
cd v2\apps\web && pmg bun --no-install run test
cd v2\apps\web && pmg bun --no-install run build
cd v2\apps\desktop && pmg bun --no-install run test
cd v2\apps\desktop && pmg bun --no-install run build
cd v2\packages\contracts && pmg bun --no-install run test
cd v2\packages\contracts && pmg bun --no-install run build
cd v2\hermsec-v3 && pmg bun --no-install run build
cd v2\hermsec-v3 && pmg bun --no-install run smoke:dashboard
cd v2\hermsec-v3 && pmg npx electron-builder --win nsis portable --x64 --publish never
cd v2\hermsec-v3 && npm.cmd run typecheck
cd v2\hermsec-v3 && npm.cmd run build
cd v2\hermsec-v3 && npm.cmd run smoke:doctor
cd v2\hermsec-v3 && npm.cmd run smoke:dashboard
cd v2\hermsec-v3 && npm.cmd run dist:win
cd v2\hermsec-v3 && .\release\win-unpacked\Hermsec.exe --smoke-doctor
node dist\src\bin\hermsec.js scan "Test projects\hermsec-node-express-vuln-lab" --mode auto --out ".hermsec\v3-smoke" --json --html --no-model
node dist\src\bin\hermsec.js doctor --json
```

Current verified scanner/tool status on this PC: Semgrep `1.167.0`, Gitleaks `8.30.1`, Bandit `1.9.4`, OSV-Scanner `2.4.0`, pip-audit `2.10.1`, and SafeDep PMG `0.19.1` are installed in `C:\Users\whent\.local\bin` and detected by `doctor`. Gitleaks, OSV-Scanner, and PMG were installed from official GitHub release assets with SHA-256 checks against the published checksum files. Semgrep, Bandit, and pip-audit were installed with `uv tool install`.

Current verified intel status: CISA KEV and NVD live update both complete successfully; the combined cache contains `1654` items, and offline cache reuse works.

Current full-suite status on June 8/19, 2026: root `pmg npm test` builds successfully and runs `59` Node tests; `59` pass, `0` fail, and `0` skip. The suite includes scheduler coverage plus vulnerable test-project recall validation. `pmg npm audit --json` previously reported `0` vulnerabilities. Targeted V2 checks currently pass for `apps/web` tests/build, `apps/desktop` tests/build, and `packages/contracts` tests/build with `pmg bun --no-install`. V2 full monorepo `bun --no-install run test` was run after the live bridge work: contracts, effect-acp, desktop, shared, scripts, and web tests progressed through the relevant Hermsec/Synara surfaces after Windows fixes, but the full monorepo command still fails in inherited `apps/server` tests with Windows-specific Cursor ACP wrapper and Git line-ending/path assumptions unrelated to the Hermsec bridge. V3 `npm.cmd run typecheck` and `npm.cmd run build` pass. V3 `npm.cmd run smoke:doctor` passes against the normal V3 profile with status `ready`, health score `100`, required `7/7`, scanners `6/6`, internet `5/5`, and providers `1/1`. V3 `npm.cmd run smoke:dashboard` launches Electron in smoke mode, runs a live online scan against `Test projects/hermsec-node-express-vuln-lab`, generates the v4 dashboard, generates a non-empty `onepager/report.pdf`, validates the dashboard bundle, and verifies the unchanged-project skip. Windows packaging now passes with `npm.cmd run dist:win`, producing ignored setup/portable artifacts under `v2/hermsec-v3/release`: `Hermsec Setup 0.1.0.exe` and `Hermsec 0.1.0.exe`. The unpacked packaged executable passed Doctor smoke at `100%` and packaged dashboard smoke with bundled CLI/scanners.

Current verified eval status: the Node vulnerable fixture scanner-only run reports precision `1.00`, recall `1.00`, and F1 `1.00` after aligning the JSON ground truth with all intentionally planted findings.

Production verification script: `scripts/verify-production.ps1` runs tool discovery, `pmg npm test` when PMG is available, `hermsec doctor --json`, and the scanner-only eval gate. It now passes in strict mode with PMG installed. PMG setup instructions are in `docs/pmg-setup.md`.

Known local constraints:

- External scanner binaries are machine-local prerequisites, not repository contents; `doctor` is the source of truth for a specific laptop/VPS.
- EPSS, RSS/security-news feeds beyond GitHub/NVD recency, deps.dev, Scorecard, Socket, Phylum, and official OWASP/NIST benchmark acquisition remain future integrations.
- OS-level schedule registration remains a future adapter; current scheduler storage, manual `schedule run`, and watch mode work locally.

## Recent Work Log - June 9, 2026

- V3 Doctor is now a first-class chat action. The Doctor quick action routes through Electron IPC, runs scanner/tool/network/provider readiness checks, and renders a compact Hermsec-themed summary card in chat instead of plain text only.
- V3 Doctor now understands desktop provider settings. OpenCode Go can be marked ready from the saved V3 settings/API key path even when the root CLI environment alone would fall back to scanner-only mode. Secrets remain redacted and are not printed.
- Root scan harness now sees Java/Maven projects. File discovery includes Java, JSP, XML, properties, Gradle files, `pom.xml`, Gradle manifests, and `gradle.lockfile`; repository discovery now reports Maven/Gradle instead of `package managers: none`.
- Root scan harness now has Java servlet/security heuristics for BenchmarkJava-style categories: command injection, SQL injection, XSS, LDAP injection, XPath injection, path traversal, weak crypto, weak hash, weak randomness, insecure cookies, and trust-boundary/session issues.
- Optional Semgrep execution now considers Java/JSP inputs, and the default local Semgrep rule bundle includes starter Java process, SQL, and servlet response rules.
- Added `scripts/benchmark-java-score.mjs`, which scores Hermsec scan JSON against OWASP BenchmarkJava `expectedresults-1.2.csv` and reports TP/FP/FN/TN, precision, recall, F1, per-category metrics, and ignored/extra predictions.
- Added regression tests for Java/Maven file discovery and Java servlet heuristic findings.
- OWASP BenchmarkJava was cloned under `.hermsec-benchmarks/BenchmarkJava` for local evaluation. Baseline before Java support found `0 / 1415` labeled vulnerable Java cases because Java files were invisible to the harness.
- Post-Java BenchmarkJava run found `1220` true positives, `708` false positives, `195` false negatives, and `617` true negatives. Overall precision is `0.6328`, recall is `0.8622`, and F1 is `0.7299`. Scan wall time was about `11.3s`; Hermsec scan duration was about `9.8s`.
- Current BenchmarkJava artifacts: `.hermsec/benchmark-java-after-java-result.json`, `.hermsec/benchmark-java-after-java-score.json`, and `.hermsec/benchmark-java-after-java/benchmarkjava/2026-06-09T17-30-45-803Z/report.html`.
- Full root test suite passed after the Java harness work: `npm test` ran `61` tests with `61` passing.
- Root `node_modules/electron` was missing Electron's generated `path.txt`, which broke the desktop smoke test. The local generated dependency state was repaired by supplying a local Electron executable/path so tests could run; no source behavior depends on this repair.
- Initial BenchmarkJava scan produced JS/support-file noise from minified/bootstrap assets. The JS/TS heuristic scanner now skips minified JS assets such as `.min.js`.
- Current harness roadmap from Grok/comparison analysis: keep Semgrep, Gitleaks, and OSV-Scanner as the lightweight base; next add Java taint tracking plus BenchmarkJava CI gates, then Trivy and Checkov, then broader OSV ecosystem coverage, then optional deep scanners such as TruffleHog, Syft/Grype, Dependency-Check, and SonarQube CE.
- Next best accuracy improvement is Java taint tracking. It should model servlet request sources, aliases such as `param -> bar`, simple transformations, sanitizers such as ESAPI encoders and prepared-statement value binding, and sinks for SQL/LDAP/XPath/file/response/session/process APIs. Goal: preserve Java recall at or above the current `86%` while raising precision from `63%` toward `75%+`.
- A dedicated root tracker now lives at `project-report-track.md`. Use it as the ongoing changelog, issue log, benchmark ledger, and decision record for future Hermsec work.

## Recent Work Log - June 19, 2026

- V3 Doctor live dashboard: the Doctor card is inserted into chat immediately instead of waiting for the run to finish.
- Added typed Doctor progress events over Electron IPC/preload with per-run ids, so progress updates hydrate only the matching chat card.
- Added live card states for scanner stack rows, internet connectivity chips, summary groups, and a compact live-check trace.
- Added safety fallback behavior: the root Doctor child process is capped at `20s`, connectivity requests retain their `7s` aborts, and the renderer stops a Doctor chat run after `35s` with a watchdog error card instead of leaving the UI stuck.
- Fixed the desktop Doctor child-process path: Electron was previously using `process.execPath`, which points to `electron.exe`; it now launches `node.exe` for the root CLI Doctor command.
- Added `npm.cmd run smoke:doctor` for the V3 app. It runs the real Electron Doctor path without opening a window, asserts required/scanner/internet readiness, prints group/connectivity JSON, and exits non-zero on smoke failures.
- Verification on this change: `cd v2\hermsec-v3 && npm.cmd run typecheck` passed, `cd v2\hermsec-v3 && npm.cmd run build` passed, `node dist\src\bin\hermsec.js doctor --json` returned `15 passed, 0 warnings, 0 failed, 6 skipped`, V3 Doctor smoke passed at `100%` against the normal V3 profile, and V3 dashboard smoke passed after the full scanner stack was installed.
- Root deep-assisted BenchmarkJava validation now has a real model-backed run. After tuning model chunking to top 10 findings with chunk size 2 and a 60s per-chunk timeout, the full online BenchmarkJava scan completed with `generatedWithModel=true`, provider `opencode-go`, `9384` findings, and a raw benchmark export.
- Latest OWASP BenchmarkJava score from the real model-backed run: precision `0.6297`, recall `0.8749`, F1 `0.7323`, TP `1238`, FP `728`, FN `177`, TN `597`. The model currently improves explanation/prioritization only; scanner/heuristic output still determines raw vulnerability detection.
- Successful deep-assisted benchmark artifacts live under `.hermsec\benchmark-runs\BenchmarkJava-deep-assisted-model-real-20260619-155145\benchmarkjava\2026-06-19T13-56-07-856Z\`. The temporary model credential was process-only, and the CLI config was restored to `preferredModelProvider=none` and `privacyMode=local-only` after the run.
- Planned next harness direction: add an adaptive scanner-planning phase that inspects each repo, detects languages/frameworks/manifests/lockfiles/IaC files, chooses only the required scanners, verifies or installs missing tools into the Hermsec-managed runtime, and then runs the relevant scanners. The chat UI should use the simple Hermsec card theme with the existing top buffer animation, a live stage comment, a neutral vertical timeline, and expandable inline step details for tools, installs, scanner lanes, findings, skipped reasons, and logs.
- V3 first pass of that direction is now implemented: the scan flow profiles the project before running the CLI, builds a scanner plan, verifies current runnable tools, marks future adapters as planned/skipped, and renders the simple neutral adaptive scan timeline card in chat with expandable step details. Typecheck/build passed and the V3 dev app was restarted for testing.

## Recent Work Log - June 19, 2026 - Scanner-Managed Harness Expansion

- Hermsec is expanding from a fixed bundled scanner set into a scanner-managed harness. The root catalog now records each scanner's id, label, category, command, version, install kind, supported languages, input types, parser, default enablement, auto-install preference, and risk notes.
- The scanner catalog now covers Hermsec heuristics, Semgrep, Gitleaks, TruffleHog, OSV-Scanner, Trivy, Checkov, Bandit, pip-audit, SafeDep PMG npm audit, Retire.js, FindSecBugs/SpotBugs, OWASP Dependency-Check, Psalm, Composer audit, gosec, govulncheck, cargo-audit, Brakeman, Flawfinder, Cppcheck, and .NET vulnerable package checks.
- The root external scanner runner now supports a broader set of safe command builders and parsers and respects `HERMSEC_ENABLED_SCANNERS`, so the desktop app can narrow scanner execution to the relevant project profile.
- V3 now has scanner settings in the app settings model: auto-install missing scanners, allow online scanner updates, lab/install-all mode, and per-scanner enabled/auto-install flags. V3 main process exposes scanner list/status/install/uninstall/update handlers.
- Current handoff caveat: the visible Settings > Scanners renderer surface and preload scanner API are now wired in the current tree, but still need typecheck/build/runtime UI verification and polish.
- The adaptive workflow should be: inspect project, match languages/manifests/lockfiles/IaC markers to scanner capabilities, verify managed/PATH tools, install eligible missing tools into `userData\managed-scanners\<platform>-<arch>` when the user enables auto-install, pass enabled scanner env into the root CLI, run scanner lanes, then report completed/skipped/failed scanners without blocking the whole scan on optional tools.
- Managed installs must stay outside scanned repositories. Python tools use `uv tool install`, npm tools use a global prefix with `--ignore-scripts`, Go tools use `go install` with `GOBIN` pointed at Hermsec's managed bin directory, and system/manual tools are detected without mutating the target project.
- Benchmark plan: keep OWASP BenchmarkJava as the Java accuracy gate, add OpenSSF CVE Benchmark for JS/TS, add focused Go/Rust/PHP/IaC fixtures, and track precision, recall, F1, runtime, scanner failures, skipped scanners, and installer behavior per ecosystem.
- Known limitations: root and V3 currently duplicate catalog data; native checksum-backed installers still need durable implementation for several binary tools; Dependency-Check needs cache policy; FindSecBugs requires compiled classes; Checkov/Trivy may need online database setup; macOS/Linux managed scanner behavior remains unverified.
- Next best work: verify Settings > Scanners end to end, deduplicate the catalog, confirm scanner settings feed into every scan launch, add installer failure tests, and run root tests plus V3 typecheck/build after the scanner-managed flow settles.
- Verification update: root and V3 typechecks now pass, root build and V3 build pass, scanner external tests pass `7/7`, scanner heuristic tests pass `10/10`, and a CLI smoke scan against `tests\fixtures\repos\node-express-vulnerable` completed with `10` findings.
- Prep-stage update: V3 scan preparation now calls the managed scanner prep path. When auto-install is enabled, eligible missing scanners are installed into the HermSec managed tools root, failures show as failed detail rows, and the scan continues with ready scanners.
- Scanner env update: `HERMSEC_ENABLED_SCANNERS` now treats unset as catalog defaults, `all` as lab/all scanners, and `__none__`/empty as no external scanners. Disabled scanners are omitted rather than listed as skipped scanner lanes.
- End-to-end verification update: root full suite now passes `70/70`; V3 Doctor smoke, dashboard smoke, typecheck, build, real Electron Settings > Scanners UI CDP check, and CLI scan fallback cases all passed. Captured UI screenshot: `output\playwright\v3-electron-scanners-verified.png`.
- Remaining verification caveats: Doctor still checks the legacy six scanner commands, not all 22 Settings scanner entries; native checksum-backed installers remain future work; expanded parser fixture tests should be added over time.
- Release pipeline update: `.github\workflows\desktop-release.yml` builds Windows and macOS desktop packages on `v*` tags or manual dispatch, then creates/updates a GitHub Release. README links macOS users to `https://github.com/sethwhenton/hermsec/releases/latest`. macOS CI builds are unsigned until Apple signing/notarization secrets are added.

## Current Decision

Keep the CLI scan engine as the reusable core, but make the Electron desktop app the main user experience. The older Blessed TUI remains as a scriptable/legacy surface. The v1 custom Electron app is stable and tested; v2 is now a whole-source Synara fork that will become the main desktop direction after dependency install/build validation and deeper Hermsec feature grafting.

## Current Research Artifacts

Read this before implementation:

```text
docs/research/manual-mode-start-to-finish.md
docs/research/automation-online-offline-notifications.md
docs/research/tui-onboarding-harness-plan.md
docs/research/local-mode-chat-agent-intel-plan.md
implementationplan.md
planforv2.md
```

These contain the end-to-end architecture, scanner choices, vulnerability intelligence sources, GitHub access strategy, model role, data schema, local-mode chat agent plan, workspace/session model, git-aware scheduler, harness boundary, implementation phases, benchmark evaluation plan, testing plan, and presentation plan.

## Planned Stack

- TypeScript for CLI, TUI, orchestration, normalization, reports, and model providers.
- Electron, React, and Vite for the desktop app.
- Custom Hermsec harness as the core engine.
- Electron desktop and scriptable CLI as the primary frontends over the same core.
- Hermes Agent integration later through an adapter that calls Hermsec, not as an MVP dependency.
- Scanner CLIs for evidence:
  - Bandit
  - Semgrep
  - Gitleaks
  - pip-audit
  - SafeDep PMG-wrapped npm audit
  - OSV-Scanner
- Bring-your-own model providers:
  - OpenRouter
  - OpenAI
  - Claude
  - Gemini
  - OpenCode Go
  - Ollama
  - LM Studio or any OpenAI-compatible local endpoint
  - no-model fallback
- Optional automation and notification features:
  - scheduled scans
  - watch/after-idle scans
  - offline queue and online sync
  - local report directory configuration
  - security intelligence feed
  - AgentMail and Telegram later, after the local MVP

## Safety Rules

- Do not install project dependencies during scanning by default.
- Do not run package lifecycle scripts by default.
- Prefer lockfile scanning.
- Do not invent CVEs. CVEs must come from scanner or advisory evidence.
- Do not send full private repositories to cloud models by default.
- Redact secrets before model calls and report output.
- Keep the project defensive: scan, explain, prioritize, and suggest fixes.

## Next Work

1. Add official OWASP/NIST benchmark acquisition behind explicit opt-in commands.
2. Move Hermsec scan/intel/report core from the root CLI bridge into v2/v3's server/runtime layer if the CLI bridge becomes too slow or brittle.
3. Add richer dashboard interactions and saved report history inside V3.
4. Package and distribute the Electron app from the verified Windows installer/portable output; macOS/Linux scripts are defined but need platform-specific verification.
5. Add EPSS, Scorecard/deps.dev/Socket/Phylum, and curated security-news feed adapters.
6. Add OS-level schedule registration if needed; current scheduler storage, manual `schedule run`, and watch mode work locally.
7. Add AgentMail and Telegram later, after the local core stays stable.
8. Add Hermes Agent or VPS/GitHub adapter after the Hermsec core is stable.
9. Create demo presentation materials from the verified local run.
