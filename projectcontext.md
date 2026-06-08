# Hermsec Project Context

## Purpose

Hermsec is a local-first, CVE-aware AI security assistant for repositories. The current product target is a Synara-inspired Electron desktop app: a user selects a local workspace, Hermsec runs defensive scanners, normalizes evidence, refreshes trusted vulnerability intelligence, optionally asks a bring-your-own model to explain scanner-backed findings, and writes local HTML, Markdown, and JSON reports.

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
- Hermsec V3 sessions and projects can be cleaned up from the sidebar. Hover or right-click a project/session row to reveal Archive/Delete actions. Session delete removes the local chat record; project archive/delete hides it in Hermsec's local project state without deleting the actual folder from disk.
- Hermsec V3 has an in-app automation popup in the top-right action strip. It supports enabled/disabled state, every day/every 3 days/every week, exact run time, and Run Now. Automations only run while the app is open; on startup and then once per minute the app checks whether the schedule is due, compares project state, and scans only when the project changed.
- Hermsec V3 Electron no longer opens DevTools automatically in dev mode. DevTools are opt-in through `HERMSEC_OPEN_DEVTOOLS=true`, V3 supports `--home-dir` / `HERMSEC_HOME`, and package icons use the Hermsec H/keyhole assets.
- Hermsec V3 chat now has a bounded security assistant router instead of a single canned fallback. It answers Hermsec/project-security questions, redirects off-topic prompts back to security work, and can explain the latest generated HTML report by reading the report artifacts next to `report.html` (`summary.json`, `findings.json`, and related files). Questions such as "what did the scan find?" explain the existing report rather than starting another scan.
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
node dist\src\bin\hermsec.js scan "Test projects\hermsec-node-express-vuln-lab" --mode auto --out ".hermsec\v3-smoke" --json --html --no-model
```

Current verified scanner/tool status on this PC: Semgrep, Gitleaks, Bandit, OSV-Scanner, pip-audit, and SafeDep PMG are installed and detected by `doctor`. PMG was installed from the official SafeDep GitHub release binary `v0.17.4`; the Windows zip SHA-256 matched the release `checksums.txt`, and `pmg version` reports `0.17.4`.

Current verified intel status: CISA KEV and NVD live update both complete successfully; the combined cache contains `1654` items, and offline cache reuse works.

Current full-suite status on June 8, 2026: root `pmg npm test` builds successfully and runs `59` Node tests; `59` pass, `0` fail, and `0` skip. The suite includes scheduler coverage plus vulnerable test-project recall validation. `pmg npm audit --json` previously reported `0` vulnerabilities. Targeted V2 checks currently pass for `apps/web` tests/build, `apps/desktop` tests/build, and `packages/contracts` tests/build with `pmg bun --no-install`. V2 full monorepo `bun --no-install run test` was run after the live bridge work: contracts, effect-acp, desktop, shared, scripts, and web tests progressed through the relevant Hermsec/Synara surfaces after Windows fixes, but the full monorepo command still fails in inherited `apps/server` tests with Windows-specific Cursor ACP wrapper and Git line-ending/path assumptions unrelated to the Hermsec bridge. V3 `pmg bun --no-install run build` passes. V3 `pmg bun --no-install run smoke:dashboard` launches Electron in smoke mode, runs a live online scan against `Test projects/hermsec-node-express-vuln-lab`, generates the v4 dashboard, generates a non-empty `onepager/report.pdf`, validates the dashboard bundle, and verifies the unchanged-project skip. Windows packaging smoke passes with `pmg npx electron-builder --win nsis portable --x64 --publish never`, producing ignored setup/portable artifacts under `v2/hermsec-v3/release`.

Current verified eval status: the Node vulnerable fixture scanner-only run reports precision `1.00`, recall `1.00`, and F1 `1.00` after aligning the JSON ground truth with all intentionally planted findings.

Production verification script: `scripts/verify-production.ps1` runs tool discovery, `pmg npm test` when PMG is available, `hermsec doctor --json`, and the scanner-only eval gate. It now passes in strict mode with PMG installed. PMG setup instructions are in `docs/pmg-setup.md`.

Known local constraints:

- External scanner binaries are machine-local prerequisites, not repository contents; `doctor` is the source of truth for a specific laptop/VPS.
- EPSS, RSS/security-news feeds beyond GitHub/NVD recency, deps.dev, Scorecard, Socket, Phylum, and official OWASP/NIST benchmark acquisition remain future integrations.
- OS-level schedule registration remains a future adapter; current scheduler storage, manual `schedule run`, and watch mode work locally.

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
