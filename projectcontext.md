# Hermsec Project Context

Hermsec V3 is the active product. It is a local-first, CVE-aware desktop security assistant for repositories: a user selects a local workspace, Hermsec can run defensive scanners or agent-only inspections, normalizes evidence, refreshes trusted vulnerability intelligence for scanner-backed runs, optionally asks a bring-your-own model to explain findings, and writes local HTML, Markdown, JSON, dashboard, and one-page report artifacts.

## Active Layout

- `desktop/` is the primary Electron + React + Vite desktop app.
- `src/` is the reusable CLI, scanner, scheduler, report, intel, and model-provider engine used by the desktop app.
- `tests/` covers the root engine and CLI behavior.
- `.github/workflows/windows-release.yml` and `.github/workflows/macos-release.yml` package the desktop app from `desktop/` and publish release assets when `v*` tags are pushed.

New product work should start in `desktop/` unless the request is specifically about the reusable root CLI/scanner engine.

## Current Product Surface

- Desktop shell with chat/investigation, project selection, scans, dashboards, reports, settings, automations, and Doctor readiness.
- Scanner-managed harness with catalog metadata, enablement state, auto-install preferences, managed/system scanner status, and adaptive project profiling.
- Packaged runtime support for the root Hermsec CLI and scanner tools under desktop resources.
- Provider settings for OpenCode Go, OpenAI, Anthropic, Google Gemini, OpenRouter, local Ollama, and custom OpenAI-compatible/base URLs, with Cursor and Ollama Cloud tracked as future integrations where the current desktop route is not yet wired.
- Local report storage with dashboard and one-page report rendering.

## Common Commands

Root engine:

```powershell
npm.cmd ci
npm.cmd run typecheck
npm.cmd run build
npm.cmd test
node dist\src\bin\hermsec.js doctor --json
```

Desktop app:

```powershell
cd desktop
npm.cmd ci
npm.cmd run typecheck
npm.cmd run build
npm.cmd run smoke:doctor
npm.cmd run smoke:dashboard
npm.cmd run dist:win
```

## Verification Notes

- Root `npm.cmd test` builds the scanner CLI engine and runs Node tests from `dist/tests`.
- Desktop `npm.cmd run build` uses `electron-vite build` and copies report templates.
- Desktop smoke tests require Electron and may exercise network/scanner/provider readiness depending on the local environment.
- Windows and macOS release packaging is handled by `.github/workflows/windows-release.yml` and `.github/workflows/macos-release.yml`.
- Provider settings now use supported provider presets, debounced URL/API-key checks, model discovery, provider-scoped model selection, and collapsible model toggles.
- Fresh desktop settings default to adaptive scanner auto-install (`scanners.autoInstallMissing: true`), and scan completion chat messages link the generated one-page PDF location when available.
- User-facing reports and dashboard data must display friendly scanner names. Legacy `hermsec-offline` findings are compatibility data only and should render as `HermSec heuristics`.
- Chat scan progress should show the real orchestration state from root scanner events. The CLI streams `HERMSEC_PROGRESS <json>` lines in JSON mode while preserving the final JSON result; desktop consumes those lines live and only uses final report-status reconciliation as a fallback.
- Deep assisted mode remains scanner-confirmed/model-supported only. Model explanations must validate against existing finding ids, scanner ids, files, lines, packages, CVEs/GHSAs/OSVs, and CWEs before reports accept them.
- The visible product scan modes are `Deep assisted scan`, `Single agent inspection`, and `MoA assisted inspection`. Keep `scanner-model-summary` as a legacy alias only; do not show it in UI.
- Single Agent and MoA scans are agent-only product modes. They perform repository discovery, then use bounded read-only code inspection helpers without running HermSec heuristics, Semgrep, Gitleaks, Trivy, OSV, Checkov, or other scanner adapters. The helpers may list files, search code, and read snippets inside the selected repo only. They must not execute shell commands, install packages, run lifecycle scripts, or read outside the repo.
- MoA product scans use specialist agents, a false-positive judge, and an aggregator. Reports should include agent-mode metadata, agents used, provider/model details, candidate/accepted/rejected/needs-review counts, aggregator info, runtime, source labels, and judge status.
- Settings > Agents lets users assign configured provider/model pairs per MoA task. Current task rows are `injection-and-execution`, `auth-and-data-flow`, `secrets-and-config`, `moa-false-positive-judge`, and `moa-aggregator`; unset rows use the active chat model.
- Settings > Models is the source of truth for provider model availability. OpenCode Go should show every model returned by provider discovery or the current 20-model preset seed; Settings > Agents should only list models enabled from Settings > Models.
- Desktop scan execution passes active provider/model settings to the root CLI through environment variables so configured providers work inside the bundled CLI process.
- Vulnerability intelligence is now a real report-generation step. The harness inventories supported dependency manifests/lockfiles, refreshes or reuses OSV/GitHub Advisory/NVD/CISA KEV intelligence according to the online-updates setting, filters out generic ecosystem-only feed items, and writes matched advisory/KEV records into `report-document.json`, Markdown, HTML, dashboard, and one-page outputs.
- The root CLI now also supports `scanner-moa-assisted` for research/product experiments. This hybrid mode runs the scanner stack and scanner-free MoA inspection, sends both candidate sets through the false-positive judge, aggregates accepted candidates, and writes the normal report template. It is currently documented in the Task 5 ACM paper as the best small-fixture F1 result: TP `7`, FP `9`, FN `5`, precision `0.4375`, recall `0.5833`, F1 `0.5000` with OpenCode Go `deepseek-v4-flash`.

## Boundaries

- Do not install dependencies inside scanned repositories.
- Do not run package lifecycle scripts inside scanned repositories during scans.
- Keep provider secrets in environment variables or local user config, never committed repo files.
- Keep generated desktop artifacts such as `desktop/out`, `desktop/release`, `desktop/resources/hermsec-cli`, `desktop/resources/runtime-tools`, and local `.hermsec*` state out of git.
