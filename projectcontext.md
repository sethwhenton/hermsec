# Hermsec Project Context

Hermsec V3 is the active product. It is a local-first, CVE-aware desktop security assistant for repositories: a user selects a local workspace, Hermsec runs defensive scanners, normalizes evidence, refreshes trusted vulnerability intelligence, optionally asks a bring-your-own model to explain scanner-backed findings, and writes local HTML, Markdown, JSON, dashboard, and one-page report artifacts.

## Active Layout

- `desktop/` is the primary Electron + React + Vite desktop app.
- `src/` is the reusable CLI, scanner, scheduler, report, intel, and model-provider engine used by the desktop app.
- `tests/` covers the root engine and CLI behavior.
- `.github/workflows/desktop-release.yml` packages the desktop app from `desktop/`.

New product work should start in `desktop/` unless the request is specifically about the reusable root CLI/scanner engine.

## Current Product Surface

- Desktop shell with chat/investigation, project selection, scans, dashboards, reports, settings, automations, and Doctor readiness.
- Scanner-managed harness with catalog metadata, enablement state, auto-install preferences, managed/system scanner status, and adaptive project profiling.
- Packaged runtime support for the root Hermsec CLI and scanner tools under desktop resources.
- Provider settings for OpenCode Go, OpenAI-compatible endpoints, Anthropic, Gemini, OpenRouter, and local/custom base URLs.
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
- Windows and macOS release packaging is handled by `.github/workflows/desktop-release.yml`.
- Fresh desktop settings default to adaptive scanner auto-install (`scanners.autoInstallMissing: true`), and scan completion chat messages link the generated one-page PDF location when available.
- User-facing reports and dashboard data must display friendly scanner names. Legacy `hermsec-offline` findings are compatibility data only and should render as `HermSec heuristics`.
- Chat scan progress should show the real orchestration state from root scanner events. The CLI streams `HERMSEC_PROGRESS <json>` lines in JSON mode while preserving the final JSON result; desktop consumes those lines live and only uses final report-status reconciliation as a fallback.
- Deep assisted mode remains scanner-confirmed/model-supported only. Model explanations must validate against existing finding ids, scanner ids, files, lines, packages, CVEs/GHSAs/OSVs, and CWEs before reports accept them.
- Vulnerability intelligence is now a real report-generation step. The harness inventories supported dependency manifests/lockfiles, refreshes or reuses OSV/GitHub Advisory/NVD/CISA KEV intelligence according to the online-updates setting, filters out generic ecosystem-only feed items, and writes matched advisory/KEV records into `report-document.json`, Markdown, HTML, dashboard, and one-page outputs.

## Boundaries

- Do not install dependencies inside scanned repositories.
- Do not run package lifecycle scripts inside scanned repositories during scans.
- Keep provider secrets in environment variables or local user config, never committed repo files.
- Keep generated desktop artifacts such as `desktop/out`, `desktop/release`, `desktop/resources/hermsec-cli`, `desktop/resources/runtime-tools`, and local `.hermsec*` state out of git.
