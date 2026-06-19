# Hermsec V3

Standalone Electron app for Hermsec chat, scans, Doctor readiness, dashboards, reports, settings, and automations. Packaged builds include the Hermsec CLI/report engine and the scanner runtime so installed users get the full scanner stack without separate setup.

## Run

```powershell
cd hermsec-v3
bun install
bun run dev
```

## Package Windows App

```powershell
cd v2\hermsec-v3
npm.cmd run dist:win
```

The packaging script runs:

- `prepare:cli-bundle` to copy the root Hermsec CLI into `resources/hermsec-cli`
- `prepare:runtime-tools` to prepare bundled scanner tools under `resources/runtime-tools/<platform>-<arch>`
- `electron-builder` to create installer and portable `.exe` files

Generated outputs:

```text
release\Hermsec Setup 0.1.0.exe
release\Hermsec 0.1.0.exe
release\win-unpacked\Hermsec.exe
```

The installer and portable app include:

- Hermsec CLI/report engine
- Semgrep
- Gitleaks
- Bandit
- OSV-Scanner
- pip-audit
- SafeDep PMG npm audit

Do not commit the generated `.exe` files directly; upload them as GitHub Release assets.

## Package Smoke Checks

```powershell
$env:HERMSEC_HOME = Join-Path $env:APPDATA 'hermsec-v3'
Start-Process -FilePath '.\release\win-unpacked\Hermsec.exe' -ArgumentList '--smoke-doctor' -Wait -PassThru

$env:HERMSEC_SMOKE_DASHBOARD='true'
$env:HERMSEC_SMOKE_USE_MODEL='false'
$env:HERMSEC_SMOKE_PROJECT='C:\path\to\repo'
Start-Process -FilePath '.\release\win-unpacked\Hermsec.exe' -Wait -PassThru
```

The latest verified packaged Doctor smoke reports status `ready`, health score `100`, required `7/7`, scanners `6/6`, internet `5/5`, and providers `1/1`.

If you see a blank window or stale `getElectronPath` errors, use a clean dev start (kills old Electron, rebuilds `out/`):

```powershell
bun run dev:clean
```

If Electron fails to install (missing `path.txt` or `.pak` files), close all Electron windows first, then:

```powershell
Get-Process electron -ErrorAction SilentlyContinue | Stop-Process -Force
Remove-Item -Recurse -Force node_modules\electron
bun install
bun run setup:electron
bun run dev
```

## Environment

Loads `.env.local` from the repo root (`v2/.env.local`):

- `HERMSEC_MODEL`
- `HERMSEC_MODEL_BASE_URL`
- `HERMSEC_MODEL_PROVIDER`
- `HERMSEC_MODEL_API_KEY` (optional, via `HERMSEC_MODEL_API_KEY_ENV`)

Provider **Test** validates connectivity from the main process against `{baseUrl}/models`.

## Agent plug-in surfaces

- `ChatItem` union in `src/renderer/src/types/chat.ts`
- `ContextBar` context chips in `uiStore.contextChips`
- `AgentQuestions` plan-mode Q&A card in the timeline
- `Spiral5x5` thinking loader when `uiStore.isAgentThinking` is true
- `window.hermsec` IPC API in `src/preload/index.ts`

## Settings persistence

`userData/settings.json` via main process store (`src/main/store.ts`).
