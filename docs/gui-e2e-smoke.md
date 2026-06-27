# Hermsec GUI End-to-End Smoke Checks

These checks validate the desktop GUI and the Electron scan path in a repeatable way.

## Prerequisites

- Run from the repository root.
- Build the root CLI before scan-mode smoke checks:

```powershell
npm run build:core
```

- For real model-backed mode checks, provide the OpenCode Go key through `.env.local`, desktop settings, or the shell:

```powershell
$env:OPENCODE_GO_API_KEY="..."
```

## Commands

```powershell
npm --prefix desktop run build
npm --prefix desktop run smoke:ui
npm --prefix desktop run smoke:doctor
npm --prefix desktop run smoke:dashboard
npm --prefix desktop run smoke:scan-modes
```

## What They Prove

- `smoke:ui` launches Electron, renders the GUI, opens Settings, and verifies the four scan modes plus Low/High MoA panels are visible.
- `smoke:doctor` verifies required runtime, scanner, provider, and internet readiness.
- `smoke:dashboard` runs a desktop scan and verifies dashboard HTML plus the one-page PDF are generated.
- `smoke:scan-modes` runs Deep assisted, Single Agent, MoA, and Scanner + MoA through the Electron desktop scan path, verifies progress events, report folders, dashboard artifacts, one-page PDFs, and mode metadata.

## Useful Overrides

```powershell
$env:HERMSEC_SMOKE_PROJECT="C:\path\to\fixture"
$env:HERMSEC_SMOKE_SCAN_MODES="deep-assisted,scanner-moa-assisted"
$env:HERMSEC_SMOKE_SCAN_MODES_OUT="C:\path\to\reports"
$env:HERMSEC_SMOKE_SCAN_MODES_USE_MODEL="false"
```

Use `HERMSEC_SMOKE_SCAN_MODES_USE_MODEL=false` only for offline harness checks. Product validation should use the real configured provider.
