# Hermsec V3 Desktop

This is the active Hermsec app: an Electron + React desktop workspace for security chat, scans, Doctor readiness, dashboards, final PDF reports, settings, scanner management, and automations.

Packaged builds include the root Hermsec CLI/report engine and the scanner runtime so installed users can run the core scanner stack without separate setup. Fresh installs also default to adaptive scanner auto-install for supported missing tools, using Hermsec-managed storage rather than the scanned repository.

## Run

```powershell
cd desktop
npm ci
npm run dev
```

From the repository root, the same app can be launched with:

```powershell
npm run desktop:dev
```

## Package Windows

```powershell
npm run desktop:dist:win
```

or:

```powershell
cd desktop
npm run dist:win
```

Generated outputs:

```text
desktop\release\Hermsec Setup 0.1.0.exe
desktop\release\Hermsec 0.1.0.exe
desktop\release\win-unpacked\Hermsec.exe
```

## Package macOS

```bash
npm run desktop:dist:mac
```

This creates a `.dmg` and `.zip` under `desktop/release/`. GitHub release builds are configured in `.github/workflows/desktop-release.yml`: push a `v*` tag, or run the workflow manually with a tag, to build Windows and macOS packages and publish them to the [latest Hermsec release](https://github.com/sethwhenton/hermsec/releases/latest).

macOS CI builds are unsigned until Apple signing certificates are configured. On first launch, users may need to approve Hermsec from System Settings > Privacy & Security.

## Bundled Runtime

The packaging script runs:

- `prepare:cli-bundle` to copy the root Hermsec CLI into `resources/hermsec-cli`
- `prepare:runtime-tools` to prepare bundled scanner tools under `resources/runtime-tools/<platform>-<arch>`
- `electron-builder` to create installer/portable assets

The current packaged bundle includes:

- Hermsec CLI/report engine
- Semgrep
- Gitleaks
- Bandit
- OSV-Scanner
- pip-audit
- SafeDep PMG npm audit

Do not commit generated `.exe`, `.dmg`, `.zip`, `resources/hermsec-cli`, or `resources/runtime-tools` outputs directly.

## Smoke Checks

```powershell
cd desktop
npm run typecheck
npm run build
npm run smoke:doctor
npm run smoke:dashboard
```

The latest verified packaged Doctor smoke reports status `ready`, health score `100`, required `7/7`, scanners `6/6`, internet `5/5`, and providers `1/1`.

## Environment

The desktop app loads `.env.local` from `desktop/.env.local` when present. Provider keys should still be stored in environment variables or OS credential stores, not committed files.

Common values:

- `HERMSEC_MODEL`
- `HERMSEC_MODEL_BASE_URL`
- `HERMSEC_MODEL_PROVIDER`
- `HERMSEC_MODEL_API_KEY` through `HERMSEC_MODEL_API_KEY_ENV`

Provider **Test** validates connectivity from the main process against `{baseUrl}/models`.

## Scanner Management

Settings > Scanners shows supported scanners, enabled state, auto-install preference, install/update/uninstall actions, managed/system path status, and whether a scanner applies to the current project profile.

The main-process scanner manager installs eligible tools into Electron `userData\managed-scanners\<platform>-<arch>` rather than the scanned project. Normal scans stay adaptive: Hermsec profiles the repo, prepares matching scanner tools, then runs only the relevant scanner lanes.

When a scan finishes, chat prefers the generated one-page PDF (`onepager/report.pdf`) as the final artifact. The assistant message shows the PDF path and renders it as a local file link that opens the PDF location in File Explorer. If PDF generation is unavailable, the app links the report folder instead.
