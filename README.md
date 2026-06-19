# Hermsec

Hermsec is a local-first security assistant for repositories. It scans project files with a defensive harness, writes local reports, and can optionally use a bring-your-own model provider to explain grounded findings.

## Quick Start

Hermsec now has a complete Electron desktop app for local workspaces, scans, intel, reports, settings, automations, and security chat. The Windows app package bundles the Hermsec CLI plus the scanner runtime, so users do not need to separately install Semgrep, Gitleaks, Bandit, OSV-Scanner, pip-audit, or SafeDep PMG.

### Windows App

```powershell
cd v2\hermsec-v3
npm.cmd run dist:win
```

This creates:

```text
v2\hermsec-v3\release\Hermsec Setup 0.1.0.exe
v2\hermsec-v3\release\Hermsec 0.1.0.exe
```

Use `Hermsec Setup 0.1.0.exe` as the installer and `Hermsec 0.1.0.exe` as the portable app. These files are about 200 MB because they include the scanner toolchain and should be uploaded as GitHub Release assets instead of committed directly to git.

Bundled scanner/runtime contents:

- Hermsec CLI/report engine
- Semgrep
- Gitleaks
- Bandit
- OSV-Scanner
- pip-audit
- SafeDep PMG npm audit

After install, run Doctor from chat to confirm readiness. A verified packaged build reports required `7/7`, scanners `6/6`, internet `5/5`, providers `1/1`, and health score `100`.

Inside the desktop composer:

```text
/help or /commands    Show available commands
/doctor               Check local readiness
/scan <path>          Run the approved scan harness
/intel                Refresh security-update summaries
/reports              Show local reports
/settings             Edit privacy, report, model, and provider settings
```

For development linking and registry publishing notes, see [docs/npm-install.md](docs/npm-install.md).

Hermsec does not install dependencies inside scanned repositories and does not run package lifecycle scripts during scans.

### CLI Development

The CLI still exists for scriptable scans and development checks:

```powershell
pmg npm ci --ignore-scripts
node node_modules\electron\install.js
pmg npm test
node dist\src\bin\hermsec.js doctor --json
node dist\src\bin\hermsec.js scan E:\path\to\repo --out .hermsec\reports --html --md --json
```

## Provider Keys

Provider keys are read from environment variables such as `OPENCODE_GO_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, and `OPENROUTER_API_KEY`. Keep real keys out of git.

For OpenCode Go, copy `.env.example` to `.env.local`, set `OPENCODE_GO_API_KEY`, keep `HERMSEC_MODEL=deepseek-v4-flash`, then enable remote model calls from Settings when you want model-backed explanations.

## V2 Synara Fork

`v2/` is a whole-source Synara fork for the next desktop direction. It is rebranded as Hermsec V2, removes Synara's marketing app, uses the selected H/keyhole mark, and adds a first Hermsec bridge for Doctor, Scan, and Intel actions. See `v2/docs/HERMSEC_V2_SCOPE.md`.
