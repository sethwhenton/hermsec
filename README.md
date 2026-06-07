# Hermsec

Hermsec is a local-first security assistant for repositories. It scans project files with a defensive harness, writes local reports, and can optionally use a bring-your-own model provider to explain grounded findings.

## Quick Start

Hermsec now has a Synara-style Electron desktop app for local workspaces, scans, intel, reports, settings, and security chat. The CLI still exists for scriptable scans.

```powershell
pmg npm ci --ignore-scripts
node node_modules\electron\install.js
pmg npm test
pmg npm run start:desktop
hermsec doctor
hermsec scan E:\path\to\repo --out .hermsec\reports --html --md --json
```

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

## Provider Keys

Provider keys are read from environment variables such as `OPENCODE_GO_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, and `OPENROUTER_API_KEY`. Keep real keys out of git.

For OpenCode Go, copy `.env.example` to `.env.local`, set `OPENCODE_GO_API_KEY`, keep `HERMSEC_MODEL=deepseek-v4-flash`, then enable remote model calls from Settings when you want model-backed explanations.

## V2 Synara Fork

`v2/` is a whole-source Synara fork for the next desktop direction. It is rebranded as Hermsec V2, removes Synara's marketing app, uses the selected H/keyhole mark, and adds a first Hermsec bridge for Doctor, Scan, and Intel actions. See `v2/docs/HERMSEC_V2_SCOPE.md`.
