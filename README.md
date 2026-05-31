# Hermsec

Hermsec is a local-first security assistant for repositories. It scans project files with a defensive harness, writes local reports, and can optionally use a bring-your-own model provider to explain grounded findings.

## Quick Start

Hermsec can be installed as an npm CLI. Once installed, type `hermsec` in PowerShell to open the rich terminal chatbot UI with panels, mouse-enabled buttons, paste-friendly input, onboarding, settings, model/provider pickers, sessions, and scan/report views.

```powershell
pmg npm ci --ignore-scripts
pmg npm test
npm pack
npm install -g .\hermsec-0.1.0.tgz --ignore-scripts
hermsec
hermsec doctor
hermsec scan E:\path\to\repo --out .hermsec\reports --html --md --json
```

Inside the TUI:

```text
/help or /commands    Show available commands
/doctor               Check local readiness
/scan <path>          Run the approved scan harness
/intel                Show security-update summaries
/reports              Show local reports
/settings             Edit privacy, report, model, and provider settings
/settings report <x>  Set report location or a custom local report folder
/model                Pick the active model provider
/provider             Configure provider credential environment variables
/provider env <name>  Store an env var name, never a raw key
/history [count]      Show recent messages in the current session
/sessions             List saved sessions for the active workspace
/sessions new         Save the current session and start a fresh one
/exit                 Leave the TUI
```

On first launch, onboarding runs inside the same rich TUI view. You can click through the setup or paste a local path/GitHub URL directly into the bottom input. Run `hermsec onboard` to open that onboarding view again.

For development linking and registry publishing notes, see [docs/npm-install.md](docs/npm-install.md).

Hermsec does not install dependencies inside scanned repositories and does not run package lifecycle scripts during scans.

## Provider Keys

Provider keys are read from environment variables such as `OPENCODE_GO_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, and `OPENROUTER_API_KEY`. Keep real keys out of git.
