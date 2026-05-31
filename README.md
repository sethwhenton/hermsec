# Hermsec

Hermsec is a local-first security assistant for repositories. It scans project files with a defensive harness, writes local reports, and can optionally use a bring-your-own model provider to explain grounded findings.

## Quick Start

```powershell
npm ci --ignore-scripts
npm run build
npm test
npm link
hermsec doctor
hermsec scan E:\path\to\repo --out .hermsec\reports --html --md --json
hermsec chat
```

Hermsec does not install dependencies inside scanned repositories and does not run package lifecycle scripts during scans.

## Provider Keys

Provider keys are read from environment variables such as `OPENCODE_GO_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, and `OPENROUTER_API_KEY`. Keep real keys out of git.
