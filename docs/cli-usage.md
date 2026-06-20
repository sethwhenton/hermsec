# Hermsec CLI Usage

Hermsec's root CLI is the scriptable command router for the V3 scanner engine. It supports local Doctor checks, scans, reports, schedules, vulnerability intelligence updates, and benchmark evaluation.

Interactive chat, scanner install controls, automation UI, dashboards, and Doctor cards live in the V3 desktop app under `desktop/`.

```bash
hermsec --help
hermsec agent ask <message> [--target <path>] [--mode auto|offline|online] [--json] [--no-model]
hermsec agent providers [--json]
hermsec doctor [--json]
hermsec scan <target> [--mode auto|offline|online] [--assist-mode scanner-model-summary|deep-assisted] [--out <dir>] [--json] [--md] [--html] [--no-model]
hermsec config get [key]
hermsec config set <key> <value>
hermsec config path
hermsec workspace list
hermsec workspace add [path] [--name <name>]
hermsec workspace use <id|name|path>
hermsec report list [--workspace <id>]
hermsec report open [latest|report-id|path]
hermsec report path [report-id] [--workspace <id>]
hermsec sync
hermsec schedule add <target> --daily <HH:mm> [--mode auto|offline|online]
hermsec schedule list
hermsec schedule run <schedule-id>
hermsec schedule remove <schedule-id>
hermsec watch <target> [--after-idle <duration>] [--mode auto|offline|online]
hermsec intel update [--workspace <id>] [--source cisa-kev|osv|github-advisory|nvd] [--offline]
hermsec eval run [--suite <path>] [--mode scanner-only|agent-assisted] [--out <dir>]
hermsec eval compare --scanner-only <summary.json> --agent-assisted <summary.json> [--out <file>]
hermsec eval explain-match [--suite <path>] --case <id> --finding <id>
```

Model provider setup:

```bash
set GEMINI_API_KEY=...
hermsec config set privacyMode cloud-assisted
hermsec config set preferredModelProvider gemini
hermsec config set providerCredentialEnv GEMINI_API_KEY
hermsec scan <target> --mode online --assist-mode scanner-model-summary
```

Supported starter providers are `openrouter`, `openai`, `claude`, `gemini`, `opencode-go`, `ollama`, `openai-compatible`, and `none`. Hermsec stores provider IDs and environment-variable names only; it rejects raw-looking key values.

Safety defaults:

- The CLI does not install dependencies or run package executors inside scanned repositories.
- Scan targets are normalized locally unless they look like a URL or SSH Git target.
- Secret-like config values are rejected; store credentials in environment variables or an OS credential store and save only references.
- Online scans use installed scanner CLIs when available. If a scanner is missing, Hermsec records a skipped status and keeps local heuristic coverage.
- Output is redacted before printing.

The full desktop flow can be checked with:

```powershell
npm run desktop:typecheck
npm run desktop:build
npm run desktop:smoke:doctor
npm run desktop:smoke:dashboard
```
