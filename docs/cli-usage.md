# Hermsec CLI Usage

Hermsec's CLI is a defensive command router over the local-first scan engine, workspace/config storage, scheduler, intelligence feed, and evaluation modules.

```bash
hermsec
hermsec chat
hermsec doctor [--json]
hermsec onboard
hermsec scan <target> [--mode auto|offline|online] [--out <dir>] [--json] [--md] [--html] [--no-model]
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
hermsec scan <target> --mode online
```

Supported starter providers are `openrouter`, `openai`, `claude`, `gemini`, `opencode-go`, `ollama`, `openai-compatible`, and `none`. Hermsec stores provider IDs and environment-variable names only; it rejects raw-looking key values.

Safety defaults:

- The CLI does not install dependencies or run package executors.
- Scan targets are normalized locally unless they look like a URL or SSH Git target.
- Secret-like config values are rejected; store credentials in environment variables or an OS credential store and save only references.
- Online scans use installed scanner CLIs when available: Semgrep, Gitleaks, Bandit, OSV-Scanner, pip-audit, and SafeDep PMG-wrapped npm audit. If a scanner is missing, Hermsec records a skipped status and keeps local heuristic coverage.
- Output is redacted before printing.

Production verification:

```powershell
.\scripts\verify-production.ps1
```

If PMG is still awaiting machine-level approval, use `.\scripts\verify-production.ps1 -AllowMissingPmg` only to verify every other production gate. PMG setup details live in `docs/pmg-setup.md`.

Command handlers call stable facade modules through optional imports and return actionable `MODULE_UNAVAILABLE` errors instead of crashing.
