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
hermsec intel update [--workspace <id>] [--source osv,kev,...] [--offline]
hermsec eval run [--suite <path>] [--mode scanner-only|agent-assisted] [--out <dir>]
hermsec eval compare --scanner-only <summary.json> --agent-assisted <summary.json> [--out <file>]
hermsec eval explain-match [--suite <path>] --case <id> --finding <id>
```

Safety defaults:

- The CLI does not install dependencies or run package executors.
- Scan targets are normalized locally unless they look like a URL or SSH Git target.
- Secret-like config keys are rejected; store credentials in environment variables or an OS credential store and save only references.
- Output is redacted before printing.

Until the other workstreams land, command handlers call stable facade modules through optional imports and return actionable `MODULE_UNAVAILABLE` errors instead of crashing.
