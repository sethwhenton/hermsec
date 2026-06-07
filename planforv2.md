# Hermsec V2 MVP Wiring Plan

## Product Goal

Hermsec V2 is an Electron security IDE for vibe-coded projects. The primary experience is a chat interface: the user opens a local folder, asks Hermsec what it can do, chooses actions like scanning a repo or setting an automation, and receives scanner-backed reports in chat plus polished local HTML artifacts.

## Implemented MVP Scope

### Desktop Bridge

- `desktopBridge.hermsec.getState()`
  - Loads Hermsec config, report list, schedule list, report directory, model override, and v2 Hermsec home metadata.
  - Uses `.hermsec-v2/hermsec-home` inside `v2/` as the default `HERMSEC_HOME`.
- `desktopBridge.hermsec.chat(input)`
  - Routes safe assistant turns to deterministic Hermsec actions.
  - "What can you do?", help, commands, features, and capability-style prompts return structured choices:
    - `Scan repo`
    - `Set an automation`
- `desktopBridge.hermsec.scan(input)`
  - Calls `node dist/src/bin/hermsec.js scan <target> --json --md --html`.
  - Passes the configured report directory through `--out`.
  - Uses model explanations only when the user disables local-only privacy and scan mode is not offline.
- `desktopBridge.hermsec.saveSettings(input)`
  - Persists supported core config values:
    - provider
    - provider credential env var name
    - custom report directory
    - privacy mode
  - Applies the selected model to `HERMSEC_MODEL` for the current app session.
- `desktopBridge.hermsec.listReports()` and `openReport(input)`
  - Reads Hermsec's report index and opens/loads saved HTML report content for preview.
- `desktopBridge.hermsec.listSchedules()`, `addSchedule()`, `updateSchedule()`, `setScheduleEnabled()`, `runSchedule()`, and `removeSchedule()`
  - Back the Automations page with persisted Hermsec scheduler state.
  - Manual Run Now uses `schedule run --force`.
  - Normal scheduled runs use git-aware evaluation.

### Chat Experience

- Empty state keeps the Synara-style Hermsec interface.
- Assistant messages can render selectable choice cards.
- Choosing `Scan repo` runs the active project through the live scan harness.
- Choosing `Set an automation` creates a daily automation for the active project using the configured default time.
- Chat replies are constrained to safe Hermsec actions: scan, automation, report list, doctor, and project/security explanation prompts.

### Settings

- Provider defaults to `opencode-go`.
- Model defaults to `deepseek-v4-flash`.
- Credential setting stores only an environment variable name, defaulting to `OPENCODE_GO_API_KEY`.
- Scan modes are `offline`, `online`, and `auto`.
- Report directory is configurable and respected by manual scans and scheduled scans.

### Automations

- Automations page can:
  - create an automation
  - enable/disable
  - edit daily time/mode from current defaults
  - delete
  - Run Now
- In-app runner checks enabled automation `nextRunAt` timestamps once per minute.
- Scheduled runs call the non-forced scheduler path, which evaluates due state and git changes before scanning.
- Successful scheduled runs update the git baseline so unchanged repos can be skipped later.

### Reports

- HTML report rendering has been redesigned for clearer executive summary, finding cards, metadata, evidence, and priority sections.
- Report preview panel loads saved HTML from the bridge.
- External/open control reveals the report file in the OS shell.

### Test Projects

Two intentionally vulnerable labs were added under:

```text
Test projects/hermsec-node-express-vuln-lab
Test projects/hermsec-python-flask-vuln-lab
```

Each includes:

- source code with fake-only secrets and vulnerable patterns
- README
- expected-findings metadata

The scan unit test now scans both labs and calculates recall against the expected finding metadata.

## Root CLI Changes

- `schedule update <id> [--target <path>] [--daily <HH:mm>] [--mode auto|offline|online] [--enabled true|false] [--json]`
- `schedule enable <id> [--json]`
- `schedule disable <id> [--json]`
- `schedule run <id> --force [--json]`
- Scheduler run behavior:
  - forced runs execute immediately
  - non-forced runs evaluate due state and git-change state
  - unchanged repos can be skipped
  - reports use the configured custom report directory
  - successful runs save a git baseline
- The model harness now honors `HERMSEC_MODEL`.

## Testing Plan

Run from the root:

```powershell
$env:PMG_DISABLE_TELEMETRY='true'
pmg npm test
```

Run from v2:

```powershell
bun --no-install run test
```

Additional live checks:

```powershell
node dist/src/bin/hermsec.js doctor --json
node dist/src/bin/hermsec.js scan "Test projects/hermsec-node-express-vuln-lab" --mode offline --json --md --html --no-model
node dist/src/bin/hermsec.js scan "Test projects/hermsec-python-flask-vuln-lab" --mode offline --json --md --html --no-model
node dist/src/bin/hermsec.js schedule list --json
```

## Preview Launch

Launch from:

```text
E:\Programming\Security insider II\Hermsec Proj\v2
```

Use:

```powershell
bun --no-install run dev:desktop --home-dir ./.hermsec-v2/electron-dev --port 58090
```

Renderer URL:

```text
http://localhost:8891
```

## Next Iteration

- Add a first-class project picker backed by Hermsec workspace storage.
- Move model/provider persistence from app-session env into a dedicated v2 settings store or root config schema extension.
- Add a report list surface in the UI instead of relying only on Latest Report and automations.
- Add OS-level schedule registration after the in-app runner behavior is stable.
- Add a real agent runtime adapter after the deterministic action router is stable.
