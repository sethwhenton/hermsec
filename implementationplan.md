# Hermsec Implementation Plan

Date: 2026-05-31

## Mission

Hermsec is a local-first security agent for vibe coders.

It provides a chatbot-style terminal experience for developers who use AI coding agents and want security review without leaving their workflow. Hermsec watches selected workspaces, understands git changes, runs controlled scanner scripts, saves local reports, and uses a restricted agent only for explanation, prioritization, and guided feedback.

Hermsec is not a general autonomous coding agent. It is a restricted security review agent.

## Core Product Principles

1. Scanners and deterministic scripts produce evidence.
2. The agent explains evidence and guides the user.
3. The agent never invents CVEs, GHSA IDs, OSV IDs, package versions, file paths, line numbers, or scan results.
4. The agent cannot edit source code in the MVP.
5. The agent cannot run arbitrary shell commands.
6. The agent cannot install dependencies or execute lifecycle scripts by default.
7. Reports are local-only for the MVP.
8. The report destination is user-configurable.
9. Git-aware scheduled scans only run when changes are detected.
10. Security news comes from deterministic APIs/RSS feeds first; the agent summarizes normalized trusted data.

## Secret Handling Notice

Provider API keys must never be written into this repository, examples, reports, logs, prompt traces, session files, scan artifacts, or generated documentation.

OpenCode Go should be configured through an environment variable or OS credential store reference:

```text
OPENCODE_GO_API_KEY
```

The OpenCode Go base URL can be documented because it is not secret:

```text
https://opencode.ai/zen/go/v1
```

Initial OpenCode Go models:

```text
kimi-k2.6
glm-5.1
deepseek-v4-pro
deepseek-v4-flash
```

## Implementation Agent Decomposition

The project should be split into specialized implementation agents/workstreams. These can run in parallel as long as file ownership is respected.

| Agent | Workstream | Primary Ownership | Status |
| --- | --- | --- | --- |
| Agent 1 | Product UX and Chat TUI | `src/tui/**`, chat flows, onboarding UX | Planned by sub-agent |
| Agent 2 | Workspaces, Sessions, Config | `src/storage/**`, `src/workspace/**`, config schemas | Planned by sub-agent |
| Agent 3 | CLI, Installation, Packaging | `src/cli/**`, `package.json`, install docs | Planned by sub-agent |
| Agent 4 | Scanner Harness and Tool Execution | `src/core/**`, `src/scanners/**`, process runner | Planned by sub-agent |
| Agent 5 | Restricted Agent Runtime and Providers | `src/agent/**`, `src/model/**`, prompts and skills | Planned by sub-agent |
| Agent 6 | Scheduler, Git Change Detection, Watch Mode | `src/scheduler/**`, `src/core/repository/**`, run logs | Planned by sub-agent |
| Agent 7 | Reports and Local Artifacts | `src/reports/**`, report schemas/templates | Wave 2 |
| Agent 8 | Security Intelligence Feed | `src/intel/**`, feed fetchers/cache/matching | Wave 2 |
| Agent 9 | Testing, QA, Security Validation | `tests/**`, fixtures, CI checks | Wave 2 |
| Agent 10 | VPS, GitHub, Future Remote Mode | `docs/remote-mode.md`, future modules | Wave 2 |

Recommended simultaneous work limit: 5 to 6 active agents. More than that creates coordination noise and merge conflicts.

## Architecture Overview

```text
User
  |
  v
Hermsec Chat TUI
  |
  v
Restricted Agent Runtime
  |
  +-- Intent router
  +-- Tool permission gate
  +-- Provider router
  +-- Redaction layer
  |
  v
Hermsec Core Harness
  |
  +-- Workspace/session manager
  +-- Git change detector
  +-- Repository inventory
  +-- Scanner planner
  +-- Safe process runner
  +-- Finding normalizer
  +-- Security intelligence cache
  +-- Report renderer
  +-- Local scheduler
```

## Repository Structure

Target structure:

```text
src/
  bin/
    hermsec.ts
  cli/
    program.ts
    commands/
      chat.ts
      config.ts
      doctor.ts
      intel.ts
      onboard.ts
      report.ts
      scan.ts
      schedule.ts
      sync.ts
      watch.ts
      workspace.ts
  tui/
    App.tsx
    screens/
      HomeScreen.tsx
      WorkspaceScreen.tsx
      OnboardingScreen.tsx
      ScanProgressScreen.tsx
      FindingDetailScreen.tsx
      ReportsCenterScreen.tsx
      IntelFeedScreen.tsx
      AutomationScreen.tsx
      SettingsScreen.tsx
    components/
      ChatTranscript.tsx
      ChatComposer.tsx
      CommandPalette.tsx
      StatusRail.tsx
      WorkspaceCard.tsx
      ScannerStatusPanel.tsx
      ReportStatusPanel.tsx
      ScheduleList.tsx
      ErrorNotice.tsx
  agent/
    runtime.ts
    intentRouter.ts
    toolRegistry.ts
    toolDispatcher.ts
    permissions.ts
    systemPrompt.ts
    skillRules.ts
    redaction.ts
    structuredOutput.ts
    costTracker.ts
    tools/
      scanTools.ts
      workspaceTools.ts
      reportTools.ts
      intelTools.ts
      scheduleTools.ts
      providerTools.ts
  model/
    provider.ts
    providerRouter.ts
    openrouter.ts
    openai.ts
    claude.ts
    gemini.ts
    ollama.ts
    opencodeGo.ts
    noModel.ts
    credentials.ts
    pricing.ts
  storage/
    platformPaths.ts
    appData.ts
    jsonStore.ts
    fileLocks.ts
    migrations.ts
    userConfig.ts
    onboardingStore.ts
    workspaceStore.ts
    sessionStore.ts
    projectConfig.ts
    reportStore.ts
    runStore.ts
    queueStore.ts
    secretsPolicy.ts
  schemas/
    configSchemas.ts
    workspaceSchemas.ts
    sessionSchemas.ts
    projectConfigSchemas.ts
    migrationSchemas.ts
  core/
    repository/
      parseTarget.ts
      prepareWorkspace.ts
      gitAccess.ts
      gitChangeDetector.ts
      baselineStore.ts
      changeClassifier.ts
    discovery/
      discoverRepository.ts
    scanner-plan/
      buildScannerPlan.ts
      changePolicy.ts
      scanScope.ts
    process/
      safeExec.ts
  scanners/
    types.ts
    gitleaks.ts
    semgrep.ts
    bandit.ts
    npmAudit.ts
    osvScanner.ts
    pipAudit.ts
  normalize/
    schema.ts
    severity.ts
    confidence.ts
    dedupe.ts
  reports/
    schema.ts
    reportStore.ts
    htmlRenderer.ts
    markdownRenderer.ts
    jsonRenderer.ts
    delta.ts
    templates/
      report.html
  scheduler/
    schedules.ts
    runner.ts
    watch.ts
    queue.ts
    runLog.ts
    locks.ts
  intel/
    schema.ts
    sourceRegistry.ts
    cache.ts
    matcher.ts
    summarizer.ts
    sources/
      osv.ts
      githubAdvisory.ts
      nvd.ts
      cisaKev.ts
      epss.ts
      depsDev.ts
      endoflife.ts
      rss.ts
  doctor/
    checks.ts
    scannerChecks.ts
    providerChecks.ts
    systemChecks.ts
  util/
    paths.ts
    redact.ts
tests/
  unit/
  integration/
  e2e/
  fixtures/
    repos/
    scanners/
    intel/
    reports/
```

## Phase 0: Project Safety And Bootstrap

### Goals

- Create a TypeScript CLI package with a chat TUI entry point.
- Preserve strict supply-chain safety.
- Keep all secrets outside git.
- Make local development reproducible.

### Root Files

```text
package.json
package-lock.json
.npmrc
tsconfig.json
eslint.config.js
vitest.config.ts
README.md
implementationplan.md
.env.example
```

### Package Manager Rules

Contributor setup must start read-only by inspecting manifests, lockfiles, `.npmrc`, scripts, and workflows before any dependency command.

Do not run these without explicit approval:

```text
npm install
pnpm install
yarn install
bun install
npx
pnpm dlx
bunx
package lifecycle scripts
```

After explicit approval, recommended setup:

```bash
npm ci --ignore-scripts
npm run build
npm test
```

If SafeDep PMG is available:

```bash
PMG_DISABLE_TELEMETRY=true pmg npm ci --ignore-scripts
```

### `.npmrc` Hardening

Add root `.npmrc`:

```ini
min-release-age=7
ignore-scripts=true
engine-strict=true
allow-git=none
allow-remote=none
allow-file=none
allow-directory=none
save-exact=true
package-lock=true
```

If an npm version does not support one of these settings, document the behavior rather than weakening the policy silently.

### Package Scripts

Suggested `package.json` scripts:

```json
{
  "scripts": {
    "build": "tsc -p tsconfig.json",
    "dev": "tsx src/bin/hermsec.ts",
    "typecheck": "tsc -p tsconfig.json --noEmit",
    "lint": "eslint .",
    "test": "vitest run",
    "test:watch": "vitest",
    "test:coverage": "vitest run --coverage",
    "pack:dry-run": "npm pack --dry-run",
    "release:dry-run": "npm publish --dry-run"
  }
}
```

Do not add `preinstall`, `install`, `postinstall`, or broad `prepare` scripts.

Published package:

```json
{
  "bin": {
    "hermsec": "./dist/bin/hermsec.js"
  },
  "files": ["dist", "README.md", "LICENSE"]
}
```

### Acceptance Criteria

- A fresh clone can build after approved dependency setup.
- Package scripts contain no lifecycle hooks.
- `.env` and `.env.*` are ignored except `.env.example`.
- Release artifacts exclude secrets, reports, caches, queued scan data, and cloned target repositories.

## Phase 1: CLI Foundation

### MVP Command Surface

```bash
hermsec
hermsec chat
hermsec doctor [--json]
hermsec onboard
hermsec scan <target> [--mode auto|offline|online] [--out <dir>] [--json] [--md] [--html] [--no-model]
hermsec config get|set|path
hermsec workspace list|add|use
hermsec report list|open|path
hermsec sync
```

### Planned Automation Commands

```bash
hermsec schedule add <target> --daily <HH:mm> --mode auto
hermsec schedule list
hermsec schedule run <schedule-id>
hermsec schedule remove <schedule-id>
hermsec watch <target> --after-idle <duration>
hermsec intel update
```

`hermsec` without arguments launches the chat TUI. On first run, it routes into onboarding.

### Command Result Contract

```ts
type CommandResult =
  | { ok: true; message: string; data?: unknown }
  | { ok: false; errorCode: string; message: string; remediation?: string };
```

### Doctor Command

`hermsec doctor` checks:

- Node version and platform support.
- Hermsec config path and report directory writability.
- `.npmrc` hardening.
- PMG availability for contributor dependency work.
- Git and optional GitHub CLI availability.
- Scanner availability and versions: Bandit, Semgrep, Gitleaks, OSV-Scanner, pip-audit, npm.
- Network availability for online mode.
- Model provider connectivity when configured.
- Whether secrets are accidentally present in tracked config paths.
- OS scheduler support for future automation.

Exit codes:

```text
0 all required checks passed
1 required local capability missing
2 config invalid
3 partial readiness, optional tools missing
```

### Tests

- `hermsec --help` renders.
- `hermsec doctor --json` returns schema-valid JSON.
- Unknown command gives actionable error.
- Target path normalization handles Windows paths with spaces.
- Config schema validation rejects invalid values.
- Environment variable redaction never prints secret values.
- `npm pack --dry-run` includes only expected files.

## Phase 2: Chat TUI UX

### UX Contract

Hermsec opens with `hermsec` as a chatbot-first terminal app: mini OpenCode-like, but security-specific and restricted. Scanner scripts produce evidence; the chat agent explains evidence, routes safe intents, manages workspace state, and writes local reports only for MVP.

The TUI must never expose generic coding-agent powers:

- no arbitrary shell
- no file edits
- no package installs
- no secrets collection
- no exploit generation

### Layout

Use a three-zone terminal layout:

```text
Top bar: Hermsec | workspace | mode | last scan | report path

Main left: chat transcript
Main right: live status rail

Bottom: chat composer + slash command hints
```

The chat transcript is the primary UI. Buttons, menus, and shortcuts assist the conversation; they do not replace it.

Primary empty-state prompt:

```text
Hermsec protects local projects by running scanners, explaining evidence, and saving reports on your machine.
What should we secure first?
```

### Onboarding Conversation

First run opens `OnboardingScreen`.

Conversation steps:

1. Welcome: explain Hermsec in one sentence.
2. Workspace: choose current folder, local path, recent workspace, or GitHub URL.
3. Privacy mode: `Local only`, `Balanced`, `Cloud assisted`.
4. Report destination: default app folder, workspace `.hermsec/reports`, custom path, ask each scan.
5. Scanner readiness: call `doctor` through the harness and show missing tools.
6. Model mode: no model, local provider, or configured cloud provider with explicit consent.
7. Scan preference: full scan, changed files, dependency-only, secrets-only.
8. Review: show non-secret config summary.
9. Save workspace profile.
10. Land on workspace home.

Report destination prompt:

```text
Where should Hermsec save reports for this workspace?
> Default app folder
  Inside this workspace
  Custom local folder
  Ask every scan
```

### Home And Workspace Screen

`HomeScreen` shows all workspaces:

- workspace name
- path or URL
- last scan time
- last finding summary
- report destination
- model mode
- scanner readiness state

`WorkspaceScreen` shows the active project:

- chat transcript
- next recommended action
- scanner readiness
- last scan summary
- recent reports
- current git branch and HEAD if available
- local-only report path

Primary actions:

```text
Scan now
Explain findings
Open latest report
Change report folder
Run doctor
Add workspace
```

### Slash Commands And Natural Language Intents

| Command | Intent |
| --- | --- |
| `/scan` | Run approved scan for current workspace |
| `/scan changed` | Scan changed files/dependency files only |
| `/doctor` | Check scanner/tool readiness |
| `/findings` | Show latest findings list |
| `/explain HERM-001` | Explain one finding from evidence |
| `/reports` | Show saved local reports |
| `/workspace` | Switch or add workspace |
| `/report-path` | Change local report destination |
| `/privacy` | Change privacy/model mode |
| `/help` | Show commands and safe boundaries |

Natural-language examples:

```text
scan this folder
check changed files
why is this high risk?
save reports to D:\Hermsec Reports
show me the latest report
run without a model
```

Unknown or unsafe requests are refused with a safe alternative.

### Status Rail

Panels:

- Workspace: path, branch, HEAD, dirty state.
- Mode: local-only/balanced/cloud-assisted.
- Scanner readiness: ready, missing, skipped, failed.
- Scan progress: queued, running, skipped, completed.
- Findings summary: critical/high/medium/low/info.
- Reports: latest local output path.
- Model: no model/local/cloud, plus privacy warning if cloud is enabled.

Scanner progress states:

```text
pending | running | skipped | failed | complete
```

### Error UX

All errors include:

```text
What happened
What Hermsec did instead
What the user can do next
```

Examples:

- Missing scanner: continue scan, mark scanner skipped, show install guidance.
- Workspace missing: disable scan action, ask user to locate workspace.
- Report destination unavailable: fall back to app data report folder and show path.
- Offline mode: run local scanners only; mark online enrichment skipped.
- Model unavailable: generate scanner-only report.
- Unsafe request: explain Hermsec cannot edit code or run arbitrary commands.

### Accessibility

- Full keyboard operation.
- Visible focus indicator for lists and buttons.
- No color-only severity encoding; include labels like `HIGH`.
- High-contrast theme by default.
- Reduced-motion mode for terminals that render poorly.
- Plain text fallback for narrow terminals.
- Screen-reader-friendly transcript order.
- Commands discoverable through `/help` and `?`.

### Tests

- First run creates workspace profile without secrets.
- Custom report path is persisted.
- Natural language maps to safe commands.
- Unsafe shell/edit/install request is refused.
- Home screen renders with no workspaces.
- Workspace screen renders with prior scan data.
- Narrow terminal uses compact layout.
- Missing scanner shows skipped state.
- Failed scanner does not crash full scan.
- Report path fallback works.
- All main actions are keyboard reachable.
- Cloud model mode requires explicit confirmation.
- Model explanation cannot add CVEs absent from evidence.

### Acceptance Criteria

- `hermsec` opens the chat TUI.
- First-run onboarding can create a workspace and local report destination.
- User can run a scan from chat or `/scan`.
- TUI calls the same scan harness as CLI.
- Scanner status, errors, findings, and report paths are visible.
- Reports remain local-only for MVP.
- Unsafe agent capabilities are absent from the tool registry.
- Demo flow completes end-to-end without editing target source files.

## Phase 3: Workspaces, Sessions, And Config

### Goal

Implement Hermsec's local-first workspace memory: user onboarding persists across runs, workspaces and chat/security sessions behave like OpenCode-style project contexts, reports stay local-only for MVP, and optional project-local `.hermsec` config never stores secrets.

### Storage Rules

- App-level state lives outside scanned repositories by default.
- Project-local `.hermsec` is opt-in and must be confirmed before writing.
- Reports are local-only for MVP.
- Secrets are never written to tracked config, project-local files, reports, sessions, logs, or migrations.
- Cloud/provider credentials are referenced by environment variable name or OS credential-store key only.

### App Data Directories

```text
Windows:
  config/data: %APPDATA%\Hermsec
  cache:       %LOCALAPPDATA%\Hermsec\Cache
  temp:        %TEMP%\Hermsec

macOS:
  config/data: ~/Library/Application Support/Hermsec
  cache:       ~/Library/Caches/Hermsec
  temp:        $TMPDIR/Hermsec

Linux:
  config/data: ${XDG_CONFIG_HOME:-~/.config}/hermsec
  state/data:  ${XDG_STATE_HOME:-~/.local/state}/hermsec
  cache:       ${XDG_CACHE_HOME:-~/.cache}/hermsec
  temp:        ${TMPDIR:-/tmp}/hermsec
```

Default app layout:

```text
Hermsec/
  config.json
  onboarding.json
  workspaces.json
  schedules.json
  sessions/
    <workspace-id>/
      <session-id>.json
  reports/
    <workspace-slug>/
      <scan-id>/
        report.html
        report.md
        summary.json
        findings.json
        evidence.json
  runs/
    <run-id>.json
  queue/
    <queued-task-id>.json
  logs/
  migrations.json
```

### Optional Project-Local `.hermsec`

Optional layout:

```text
<project>/.hermsec/
  project.json
  reports/
  runs/
  queue/
```

Tracked-safe default:

```text
.hermsec/project.json
```

Ignored runtime state:

```text
.hermsec/cache/
.hermsec/queue/
.hermsec/tmp/
.hermsec/secrets/
```

`project.json` may contain scan policy, suppressions, preferred report destination, and project display name. It must not contain API keys, tokens, private model credentials, raw prompts containing code, or scanner raw outputs with secrets.

### Core Schemas

Use Zod schemas and export TypeScript types from them.

```ts
type UserConfig = {
  schemaVersion: 1;
  privacyMode: "local-only" | "balanced" | "cloud-assisted";
  defaultReportLocation: "app-data" | "project-local" | "custom" | "ask";
  customReportDir?: string;
  preferredModelProvider?: "none" | "ollama" | "openrouter" | "openai" | "claude" | "gemini" | "opencode-go" | "openai-compatible";
  providerCredentialRef?: {
    kind: "env" | "os-credential-store" | "session-only";
    name?: string;
  };
  recentWorkspaceIds: string[];
};
```

```ts
type WorkspaceProfile = {
  schemaVersion: 1;
  id: string;
  displayName: string;
  rootPath: string;
  sourceKind: "local" | "github-temp" | "github-local-clone";
  remoteUrl?: string;
  reportDir: string;
  privacyMode: UserConfig["privacyMode"];
  scanMode: "offline" | "online" | "auto";
  projectConfigMode: "none" | "read-only" | "write-project-local";
  lastScanId?: string;
  lastScannedCommit?: string;
  createdAt: string;
  updatedAt: string;
};
```

```ts
type SessionRecord = {
  schemaVersion: 1;
  id: string;
  workspaceId: string;
  title: string;
  createdAt: string;
  updatedAt: string;
  messages: {
    id: string;
    role: "user" | "assistant" | "tool";
    content: string;
    createdAt: string;
    redactionApplied: boolean;
  }[];
  toolCalls: {
    id: string;
    toolName: "scan" | "doctor" | "report" | "workspace" | "intel" | "schedule";
    status: "queued" | "running" | "succeeded" | "failed" | "skipped";
    runId?: string;
  }[];
  discussedScanIds: string[];
  discussedFindingIds: string[];
  compactSummary?: string;
};
```

```ts
type ProjectConfig = {
  schemaVersion: 1;
  displayName?: string;
  scanPolicy?: {
    mode?: "offline" | "online" | "auto";
    include?: string[];
    exclude?: string[];
    failOn?: "critical" | "high" | "none";
  };
  reports?: {
    location?: "project-local" | "app-data" | "custom";
    customDir?: string;
    formats?: ("md" | "json" | "html")[];
  };
  suppressions?: {
    findingIdOrFingerprint: string;
    reason: string;
    expiresAt?: string;
  }[];
};
```

### Onboarding Persistence

Onboarding is resumable:

```text
not-started -> privacy-selected -> workspace-selected -> scanner-checked
-> report-location-selected -> provider-selected -> complete
```

Persist to `onboarding.json` after each step. Once complete, write `config.json`, `workspaces.json`, and the first session record.

### Secrets Policy

`src/storage/secretsPolicy.ts`:

- Reject keys matching secret-like names before JSON writes.
- Redact values matching token/key patterns before sessions, logs, reports, and run records.
- Store only credential references, never credential values.
- Allowed secret locations: environment variables, OS credential store, or session-only memory.
- GitHub access uses existing `gh`, SSH, Git credentials, or environment references. Hermsec does not store GitHub credentials.

### Migrations

Every persisted file gets `schemaVersion`.

Migration behavior:

1. Read file.
2. Validate current version.
3. Backup to `<name>.bak.<timestamp>`.
4. Apply ordered migrations.
5. Validate final schema.
6. If validation fails, keep backup and return recovery guidance.
7. Never migrate unknown secret-looking fields into new files.

### Tests

- Windows/macOS/Linux path resolution.
- Missing app data directory is created.
- Corrupt JSON returns a useful error without data loss.
- Atomic write uses temp file then rename.
- Workspace IDs are stable for the same root path.
- Recent workspaces update without duplicates.
- Sessions persist messages, tool calls, scan IDs, and compaction summary.
- Project-local `.hermsec/project.json` is read only when present.
- Project-local writes require explicit opt-in.
- Secrets are rejected/redacted from config, sessions, reports, runs, and logs.
- Schema migrations backup old files and validate upgraded files.
- Onboarding resumes from the last completed step.
- Custom report directory fallback goes to app data if unavailable.

### Acceptance Criteria

- `hermsec` first run creates app data storage and resumes onboarding if interrupted.
- `hermsec onboard` saves a user profile, first workspace, and first session without touching the project unless approved.
- `hermsec workspace list` shows saved workspaces from app data.
- `hermsec session list <workspace>` shows persisted sessions.
- Reports are saved under the configured local destination.
- `.hermsec/project.json` is optional, schema-validated, and secret-free.
- No persisted JSON contains API keys, tokens, SSH keys, PATs, or raw secret scanner matches.

## Phase 4: Restricted Agent Runtime And Provider Router

### Goal

Implement Hermsec's chat agent as a restricted, read-only, scanner-driven runtime. The model may explain scanner evidence, route user intent, and request approved Hermsec tools, but it must not edit source code, run arbitrary shell commands, install packages, read secrets, or claim vulnerabilities without scanner/advisory evidence.

### Runtime Boundary

`src/agent/runtime.ts` exposes one narrow entry point:

```ts
runAgentTurn(input: AgentTurnInput): Promise<AgentTurnResult>
```

Rules:

- The agent can only call tools registered in `toolRegistry.ts`.
- Tools must be Hermsec-owned functions, not arbitrary shell commands.
- Source repositories are read-only inputs.
- Scanner wrappers and report renderers perform the work.
- The model receives normalized findings, approved snippets, and redacted context only.
- No provider may receive full private repository content by default.

### Intent Routing

```ts
type AgentIntent =
  | "scan_target"
  | "explain_findings"
  | "show_report"
  | "configure_provider"
  | "configure_workspace"
  | "configure_schedule"
  | "update_security_intel"
  | "show_help"
  | "unsafe_or_out_of_scope"
  | "needs_clarification";
```

Routing rules:

- Scan requests route to scanner planning, not model-only analysis.
- Finding questions require an existing scan result or finding ID.
- Provider setup routes to credential handling and provider health checks.
- Requests to edit code, run installs, execute arbitrary commands, exploit systems, or bypass secrets route to `unsafe_or_out_of_scope`.
- Ambiguous workspace or provider requests route to `needs_clarification`.

### Tool Registry

Core tool contract:

```ts
type HermsecTool<I, O> = {
  name: string;
  description: string;
  inputSchema: JsonSchema;
  outputSchema: JsonSchema;
  permission: ToolPermission;
  run(input: I, context: ToolContext): Promise<O>;
};
```

Allowed MVP tools:

```text
workspace.select
workspace.describe
workspace.listFilesSafe
workspace.readSnippetSafe
scan.plan
scan.run
scan.status
scan.getFindings
report.render
report.openLocation
intel.update
intel.matchWorkspace
schedule.create
schedule.list
schedule.disable
provider.list
provider.healthCheck
provider.setPreference
```

Forbidden tools:

```text
shell.run
file.write
file.edit
package.install
dependency.execute
web.fetch.any
repo.modify
git.push
secret.readRaw
subagent.spawn
javascript.eval
```

### Tool Permissions

```ts
type ToolPermission = {
  readWorkspace: boolean;
  readOutsideWorkspace: false;
  writeWorkspace: false;
  writeAppData: boolean;
  network: "none" | "trusted-intel" | "model-provider";
  requiresUserApproval: boolean;
  allowedInOfflineMode: boolean;
};
```

Safety defaults:

- `workspace.readSnippetSafe` may read only selected files inside the active workspace.
- Snippets must be size-limited and redacted before model use.
- `scan.run` may execute only known scanner wrappers.
- Package manager installs and lifecycle scripts are never agent tools.
- `report.render` writes only to the configured report directory or app data directory.
- Project-local `.hermsec` writes require explicit user approval.

### Provider Router

Provider interface:

```ts
type ModelProviderAdapter = {
  id: "openrouter" | "openai" | "claude" | "gemini" | "ollama" | "opencode-go" | "none";
  listModels(): Promise<ModelInfo[]>;
  healthCheck(config: ProviderConfig): Promise<ProviderHealth>;
  complete(request: ModelRequest): Promise<ModelResponse>;
  stream?(request: ModelRequest): AsyncIterable<ModelStreamEvent>;
  estimateCost?(request: ModelRequest): CostEstimate;
};
```

Adapters:

- `openrouter.ts`: OpenRouter API, broad model selection, cloud privacy warning.
- `openai.ts`: OpenAI API-compatible structured output path.
- `claude.ts`: Anthropic Messages API adapter.
- `gemini.ts`: Google Gemini adapter.
- `ollama.ts`: local Ollama adapter, preferred for private code snippets.
- `opencodeGo.ts`: OpenCode Go adapter.
- `noModel.ts`: deterministic fallback that reports scanner evidence without AI explanation.

OpenCode Go adapter:

```ts
const opencodeGoConfig = {
  id: "opencode-go",
  baseUrl: "https://opencode.ai/zen/go/v1",
  credentialEnv: "OPENCODE_GO_API_KEY",
  models: ["kimi-k2.6", "glm-5.1", "deepseek-v4-pro", "deepseek-v4-flash"]
};
```

Routing rules:

- If privacy mode is `local-only`, use Ollama, OpenCode Go when explicitly allowed as remote, or `noModel`.
- If cloud provider is selected, show what data categories will be sent.
- If provider health check fails, fall back to `noModel` and mark explanations skipped.
- Model output never changes raw scanner findings; it only fills explanation fields.

### Credential Handling

Allowed storage modes:

```text
environment variable
OS credential store
session-only memory
```

Rules:

- Never write API keys to reports, logs, scan JSON, Markdown, git-tracked config, or prompts.
- Workspace config stores provider ID and credential reference only.
- Logs may show `OPENAI_API_KEY present`, never the value.
- Redaction runs on all model prompts, reports, errors, and debug traces.
- Missing credentials produce a setup prompt, not a stack trace.

### Prompt And Skill Rules

Hermsec system prompt:

```text
You are Hermsec, a defensive security review agent.
Use only supplied scanner and advisory evidence.
Do not invent CVEs, GHSA IDs, OSV IDs, packages, versions, files, or line numbers.
For code findings, prefer CWE/category language unless scanner evidence includes a CVE.
Do not provide exploit instructions.
Do not ask to install dependencies or run lifecycle scripts.
Ask clarifying questions when workspace, scan ID, finding ID, or provider is ambiguous.
```

Skill routing:

```text
scan request -> scan.plan then scan.run
finding explanation -> scan.getFindings then model explanation
provider setup -> provider.healthCheck then provider.setPreference
security news -> intel.update from trusted feeds only
schedule request -> schedule.create with git-aware scan policy
unsafe request -> refusal plus safe defensive alternative
```

### Redaction

Shared sanitizer:

```ts
redactForModel(input: unknown): RedactionResult
redactForReport(input: unknown): RedactionResult
redactForLog(input: unknown): RedactionResult
```

Redact:

- API keys and bearer tokens
- GitHub tokens
- SSH/private keys
- cloud credentials
- `.env` values
- scanner-detected secrets
- high-entropy strings
- authorization headers
- provider request/response secrets

Reports preserve evidence shape while replacing values with markers like `[REDACTED_SECRET]`.

### Structured Outputs

```ts
type ModelExplanation = {
  title: string;
  impact: string;
  evidenceSummary: string;
  suggestedFix: string;
  confidenceReason: string;
  safeNextSteps: string[];
  cveUsage: "from_evidence" | "not_applicable" | "not_present";
};
```

Validation rules:

- Reject new CVE/GHSA/OSV IDs not present in input evidence.
- Reject new file paths, package names, or line numbers not present in input evidence.
- Clamp unsafe remediation text that suggests exploit steps or arbitrary installs.
- On invalid output, retry once with a stricter correction prompt, then use `noModel`.

### Cost Tracking

```ts
type ModelUsage = {
  provider: string;
  model: string;
  promptTokens?: number;
  completionTokens?: number;
  totalTokens?: number;
  estimatedUsd?: number;
  local: boolean;
};
```

Rules:

- Cost tracking is metadata only; it must not log prompts containing secrets.
- Show estimated cost before large cloud explanations when possible.
- Include provider/model/cost summary in `agent-summary.json`.
- For local providers, mark cost as `0` or `local`.

### Tests

- Intent router blocks edit, shell, install, exploit, and secret-reading requests.
- Tool dispatcher refuses unregistered tools.
- `workspace.readSnippetSafe` cannot read outside workspace.
- Redaction removes keys from prompts, reports, logs, and errors.
- Cloud provider path requires explicit privacy consent for snippets.
- Local-only privacy mode never routes to OpenRouter/OpenAI/Claude/Gemini.
- Provider fallback uses `noModel` when health checks fail.
- Structured output rejects invented CVEs and invented file paths.
- Cost tracker records provider/model/token metadata without storing prompt text.
- Report generation still works when model explanation is skipped.

### Acceptance Criteria

- Hermsec can run a full scan and report with `noModel`.
- The chat agent cannot edit files, run arbitrary shell commands, or install packages.
- All model calls pass through provider router, redaction, and structured-output validation.
- Cloud providers receive only normalized evidence and approved snippets.
- Secrets never appear in logs, reports, model prompts, or saved session files.
- Provider adapters exist for OpenRouter, OpenAI, Claude, Gemini, Ollama, OpenCode Go, and no-model fallback.

## Phase 5: Scanner Harness And Tool Execution

### Goal

Hermsec's scanner harness is evidence-first. Scanners and deterministic scripts produce security evidence; the agent/model only explains normalized evidence and must never run arbitrary shell, install packages, invent CVEs, or request secrets.

### Repository Discovery And Git Access

`parseTarget(input)` returns:

```ts
type ParsedTarget = {
  kind: "local-path" | "github-https" | "github-ssh";
  input: string;
  resolvedPath?: string;
  remoteUrl?: string;
  owner?: string;
  repo?: string;
};
```

Local paths are resolved to absolute paths and must exist. GitHub URLs are parsed without storing credentials. Hermsec should prefer scanning a local clone for private repositories.

`prepareWorkspace(target, options)` returns:

```ts
type PreparedWorkspace = {
  scanRoot: string;
  cleanup: () => Promise<void>;
  targetMeta: Record<string, unknown>;
};
```

GitHub targets are cloned with:

```text
git clone --depth 1 --no-recurse-submodules <url> <tempDir>
```

after an optional `git ls-remote` access check.

If authentication fails, report `authentication_required_or_not_found`; do not ask for tokens. If `gh` is present, `gitAccess.ts` may run `gh auth status` only to explain readiness.

Discovery records Python, JS/TS, package managers, lockfiles, source counts, ignored folders, current branch, HEAD SHA, and dirty state.

Default skips:

```text
.git
node_modules
vendor
venv
.venv
dist
build
coverage
.next
.nuxt
.cache
```

### Scanner Planning

```ts
type ScannerPlanItem = {
  id: "gitleaks" | "semgrep" | "bandit" | "npm-audit" | "osv-scanner" | "pip-audit";
  status: "planned" | "skipped";
  reason?: string;
  inputs: string[];
  requiresNetwork: boolean;
  timeoutMs: number;
};
```

Rules:

- Always consider Gitleaks and Semgrep.
- Add Bandit when Python files exist.
- Add npm audit only when `package-lock.json` or `npm-shrinkwrap.json` exists and online registry queries are allowed.
- Add OSV-Scanner for supported lockfiles.
- Add pip-audit only for locked or fully pinned Python inputs by default.
- Skip resolver-based auditing unless the user explicitly approves it.

### Safe Process Execution Contract

`safeExec(request)` accepts only executable IDs from an allowlist and argument arrays built by scanner wrappers:

```ts
type ToolExecutionRequest = {
  tool: ScannerPlanItem["id"] | "git" | "gh";
  executable: string;
  args: string[];
  cwd: string;
  env?: Record<string, string>;
  timeoutMs: number;
  stdoutPath: string;
  stderrPath: string;
  allowedExitCodes: number[];
  maxOutputBytes: number;
  network: "none" | "advisory-only";
};
```

Rules:

- No shell strings.
- No `cmd`, `powershell`, `bash`, `sh`, `npx`, `pnpm dlx`, `bunx`, install commands, lifecycle scripts, or package fixes.
- Redact environment captures.
- Kill timed-out process trees.
- Treat configured findings exit codes as `ok_with_findings`, not harness failure.

### Scanner Wrapper Contracts

```ts
type ScannerResult = {
  scanner: ScannerPlanItem["id"];
  status: "ok" | "ok_with_findings" | "skipped" | "failed" | "timed_out";
  version?: string;
  findings: Finding[];
  rawOutputPath?: string;
  stderrPath?: string;
  durationMs: number;
  error?: { code: string; message: string; retryable: boolean };
};
```

Default commands:

- Gitleaks working tree: `gitleaks dir <repo> --report-format json --report-path <raw>/gitleaks.json --no-banner`; use `--redact` when available, otherwise redact secret fields before persistence.
- Semgrep: `semgrep scan --config rules/semgrep --json --json-output <raw>/semgrep.json --metrics off <repo>`. Do not use `--config auto` by default because it can contact Semgrep services.
- Bandit: `bandit -r <repo> -f json -o <raw>/bandit.json -x <skipCsv> --exit-zero`.
- npm audit: `npm audit --json --package-lock-only --ignore-scripts=true`, cwd at the package root, only with lockfile and online advisory mode.
- OSV-Scanner: `osv-scanner scan -L <lockfile> --format json --output-file <raw>/osv-<name>.json`.
- pip-audit: `pip-audit -r requirements.txt --format json --output <raw>/pip-audit.json --progress-spinner off --no-deps --disable-pip` when requirements are fully pinned; otherwise skip with `unpinned_requirements_need_approval`.

### Normalized Finding Schema

```ts
type Finding = {
  id: string;
  fingerprint: string;
  sourceTools: string[];
  category: "code" | "dependency" | "secret" | "supply-chain" | "config";
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  confidence: "confirmed" | "high" | "medium" | "low";
  location?: { file: string; startLine?: number; endLine?: number };
  package?: { ecosystem: string; name: string; installedVersion?: string; fixedVersions?: string[] };
  identifiers: { cve: string[]; ghsa: string[]; osv: string[]; cwe: string[] };
  evidence: { message: string; rawSourceIds: string[]; references: string[]; snippet?: string; redacted: boolean };
};
```

Dependency CVEs are allowed only when scanner/advisory evidence contains them. Code findings should use CWE/category language unless a tool provides a real advisory ID.

Dedupe:

- dependencies: package plus advisory ID
- secrets: secret fingerprint
- code: rule ID plus file plus line range

### Raw Evidence Storage

```text
<reportRoot>/<scanId>/
  summary.json
  findings.json
  report.md
  evidence/
    manifest.json
    raw/
      semgrep.json
      bandit.json
      npm-audit.json
      osv-*.json
      pip-audit.json
      gitleaks.json
    stderr/
      <tool>.txt
```

`manifest.json` records command ID, argv hash, tool version, exit code, duration, redaction status, output size, and SHA-256 of stored evidence. Secret-bearing fields must be redacted before writing by default.

### Error Handling

- Missing tool: mark scanner `skipped`, continue, include install guidance.
- Invalid JSON: store raw output, mark `failed`, continue.
- Timeout: kill process, mark `timed_out`, keep partial stderr.
- Network blocked: run offline-safe scanners, skip online advisory tools.
- No lockfile: create informational supply-chain finding, do not generate lockfiles.
- Scanner findings exit codes: parse output and continue.

### Tests

- Windows paths with spaces, missing folder, GitHub HTTPS, SSH URL, malformed URL.
- Python-only, Node-only, mixed repo, generated folders skipped, dirty git state.
- Lockfile-driven npm/OSV plan, no-lockfile warning, pinned vs unpinned Python requirements.
- `safeExec` rejects shell executables, install/executor commands, handles timeout, output cap, missing binary, allowed findings exit code.
- Scanner adapter fixture tests for Gitleaks, Semgrep, Bandit, npm audit, OSV-Scanner, and pip-audit JSON.
- Normalization tests: severity mapping, CVE/GHSA/OSV extraction, redaction, dedupe across npm audit and OSV.
- Golden report tests: stable `summary.json`, `findings.json`, and Markdown output.
- End-to-end temp repo test: no package installs, no source edits, report folder created, skipped tools visible.

### Acceptance Criteria

- `hermsec scan <local-path>` discovers repo metadata without modifying the target.
- GitHub targets clone read-only to temp and record commit SHA.
- No install, package executor, lifecycle script, or arbitrary shell runs during scanning.
- Scanner plan clearly states planned and skipped tools before execution.
- Each scanner failure is isolated and does not crash the full scan.
- Findings are normalized, deduplicated, and backed by raw evidence references.
- Secret values are redacted before report output or model input.
- Model/agent explanations can only reference supplied findings and cannot add new CVEs.

## Phase 6: Local Scheduler, Git Change Detection, And Watch Mode

### Goal

Implement local-first automation so Hermsec can answer requests like:

```text
Every day at 9am, check this repo for git changes and scan only if changed.
```

The first implementation should use an in-app scheduler while Hermsec is running. OS-level scheduling can be added later through a separate `schedule install-service` command.

### State Storage

```text
%APPDATA%\Hermsec\
  schedules.json
  workspaces.json
  baselines\
    <workspace-id>.json
  runs\
    <run-id>\
      run.json
      events.jsonl
  queue\
    <queue-id>.json
```

Project-local `.hermsec` remains optional and must require user approval before writing into the protected repo.

### Schedule Model

```ts
type ScheduleRecord = {
  id: string;
  workspaceId: string;
  targetPath: string;
  enabled: boolean;
  trigger: "daily" | "weekdays" | "cron";
  time?: "09:00";
  cron?: string;
  timezone: string;
  mode: "offline" | "online" | "auto";
  changePolicy: "scan-if-git-changed" | "scan-always";
  scanDepth: "auto" | "changed-files" | "full";
  nextRunAt?: string;
  lastRunAt?: string;
  lastStatus?: "success" | "partial" | "skipped" | "failed" | "blocked";
  disabledReason?: string;
};
```

Do not store credentials, tokens, model keys, or notification secrets in schedule records or logs.

### Scheduler Algorithm

1. Load `schedules.json` and ignore disabled schedules.
2. Compute `nextRunAt` using the schedule timezone.
3. On each scheduler tick, select due schedules.
4. Acquire a workspace lock so two schedules do not scan the same repo at once.
5. Validate that `targetPath` exists.
6. Validate git availability when `changePolicy` requires git.
7. Run `gitChangeDetector`.
8. If unchanged, write a skipped run log and keep the baseline unchanged.
9. If changed, classify changes and build a scan plan.
10. Run the scan harness with the selected scope.
11. Save report artifacts.
12. Update the git baseline only after the required scan steps and local report write succeed.
13. Release the lock and update `lastRunAt`, `lastStatus`, and `nextRunAt`.

Missed-run behavior: if Hermsec was closed at 9am, run once on startup only when the missed run is within a configurable grace window, such as 2 hours. Otherwise skip to the next scheduled time and log the skip.

### Git Baseline Tracking

```ts
type BaselineRecord = {
  workspaceId: string;
  repoRoot: string;
  branch?: string;
  headCommit?: string;
  lastSuccessfulScanId?: string;
  workingTreeFingerprint?: string;
  scannedAt: string;
};
```

Read-only git commands:

```text
git rev-parse --show-toplevel
git rev-parse --git-dir
git rev-parse --abbrev-ref HEAD
git rev-parse --verify HEAD
git status --porcelain=v1 -z --untracked-files=all
git diff --name-status -M -C <baseline> HEAD
git diff --cached --name-status -M -C
git diff --name-status -M -C
git ls-files --others --exclude-standard -z
```

The working tree fingerprint should include `HEAD`, staged changes, unstaged changes, untracked file paths, file sizes, mtimes, and local content hashes for changed text files. Store only hashes and paths, never file contents.

### Change Classification

| Bucket | Examples | Scan Plan |
| --- | --- | --- |
| Dependency | `package.json`, lockfiles, `requirements.txt`, `pyproject.toml`, `poetry.lock`, `go.mod`, `Cargo.lock` | Dependency scanners plus supply-chain checks |
| Security-sensitive | auth, session, token, permission, middleware, config, Docker, CI, IaC, `.env.example` | Static scan plus high-attention review |
| Source | `.ts`, `.js`, `.py`, `.go`, `.rs`, `.java`, `.cs`, routes/controllers/services | Changed-file static scan |
| Docs-only | `.md`, docs folders, images, presentation files | Skip or light metadata-only run |
| Generated/vendor | `node_modules`, `dist`, `build`, `.venv`, coverage | Ignore unless explicitly configured |

If multiple buckets apply, choose the highest required scan depth. Dependency or security-sensitive changes override docs-only skips.

### Watch-After-Idle Mode

```bash
hermsec watch . --after-idle 10m
```

Implementation:

1. Start a filesystem watcher for the workspace.
2. Exclude `.git`, `.hermsec`, report output folders, dependency folders, virtualenvs, build output, and coverage.
3. On every event, update `lastChangeAt` and reset the idle timer.
4. When no events occur for `afterIdleMs`, run git change detection.
5. If unchanged since the last successful scan, log a skip.
6. If changed, classify changes and run the same scan planner used by scheduled mode.
7. If changes happen during a scan, mark `pendingAfterCurrentRun = true` and run one more detection pass after the scan completes.

Git status remains the source of truth; file watcher events only decide when to check.

### Run Logs

```text
%APPDATA%\Hermsec\runs\<run-id>\run.json
%APPDATA%\Hermsec\runs\<run-id>\events.jsonl
```

```ts
type RunLog = {
  runId: string;
  scheduleId?: string;
  workspaceId: string;
  trigger: "schedule" | "watch" | "manual-run";
  startedAt: string;
  endedAt?: string;
  status: "success" | "partial" | "skipped" | "failed" | "blocked";
  skipReason?: string;
  baselineBefore?: object;
  baselineAfter?: object;
  changedFiles: string[];
  classifications: string[];
  scanScope: "none" | "changed-files" | "dependency" | "full";
  scannerStatuses: Record<string, string>;
  reportPaths: string[];
  queuedTasks: string[];
  errors: { code: string; message: string }[];
};
```

Write logs atomically through temp files and rename. Redact secrets from paths, command output, scanner messages, and model/provider errors.

### Offline Behavior

In `offline` mode, run only local checks:

- static scanners
- secret scanning
- manifest parsing
- cached advisory matching
- local report generation
- history comparison

In `auto` mode, if online enrichment fails:

- complete the local scan
- save the report
- queue advisory/model enrichment in `%APPDATA%\Hermsec\queue`
- mark the run as `partial`
- update the git baseline if the local scan completed successfully

Network unavailability must not block local reports.

### Failure Recovery

| Failure | Behavior |
| --- | --- |
| Workspace missing | Mark schedule `blocked`, store `disabledReason`, do not delete it |
| Not a git repo | If fallback full scan is allowed, run full scan; otherwise block with explanation |
| Repo has no commits | Run initial full scan and create baseline after success |
| Baseline commit missing or unreachable | Treat as branch rewrite/rebase and run full scan |
| Scanner missing | Mark scanner unavailable, continue with remaining scanners |
| Report destination unavailable | Fall back to app data report directory |
| Hermsec exits mid-run | On startup, mark stale run `failed`, keep old baseline, retry next due run |
| Lock file stale | Reclaim after timeout if owning process is gone |
| Watcher fails | Fall back to periodic git fingerprint polling |

Baseline updates must never happen after a crash, blocked run, failed report write, or incomplete required scan.

### Tests

- Schedule parsing: daily 09:00, weekday 09:00, custom cron, timezone, DST, missed-run grace.
- Git detector: no repo, no commits, no changes, new commit, staged file, unstaged file, untracked file, rename, delete, branch switch, unreachable baseline.
- Classifier: dependency-only, source-only, docs-only skip, security-sensitive config, mixed changes.
- Scan planner: changed-file scan, dependency scan, full scan fallback, scanner unavailable.
- Watch mode: debounce, coalesced events, ignored folders, change during active scan, watcher fallback.
- Run logs: atomic writes, redaction, skipped run, partial offline run, crash recovery.
- Offline queue: auto mode queues enrichment, offline mode does not call network scanners.
- Integration: temp git repo scheduled scan, skip when unchanged, scan after change, baseline updates only after success.

### Acceptance Criteria

- A user can create a daily 9am schedule for a workspace.
- Scheduled mode skips clean repos and logs `skipped, no git changes`.
- Scheduled mode scans only when git state changed since the last successful baseline.
- Dependency and security-sensitive changes trigger stronger scan plans than docs-only changes.
- Watch mode waits until the repo is idle before scanning and does not duplicate scans during active edits.
- Offline mode still produces local reports and queues online enrichment when appropriate.
- Run logs are durable, redacted, and sufficient to explain every skip, failure, and scan decision.
- Crash recovery never corrupts schedules, logs, or baselines.

## Phase 7: Reports And Local Artifacts

### Scope

Reports are local-only for the MVP. The user chooses the destination during onboarding, through chat, or with CLI config. Hermsec produces HTML, Markdown, and JSON from the same normalized report document. The renderer owns layout, ordering, escaping, styles, links, and print behavior. The agent may only fill narrative fields such as explanations, executive summary, next actions, and delta summary.

### Primary Files

```text
src/reports/
  schema.ts
  reportRenderer.ts
  reportStore.ts
  artifactPaths.ts
  htmlRenderer.ts
  markdownRenderer.ts
  jsonRenderer.ts
  evidenceBundle.ts
  reportIndex.ts
  delta.ts
  openReport.ts
  templates/
    report.html
    report.css
tests/unit/reports/
tests/integration/reports/
tests/fixtures/reports/
```

### Artifact Layout

```text
<reportDir>/<workspace-slug>/<scan-timestamp>/
  report.html
  report.md
  summary.json
  findings.json
  evidence.json
  run.json
  agent-summary.json
  delta.json
  raw/
    gitleaks.json
    semgrep.json
    bandit.json
    npm-audit.json
    pip-audit.json
    osv-scanner.json
```

### Core Schemas

```ts
type ReportFormat = "html" | "markdown" | "json";

type ReportDocument = {
  schemaVersion: "1.0";
  scanId: string;
  workspaceId: string;
  workspaceName: string;
  generatedAt: string;
  target: ScanTarget;
  run: ScanRunSummary;
  tools: ScannerStatus[];
  summary: ReportSummary;
  findings: Finding[];
  explanations: Record<string, ModelExplanation | undefined>;
  evidence: EvidenceBundle;
  delta?: DeltaReport;
  limitations: string[];
};

type ReportSummary = {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  secrets: number;
  confirmedCves: number;
  knownExploited: number;
  scannerFailures: number;
  generatedWithModel: boolean;
};

type EvidenceBundle = {
  bundleId: string;
  redactionApplied: boolean;
  rawArtifacts: EvidenceArtifact[];
  findingEvidence: Record<string, EvidenceReference[]>;
};

type EvidenceArtifact = {
  scanner: string;
  path: string;
  sha256: string;
  sizeBytes: number;
  status: "stored" | "missing" | "redacted";
};

type ReportIndexEntry = {
  scanId: string;
  workspaceId: string;
  generatedAt: string;
  reportDir: string;
  htmlPath: string;
  markdownPath: string;
  summaryPath: string;
  totals: ReportSummary;
  commitSha?: string;
  previousScanId?: string;
};

type DeltaReport = {
  baseScanId?: string;
  currentScanId: string;
  newFindingIds: string[];
  fixedFindingIds: string[];
  unchangedFindingIds: string[];
  worsenedFindingIds: string[];
  improvedFindingIds: string[];
  summaryText?: string;
};
```

### Rendering Flow

1. `reportStore.ts` resolves the configured report destination.
2. `artifactPaths.ts` creates a safe workspace slug and timestamped artifact directory.
3. `evidenceBundle.ts` stores scanner raw outputs, hashes them, redacts sensitive values, and maps evidence references to finding IDs.
4. `delta.ts` compares current findings against the previous report index entry for the workspace.
5. `reportRenderer.ts` builds one `ReportDocument`.
6. `htmlRenderer.ts`, `markdownRenderer.ts`, and `jsonRenderer.ts` render from that same document.
7. `reportIndex.ts` updates the local index only after all required artifacts are written successfully.
8. `openReport.ts` opens the HTML report or reveals the report directory from CLI/TUI.

### HTML Template

`src/reports/templates/report.html` must be stable and deterministic. It should contain named placeholders only:

```text
{{metadata}}
{{summary}}
{{priorityActions}}
{{findings}}
{{delta}}
{{scannerStatus}}
{{limitations}}
```

Rules:

- Escape all finding text, evidence text, paths, model output, and scanner messages.
- Use local CSS only; no CDN, remote fonts, remote scripts, or external tracking.
- No client-side JavaScript required for MVP.
- Include print CSS for clean paper/PDF export.
- Show scanner-only reports cleanly when no model explanation exists.
- Show whether code snippets were included and whether redaction was applied.
- Never render secrets, provider keys, tokens, or unredacted secret values.

### Markdown Generation

`markdownRenderer.ts` produces:

```text
Hermsec Security Report
  Scan Metadata
  Executive Summary
  Priority Actions
  Delta Since Previous Scan
  Findings
  Scanner Status
  Evidence Bundle
  Limitations
```

Markdown rules:

- Use stable heading IDs where practical.
- Group findings by severity, then confidence, then title.
- Include advisory IDs only when present in scanner/advisory evidence.
- Link to local raw artifact filenames, not absolute private paths, unless user config allows absolute paths.
- Include "scanner-only explanation unavailable" when the model was skipped or failed.

### JSON Outputs

- `summary.json`: machine-readable overview for TUI, CLI, future notifications, and Hermes adapter.
- `findings.json`: normalized findings only.
- `evidence.json`: redacted evidence bundle metadata and artifact hashes.
- `run.json`: scanner execution status, durations, exit codes, mode, report paths, and fallback status.
- `agent-summary.json`: narrative fields generated by model or no-model fallback.
- `delta.json`: finding comparison against previous scan.

### Report Index

Global index:

```text
%APPDATA%\Hermsec\reports-index.json
```

Responsibilities:

- List reports by workspace, date, severity, and scan ID.
- Support `hermsec report list`, `hermsec report open <scan-id>`, and TUI Report Center.
- Keep entries even when the original configured report directory later becomes unavailable, but mark missing paths clearly.
- Update atomically with a temp file plus rename.

### Local Storage Fallback

If the configured destination is missing, unwritable, or unavailable:

1. Do not fail the scan.
2. Fall back to:

```text
%APPDATA%\Hermsec\reports\<workspace-slug>\<timestamp>\
```

3. Record fallback details in `run.json`.
4. Show the actual saved path in CLI/TUI.
5. Preserve the user's configured destination without overwriting it.

### Print And Export UX

CLI:

```text
hermsec report list
hermsec report open <scan-id>
hermsec report reveal <scan-id>
hermsec report export <scan-id> --format html|markdown|json
```

TUI Report Center:

- Latest report
- Previous reports
- Open HTML
- Reveal folder
- Copy Markdown path
- Export JSON bundle
- Print instructions using browser print from `report.html`

### Tests

- `schema.ts` validates complete and minimal scanner-only report documents.
- `htmlRenderer.ts` escapes unsafe HTML in finding titles, evidence, paths, and model text.
- `markdownRenderer.ts` renders all required sections with no model explanation.
- `jsonRenderer.ts` emits valid `summary.json`, `findings.json`, `evidence.json`, and `run.json`.
- `delta.ts` classifies new, fixed, unchanged, improved, and worsened findings.
- `artifactPaths.ts` normalizes workspace names and prevents path traversal.
- `evidenceBundle.ts` hashes raw artifacts and redacts token-like strings.
- Full report generation from scanner fixture outputs.
- Missing configured report directory falls back to app data.
- Report index updates after successful render.
- Failed render does not leave a partial index entry.
- Previous scan comparison creates `delta.json`.
- Stable HTML and Markdown snapshots for scanner-only, model-enabled, and scanner-failure reports.

### Acceptance Criteria

- Each scan writes HTML, Markdown, and JSON artifacts locally.
- Reports use one shared `ReportDocument` schema.
- HTML uses the stable template; the agent never controls layout.
- Reports remain useful without model output.
- Evidence is redacted before storage and rendering.
- Report destination is user-configured and fallback-safe.
- Report index supports history, open, and delta comparison.
- Delta reports identify new and fixed findings.
- Print/export flow works from the generated HTML report.

## Phase 8: Security Intelligence And Vibe Coder Feed

### Goal

Build `src/intel/**` as a deterministic security-intelligence layer. Fetchers pull only from trusted APIs/RSS feeds, normalize raw source records, dedupe overlapping advisories, match them to workspace inventory, cache them for offline use, and let the agent summarize only normalized trusted data.

The agent must never browse randomly, invent CVEs, or treat news as evidence unless it is linked to a normalized source item.

### File Ownership

```text
src/intel/
  schema.ts
  sourceRegistry.ts
  fetchers.ts
  cache.ts
  dedupe.ts
  matcher.ts
  feed.ts
  summarizer.ts
  updater.ts
  sources/
    osv.ts
    githubAdvisory.ts
    nvd.ts
    cisaKev.ts
    epss.ts
    npmAudit.ts
    depsDev.ts
    openssfScorecard.ts
    endoflife.ts
    rss.ts
    socket.ts
    phylum.ts
tests/unit/intel/
tests/integration/intel/
tests/fixtures/intel/
```

### Source Priorities

| Priority | Source | MVP Use | Cadence | Notes |
| --- | --- | --- | --- | --- |
| P0 | CISA KEV | Known-exploited CVE flag and urgency boost | 1h when online | Fetch JSON, match by CVE. |
| P0 | OSV.dev | Package/version vulnerability matching | On scan + 6h background | Prefer `querybatch` for inventory packages. |
| P0 | GitHub Global Advisories | GHSA/CVE/package advisory enrichment | On scan + 6h background | REST endpoint works unauthenticated for public advisories. |
| P1 | FIRST EPSS | Exploitation probability/percentile | Daily | Batch CVEs with comma-separated `cve`. |
| P1 | NVD CVE API | CVSS/CWE/CPE/reference enrichment | 12h, rate-limited | Use only for CVE metadata, not package-version truth. |
| P1 | npm audit | npm lockfile advisory evidence | During scan only | Disclose registry submission; never run `audit fix`. |
| P2 | deps.dev | Package metadata, dependencies, license, project links | 7d | Enrich direct dependencies. |
| P2 | endoflife.date | Runtime/framework EOL risk | 7d | Match Node/Python/Django/etc. from inventory. |
| P2 | OpenSSF Scorecard | Upstream repo health | 7d | Use deps.dev project scorecard first; direct API later. |
| P3 | Vendor/RSS | Stack-specific news | 6h | CISA advisories, OpenSSF blog, GitHub supply-chain tag, Node/Python/vendor feeds. |
| Future | Socket/Phylum | Malicious package and supply-chain signals | disabled | Add only after explicit configuration. |

### API Contracts

```ts
type IntelSource =
  | "osv" | "github-advisory" | "nvd" | "cisa-kev" | "epss"
  | "npm-audit" | "deps-dev" | "openssf-scorecard" | "endoflife"
  | "rss" | "socket" | "phylum" | "vendor";

type IntelFetcher = {
  source: IntelSource;
  priority: "P0" | "P1" | "P2" | "P3";
  onlineRequired: boolean;
  ttlMs: number;
  fetch(input: IntelFetchInput): Promise<IntelFetchResult>;
};

type IntelFetchInput = {
  mode: "online" | "offline" | "auto";
  workspace?: WorkspaceProfile;
  inventory?: WorkspaceInventory;
  since?: string;
  now: string;
};

type IntelFetchResult = {
  source: IntelSource;
  fetchedAt: string;
  status: "fresh" | "cached" | "skipped" | "failed";
  rawSnapshotPath?: string;
  items: SecurityIntelItem[];
  error?: HermsecError;
};
```

External contracts:

- OSV: `POST https://api.osv.dev/v1/querybatch` with package/version queries; use `GET /v1/vulns/{id}` for detail records.
- GitHub Advisories: `GET https://api.github.com/advisories?ecosystem=npm&affects=package@version&modified=>YYYY-MM-DD&per_page=100`; use `GET /advisories/{ghsa_id}` for detail.
- NVD: `GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveIds=CVE-...`; batch CVEs and throttle unauthenticated calls.
- CISA KEV: fetch `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`.
- EPSS: `GET https://api.first.org/data/v1/epss?cve=CVE-1,CVE-2`.
- deps.dev: use `/v3/systems/{SYSTEM}/packages/{name}/versions/{version}` and `:dependencies`.
- endoflife.date: use `/api/v1/products/{product}` with legacy `/api/{product}.json` fallback.
- npm audit: run only through scanner harness as `npm audit --json --package-lock-only`; never use `npm audit fix`.

### Normalized Schemas

```ts
type SecurityIntelItem = {
  id: string;
  source: IntelSource;
  sourceIds: string[];
  title: string;
  summary?: string;
  url: string;
  publishedAt?: string;
  modifiedAt?: string;
  identifiers: { cve: string[]; ghsa: string[]; osv: string[]; cwe: string[] };
  ecosystems: string[];
  packages: { ecosystem: string; name: string; affectedRange?: string; fixedVersion?: string }[];
  severity: "critical" | "high" | "medium" | "low" | "unknown";
  cvss?: { score: number; vector?: string; version?: "3" | "4" };
  epss?: { score: number; percentile: number; date?: string };
  cisaKev?: { knownExploited: true; addedAt?: string; dueDate?: string; ransomwareUse?: boolean };
  tags: string[];
  provenance: { fetchedAt: string; rawSnapshotPath?: string; normalizedFrom: IntelSource[] };
};

type WorkspaceInventory = {
  workspaceId: string;
  capturedAt: string;
  ecosystems: string[];
  packages: { ecosystem: string; name: string; version?: string; direct: boolean; files: string[] }[];
  runtimes: { name: string; version?: string; source: string }[];
  frameworks: string[];
  ciTools: string[];
  dockerImages: string[];
  previousFindingIds: string[];
};

type IntelRelevance = {
  itemId: string;
  workspaceId: string;
  score: number;
  reasons: string[];
  matchedPackages: string[];
  matchedRuntime?: string;
  priority: "urgent" | "high" | "normal" | "watch";
};
```

### Cache And Offline Layout

```text
%APPDATA%/Hermsec/intel/
  index.json
  items.jsonl
  relevance/<workspace-id>.json
  sources/<source>/<timestamp>.raw.json
  sources/<source>/state.json
  offline-queue/
```

Rules:

- Store raw source snapshots before normalization.
- Hash raw payloads for reproducibility.
- Preserve `ETag` and `Last-Modified` where available.
- Never store tokens.
- If offline, serve stale cache with `status: cached` and visible cache age.
- Queue failed online enrichment for `hermsec sync`.

### Dedupe Rules

Canonical key order:

1. CVE set
2. GHSA ID
3. OSV ID
4. package ecosystem/name/range
5. source URL hash

Merge records when any strong identifier overlaps. Keep source-specific fields in `provenance.normalizedFrom`.

Prefer package affected ranges from OSV/GHSA/npm audit over NVD CPE text. Prefer KEV as an urgency flag, not as proof that the workspace package is affected. Keep withdrawn advisories but hide them by default unless they were previously matched.

### Workspace Matching

| Signal | Score |
| --- | ---: |
| Exact package ecosystem/name/version affected | +70 |
| Direct dependency | +15 |
| Transitive dependency | +8 |
| Runtime/framework EOL or security release match | +45 |
| Previous finding references same CVE/GHSA/OSV | +25 |
| CISA KEV | +25 |
| EPSS percentile >= 0.95 | +15 |
| Same ecosystem but no exact package | +5 |
| Generic RSS story with no stack match | hide by default |

Feed output must include `whyShown`, such as:

```text
Direct npm dependency lodash@4.17.20 matches GHSA...
```

### CLI And UX

```text
hermsec intel update [--workspace <id>] [--source osv,kev,...] [--offline]
hermsec intel feed [--workspace <id>] [--limit 20] [--urgent]
hermsec sync
```

TUI `IntelFeedScreen` tabs:

- Urgent
- This workspace
- Ecosystem
- General

Each item shows title, source badges, CVE/GHSA/OSV IDs, KEV/EPSS badges, affected package/runtime, cache age, and `Why this matters here`.

The agent summary is optional and must cite item IDs only. If no model is configured, render deterministic summaries from normalized fields.

### Tests

- Source normalizers parse fixtures.
- Dedupe merges OSV/GHSA/NVD/KEV overlap.
- Semver/range matching handles npm and PyPI cases.
- Relevance scoring ranks KEV exact matches first.
- Stale cache status is explicit.
- Mock HTTP fetchers for OSV, GHSA, NVD, KEV, EPSS, deps.dev, endoflife.
- Verify ETag/Last-Modified reuse.
- Verify NVD throttling.
- Offline mode returns cached feed without network.
- Node fixture with vulnerable `package-lock.json` produces OSV/GHSA/npm-audit match.
- Python fixture produces PyPI match.
- Workspace with EOL runtime receives endoflife warning.
- Offline scan queues enrichment; `hermsec sync` enriches queued findings.
- Vibe Coder Feed hides unrelated generic RSS items.
- No source fetcher asks for secrets.
- No raw private code is sent to intel APIs.
- npm audit privacy notice appears before registry submission in privacy-sensitive mode.

### Acceptance Criteria

1. `hermsec intel update` fetches P0/P1 sources online, writes raw snapshots, normalized items, and source state.
2. `hermsec intel feed --workspace <id>` shows only relevant or urgent items with deterministic `whyShown` reasons.
3. OSV, GHSA, NVD, KEV, and EPSS overlap dedupes into one item while preserving provenance.
4. CISA KEV and high EPSS raise priority but do not create false package matches.
5. Offline mode serves cached intel with cache age and never fails a local scan because the network is unavailable.
6. Tests cover fetchers, cache, dedupe, relevance, offline behavior, and source failure handling.
7. The agent summarizes only `SecurityIntelItem[]` plus `IntelRelevance[]`; it cannot add identifiers, packages, affected versions, or source claims not present in normalized data.

## Phase 9: Testing, QA, And Security Validation

### Goal

The test suite must prove that Hermsec is safe, deterministic, privacy-preserving, and useful across CLI, TUI, scanner harness, model providers, scheduler, git-aware workflows, report rendering, and release packaging.

Testing must avoid real secrets, live private repositories, destructive commands, dependency installs, and uncontrolled network calls.

### Test Principles

1. Scanner evidence is the source of truth.
2. Tests must be deterministic and runnable offline by default.
3. No test may require real API keys, real tokens, or private repositories.
4. Fixture secrets must be fake, labeled, and never usable.
5. Provider tests use mocks, not live cloud calls.
6. Network tests are opt-in and skipped in normal CI.
7. Package manager commands must not install dependencies during scan tests.
8. Report snapshots must be stable across machines.
9. Git fixtures must be local repositories created from test data.
10. Security guardrails are release blockers.

### Test Structure

```text
tests/
  unit/
    cli/
    config/
    core/
    scanners/
    normalization/
    providers/
    agent/
    reports/
    scheduler/
    git/
    intel/
    redaction/
  integration/
    scanner-wrappers/
    provider-mocks/
    report-rendering/
    scheduler/
    git-fixtures/
    storage/
  e2e/
    cli-scan/
    tui-flows/
    offline-mode/
    scheduled-scan/
    release-smoke/
  snapshots/
    reports/
    tui/
    terminal/
  fixtures/
    repos/
    scanner-output/
    providers/
    intel/
    reports/
    git/
    configs/
    policies/
```

### Test Matrix

| Area | Test Type | What To Validate | Required Fixtures | Acceptance Criteria |
| --- | --- | --- | --- | --- |
| CLI commands | Unit, E2E | `hermsec`, `doctor`, `scan`, `workspace`, `schedule`, `report`, `config`, `intel` commands | fake app data dir, temp repo | Commands return structured success/error objects and actionable messages |
| TUI onboarding | E2E, snapshot | first-run flow, privacy mode, report destination, scanner readiness | terminal interaction fixture | User can complete onboarding without secrets or network |
| Config storage | Unit, integration | schema validation, migrations, corrupt config handling | config JSON fixtures | Invalid config fails safely with remediation |
| Workspace manager | Unit, integration | path normalization, workspace IDs, report dirs | local temp paths | No path traversal, stable workspace records |
| Safe process runner | Unit, integration | args array execution, timeout, output limit, redaction | fake scanner binaries/scripts | No shell interpolation; blocked inputs are rejected |
| Scanner plan | Unit | language and lockfile detection | fixture repos | Correct scanner plan for Node, Python, mixed, clean, docs-only repos |
| Scanner wrappers | Integration | Bandit, Semgrep, Gitleaks, npm audit, pip-audit, OSV handling | fake scanner executables and raw output fixtures | Missing, failed, timeout, and success states normalize correctly |
| Provider adapters | Unit, integration | OpenRouter, OpenAI-compatible, Ollama, no-model | mock HTTP server responses | Requests are redacted and structured responses validate |
| Agent permissions | Unit, E2E | restricted tools, refusal behavior, CVE guardrails | malicious prompt fixtures | Agent cannot call forbidden tools or invent identifiers |
| Redaction | Unit, property-style | token patterns, URLs, env-like strings, scanner output | fake secret corpus | Secrets are removed from prompts, logs, reports, and errors |
| Privacy modes | E2E | local-only, balanced, cloud-assisted | mocked providers/network | Cloud paths require explicit mode and send minimal evidence |
| Report rendering | Unit, snapshot, integration | HTML, Markdown, JSON, terminal summary | finding and scan report fixtures | HTML escapes unsafe text; JSON validates; Markdown complete |
| Scheduler | Unit, integration | cron parsing, run logs, baseline updates, skip behavior | fake clock, git repos | Baseline updates only after successful scans |
| Intel fetchers | Unit, integration | OSV, GHSA, NVD, CISA KEV, EPSS fixture parsing | cached JSON/RSS fixtures | Offline cache works; source overlap dedupes |
| Safety policy | Unit, E2E | no installs, no lifecycle scripts, no source writes | dangerous repo fixtures | Hermsec reports risk without executing project code |
| Performance | Benchmark, smoke | large repo planning, output size limits, report rendering | generated large fixture repo | Meets runtime and memory budgets |
| Release QA | E2E, manual checklist | install artifact, CLI help, scan demo, report output | clean machine/temp workspace | Release candidate passes all gates |

### Fixture Repositories

```text
tests/fixtures/repos/
  node-clean/
  node-vulnerable-lockfile/
  node-no-lockfile/
  node-package-scripts/
  python-clean/
  python-bandit-examples/
  python-vulnerable-requirements/
  mixed-node-python/
  secret-fixture/
  docs-only-change/
  dependency-change/
  security-sensitive-change/
  huge-generated-folders/
  malformed-files/
  no-git-folder/
  empty-git-repo/
```

Fixture rules:

- Use fake secrets only, such as `HERMSEC_FAKE_TEST_TOKEN_DO_NOT_USE`.
- Do not include real credentials, personal data, private URLs, or live tokens.
- Vulnerable code must be toy code for scanner validation only.
- Do not include exploit instructions.
- Lockfiles should be minimal and stable.
- Package scripts in fixtures must never be executed.

### Scanner Output Fixtures

```text
tests/fixtures/scanner-output/
  bandit/
    empty.json
    sql-injection.json
    subprocess-shell-true.json
    malformed.json
  semgrep/
    empty.json
    command-injection.json
    multi-result.json
    malformed.json
  gitleaks/
    empty.json
    fake-secret.json
    multiple-secrets.json
  npm-audit/
    empty.json
    vulnerable-package.json
    advisory-with-ghsa-cve.json
  pip-audit/
    empty.json
    vulnerable-requirements.json
  osv-scanner/
    empty.json
    npm-and-pypi.json
    aliases-overlap.json
```

Acceptance:

- Every scanner normalizer has success, empty, malformed, and partial-output tests.
- Normalizers never throw raw parser errors to users.
- Normalizers preserve raw source IDs and references.
- CVE, GHSA, OSV, and CWE IDs appear only when present in fixture evidence.

### Provider Mock Fixtures

```text
tests/fixtures/providers/
  explanation-success.json
  explanation-malformed-json.json
  explanation-adds-fake-cve.json
  rate-limited.json
  auth-failed.json
  timeout.json
  streaming-success.ndjson
```

Required tests:

- Provider request builder includes only allowed finding evidence.
- Redaction runs before request creation.
- Provider timeout produces scanner-only report.
- Malformed model output is rejected or downgraded.
- If model output introduces a CVE not present in evidence, the CVE is removed and the explanation is flagged.
- No provider test depends on real API keys.

### Git Repository Fixtures

| Fixture | Setup | Expected Behavior |
| --- | --- | --- |
| clean repo | one commit, no changes | schedule can skip if baseline matches |
| dirty source change | committed baseline plus modified source file | changed-file scan is planned |
| dependency change | lockfile modified | dependency scan is planned |
| docs-only change | Markdown changed only | heavy scan skipped by policy |
| security-sensitive change | `.github/workflows`, auth, config, Dockerfile | static/security-sensitive scan planned |
| no commits | git init without commit | initial scan runs and records first baseline after success |
| detached HEAD | checkout commit SHA | scan records commit and branch as detached |
| deleted workspace | path removed before run | schedule disables or marks recoverable error |
| failed scan | scanner failure during scheduled run | baseline is not updated |

### Report Rendering Tests

- HTML escapes finding titles, evidence, file paths, package names, references, and model text.
- Markdown renders all findings without dropping evidence.
- JSON report validates against the scan schema.
- Missing model explanation still produces a complete scanner-only report.
- Failed or skipped scanners appear in the report.
- Secret findings show redacted values only.
- Report metadata includes scan ID, target, commit SHA when available, mode, tools, and report paths.
- Delta reports correctly classify new, fixed, unchanged, and worsened findings.
- Snapshot tests use stable timestamps, paths, and scan IDs.

### Safety And Security Tests

| Guardrail | Required Test |
| --- | --- |
| No arbitrary shell | Agent/tool registry rejects shell requests |
| No package install | Scan never runs `npm install`, `npm ci`, `pnpm install`, `yarn install`, `npx`, `pip install`, or lifecycle scripts |
| No source writes | Scanner and agent paths cannot edit workspace source files |
| No path escape | Report and raw evidence paths cannot traverse outside approved dirs |
| No CVE invention | Model explanations cannot add identifiers absent from evidence |
| Secret redaction | Tokens are removed from prompts, logs, reports, and errors |
| Cloud privacy | Local-only mode blocks cloud provider calls |
| Network control | Offline mode never performs advisory/model/notification calls |
| Scanner failure isolation | One failed scanner does not crash the whole scan |
| Output limits | Large scanner output is truncated safely and marked |
| Timeout handling | Hung scanners are killed and reported as timed out |

### Privacy Tests

1. Local-only scan with model configured still makes no cloud call.
2. Balanced mode uses online advisories only when allowed.
3. Cloud-assisted mode sends only normalized findings and allowed snippets.
4. Redaction preview output matches the actual provider request payload.
5. Session history stores tool calls and summaries, not secrets.
6. Report artifacts do not contain provider keys, GitHub tokens, Telegram tokens, AgentMail keys, npm tokens, or environment dumps.
7. Logs redact token-like strings before writing.

### Performance Budgets

| Scenario | Budget |
| --- | ---: |
| CLI help startup | under 500 ms |
| Config load | under 100 ms |
| Scanner plan for 10k files | under 3 s |
| Normalizing 5k findings | under 2 s |
| Rendering 5k-finding JSON report | under 2 s |
| Rendering 1k-finding HTML report | under 3 s |
| Watch debounce overhead | under 100 ms per event burst after coalescing |
| Redaction of 5 MB text | under 1 s |

### E2E Scenarios

1. First-run onboarding creates a workspace and report destination.
2. `hermsec doctor` reports missing optional scanners as warnings.
3. `hermsec scan <local fixture>` creates `report.html`, `report.md`, `summary.json`, `findings.json`, `evidence.json`, and `run.json`.
4. Secret fixture produces a redacted secret finding.
5. Node vulnerable lockfile produces dependency findings from fixtures/mocks.
6. Python fixture produces Bandit/Semgrep-style code findings from fixtures/mocks.
7. No-model mode produces a complete report.
8. Mock-provider mode adds explanation without changing scanner evidence.
9. Offline mode queues enrichment but still writes local reports.
10. Scheduled scan skips unchanged repo.
11. Scheduled scan runs after dependency change.
12. Failed scheduled scan does not update baseline.
13. Report destination unavailable falls back to app data and tells the user where the report was saved.
14. TUI flow can start onboarding, choose local-only mode, run scan, and open report center.

### Snapshot Strategy

Use snapshots for stable presentation surfaces only:

- Markdown report
- HTML report body or normalized DOM
- JSON report schema shape
- terminal summary output
- TUI screen states
- scanner plan output
- run log examples

Snapshot rules:

- Normalize timestamps.
- Normalize absolute paths.
- Normalize OS path separators.
- Use deterministic scan IDs.
- Do not snapshot raw secrets, machine usernames, home directories, or live network responses.

### CI Guidance

CI layers:

```text
ci:static
  typecheck
  lint
  format check

ci:unit
  unit tests
  schema tests
  redaction tests

ci:integration
  scanner fixture tests
  provider mock tests
  report rendering tests
  git fixture tests

ci:e2e
  CLI smoke tests
  offline scan flow
  scheduled scan flow with fake clock

ci:security
  safety guardrail tests
  secret scanning of repository
  dependency audit when approved and safe
```

GitHub Actions rules:

- Set top-level permissions to `contents: read`.
- Use `actions/checkout` with `persist-credentials: false`.
- Pin third-party actions to full commit SHAs where practical.
- Do not run CI on `pull_request_target` with secrets.
- Do not expose provider credentials to PR workflows.
- Do not share caches between untrusted PR jobs and trusted release jobs.
- Keep network-dependent tests out of default CI.
- If dependency installation is needed in CI, use lockfile-respecting install with lifecycle scripts disabled.
- Prefer SafeDep PMG before package-manager install commands where available and approved.

### Release QA Gates

A release candidate is acceptable only when:

1. All unit, integration, e2e, snapshot, and safety tests pass.
2. The app runs without real API keys.
3. Local-only mode performs no cloud/provider calls.
4. Reports contain no unredacted fake secrets.
5. Scanner fixture coverage exists for every supported scanner.
6. Provider mock coverage exists for every supported provider adapter.
7. Git-aware scheduler skip/run/baseline behavior is tested.
8. Report rendering escapes unsafe content.
9. No test executes dependency lifecycle scripts.
10. No test modifies source fixtures except inside temporary copies.
11. `doctor` clearly reports missing tools without crashing.
12. A fresh clone can run the documented test suite after approved dependency setup.
13. The demo fixture scan completes within the performance budget.
14. The release notes list known limitations and any skipped optional tests.

## Phase 10: Post-MVP VPS And GitHub Mode

Status: post-MVP. Local mode remains the primary build target. Remote mode must reuse the same scan engine, finding schema, scheduler rules, report renderer, redaction layer, and scanner safety policy from the local MVP.

### Goals

- Run Hermsec as a VPS-hosted service for selected GitHub repositories.
- Support GitHub-triggered scans through signed webhooks.
- Support scheduled remote scans that skip unchanged repositories.
- Store reports remotely with access control and retention.
- Keep tokens, private code, scan workspaces, logs, and reports separated by clear security boundaries.
- Avoid turning remote mode into a general CI runner or arbitrary shell service.

### Non-Goals

- Not part of the local MVP.
- No multi-tenant SaaS until single-tenant VPS mode is hardened.
- No automatic source-code edits.
- No package installs or lifecycle scripts during scans.
- No raw private repository contents in logs.
- No broad GitHub token scopes.

### Architecture

```text
GitHub
  |
  | signed webhook / scheduled poll
  v
Hermsec VPS API
  |
  +-- repo registry
  +-- token vault references
  +-- webhook verifier
  +-- authz and audit log
  |
  v
Remote job queue
  |
  v
Remote scan worker
  |
  +-- repo sync sandbox
  +-- Hermsec scan engine
  +-- scanner wrappers
  +-- redaction layer
  +-- report renderer
  |
  v
Remote report store
```

### Concrete Modules

```text
src/remote/
  server.ts
  config.ts
  authz.ts
  auditLog.ts
  github/
    appAuth.ts
    tokenAuth.ts
    tokenVault.ts
    repoRegistry.ts
    repoSync.ts
    webhook.ts
    webhookDedupe.ts
  jobs/
    queue.ts
    worker.ts
    scheduler.ts
    leases.ts
  sandbox/
    workspace.ts
    limits.ts
    networkPolicy.ts
  reports/
    remoteReportStore.ts
    reportAccess.ts
    retention.ts
  observability/
    logger.ts
    metrics.ts
    health.ts
```

### Data Model

```ts
type RemoteRepository = {
  id: string;
  provider: "github";
  owner: string;
  repo: string;
  defaultBranch: string;
  private: boolean;
  credentialRef: string;
  webhookEnabled: boolean;
  schedules: string[];
  lastScannedSha?: string;
  retentionDays: number;
};

type RemoteScanJob = {
  id: string;
  repoId: string;
  reason: "webhook" | "schedule" | "manual";
  ref: string;
  sha?: string;
  status: "queued" | "running" | "succeeded" | "failed" | "cancelled";
  attempts: number;
  createdAt: string;
  startedAt?: string;
  finishedAt?: string;
};

type RemoteReport = {
  scanId: string;
  repoId: string;
  commitSha: string;
  artifactRoot: string;
  visibility: "private";
  expiresAt?: string;
};
```

### GitHub Token Handling

- Prefer GitHub App installation tokens for production remote mode because they are short-lived and repository-scoped.
- Fine-grained personal access tokens are an acceptable single-user fallback only when limited to selected repositories.
- Required baseline permissions: repository metadata read and contents read.
- Optional permissions: pull request read for PR scans, issues or checks write only if Hermsec later posts summaries back to GitHub.
- Store only encrypted token material or secret-manager references. Never store plaintext tokens in repo config, reports, job payloads, or logs.
- Show only token fingerprints, provider type, repository scope, created time, and last successful use.
- Do not embed tokens in clone URLs that can appear in process lists or logs.
- Token revocation must fail closed: mark repo disconnected, stop future scans, keep old reports private.

### Repo Sync

- Only sync repositories explicitly registered in `repoRegistry`.
- Validate GitHub webhook `owner/repo` against registered repos before enqueueing work.
- Use shallow clone or fetch where possible, then checkout the exact webhook SHA/ref.
- Prefer disposable per-job workspaces:

```text
/var/lib/hermsec/workspaces/<repo-id>/<job-id>/
```

- Delete workspaces after report generation unless debug retention is explicitly enabled.
- Never reuse a dirty workspace for another repository.
- Do not run dependency installation during sync or scan.
- Do not follow arbitrary repository-provided hooks or scripts.
- Record commit SHA, branch/ref, webhook delivery ID, and sync method in `run.json`.

### Webhooks

- Endpoint: `POST /webhooks/github`.
- Verify GitHub HMAC signature against the webhook secret using the raw request body before parsing JSON.
- Reject missing, invalid, or replayed delivery IDs.
- Supported events:
  - `push`: scan changed branch if branch policy matches.
  - `pull_request`: scan opened, reopened, and synchronize events.
  - `repository`: disable or update registry entry when renamed, archived, or removed.
  - `installation`: future GitHub App setup and teardown.
- Debounce rapid push events by repo/ref.
- Webhook jobs should be idempotent by `repoId + eventName + deliveryId + sha`.

### Scheduled Remote Scans

Reuse the local schedule model with remote fields.

Default policy: `scan-if-git-changed`.

Flow:

1. Resolve repo registration.
2. Verify credential health.
3. Read remote HEAD for the configured ref.
4. Compare with `lastScannedSha`.
5. Skip if unchanged.
6. Enqueue scan if changed.
7. Update baseline only after successful report generation.

### Remote Report Storage

- Single-tenant VPS default: filesystem storage under `/var/lib/hermsec/reports`.
- Later multi-tenant mode: S3-compatible object storage plus database metadata.
- Store `report.html`, `report.md`, `summary.json`, `findings.json`, `evidence.json`, `run.json`, and selected redacted raw scanner output.
- Reports are private by default and require Hermsec authorization.
- Support retention policies per repo.
- Redact secrets before writing report artifacts.
- Do not store full private source snapshots as report artifacts.

### Security Boundaries

- Run API and worker as a non-root `hermsec` OS user.
- Separate API process from scan worker process.
- Enforce path boundaries for workspaces and reports.
- Use executable plus argument arrays, never shell interpolation.
- Apply scan timeouts, max output size, max repo size, and max report size.
- Block package lifecycle scripts and arbitrary package execution.
- Treat fork PR code as untrusted. Do not expose privileged tokens or secrets to fork scan jobs.
- Restrict outbound network later to GitHub, advisory APIs, configured model providers, and report destinations.
- Multi-tenant mode requires stronger isolation such as containers, per-tenant storage prefixes, per-job network policy, and stricter quota enforcement.

### Deployment

Target: Ubuntu VPS with Node.js, Git, scanner CLIs, reverse proxy, and systemd.

Services:

- `hermsec-api.service`
- `hermsec-worker.service`
- optional `hermsec-scheduler.timer`

Directories:

```text
/etc/hermsec/                 # root-owned config, no repo secrets
/var/lib/hermsec/             # reports, queue db, workspaces
/var/log/hermsec/             # redacted structured logs
```

TLS terminates at Caddy or Nginx. Secrets live in a server secret store or root-owned environment file with restricted permissions.

### Observability

- Structured JSON logs with token and secret redaction.
- Health endpoints:
  - `/healthz`: process alive.
  - `/readyz`: database, queue, report store, and scanner availability.
- Metrics:
  - webhook accepted/rejected count
  - queue depth
  - scan duration
  - scanner failures
  - report generation failures
  - token auth failures
  - disk usage
  - skipped unchanged schedules
- Audit events:
  - repo registered/removed
  - credential added/rotated/revoked
  - webhook rejected
  - scan started/completed/failed
  - report viewed/downloaded

### Risks And Mitigations

| Risk | Mitigation |
| --- | --- |
| Token leakage | Vault references, encryption, redaction, no tokens in clone URLs/logs. |
| Malicious repo code | No installs, no lifecycle scripts, sandboxed workspace, resource limits. |
| Webhook spoofing | HMAC validation, replay guard, registered repo check. |
| Cross-repo data exposure | Per-job workspaces, report authz, path boundary tests. |
| VPS disk exhaustion | Quotas, retention cleanup, report size limits, metrics. |
| Scanner false confidence | Keep evidence-grounded schema and report limitations. |
| Multi-tenant complexity | Ship single-tenant VPS first; defer SaaS isolation. |

### Tests

- Unit tests for webhook signature verification, replay detection, token redaction, path boundary checks, schedule skip logic, and report access checks.
- Integration tests with a mock GitHub API and local bare Git repositories.
- E2E test: register repo with credential reference, receive signed push webhook, enqueue scan job, clone exact commit, run scanner harness without installs, write remote report, view report through authorized endpoint.
- Security tests:
  - invalid webhook signature is rejected
  - replayed delivery ID is rejected
  - unregistered repo webhook is rejected
  - malicious branch name cannot escape workspace paths
  - token-like strings are redacted from logs and reports
  - fork PR scan receives no privileged secrets
  - revoked token disables future scans gracefully

### Acceptance Criteria

- Remote mode is behind an explicit post-MVP feature flag or separate server command.
- A registered GitHub repo can be scanned from a signed webhook without exposing tokens.
- Scheduled remote scans skip unchanged commits.
- Every scan uses a disposable bounded workspace.
- Reports are stored remotely and are private by default.
- Logs contain no repository secrets, GitHub tokens, model keys, or raw private source.
- Token revocation, scanner failure, clone failure, and report-store failure produce clear recoverable errors.
- The remote test suite proves webhook validation, repo sync, job retry, report access control, and redaction.

## Milestone Plan

### Milestone 1: Skeleton

- CLI entrypoint
- app data storage
- workspace add/list/use
- local report destination config
- doctor placeholder

### Milestone 2: Manual Scan

- repository inventory
- safe process runner
- one scanner wrapper
- normalized findings
- JSON report

### Milestone 3: Local Reports

- HTML report
- Markdown report
- report index
- report open command

### Milestone 4: Chat Agent

- chat TUI
- intent router
- restricted tool registry
- mock provider
- scanner-only mode

### Milestone 5: Model Providers

- `noModel` adapter
- Ollama adapter
- OpenRouter adapter
- OpenAI/Claude/Gemini/OpenCode Go adapters
- redaction and structured outputs

### Milestone 6: Git Scheduling

- schedule store
- git baseline
- change classifier
- scheduled scan run logs
- watch-after-idle mode

### Milestone 7: Security Intel

- OSV fetcher
- GitHub Advisory fetcher
- NVD/CISA KEV/EPSS enrichment
- local cache
- Vibe Coder Security Feed

### Milestone 8: QA And Demo

- fixture repos
- E2E tests
- report snapshots
- demo script
- final docs

## Definition Of Done

Hermsec local MVP is done when:

1. `hermsec` opens chatbot-style onboarding.
2. A user can create/select workspaces.
3. Reports can be saved to a user-selected local directory.
4. A manual scan runs at least one scanner through the safe harness.
5. Findings are normalized and rendered to HTML/Markdown/JSON.
6. The restricted agent can explain findings without inventing CVEs.
7. A scheduled git-aware scan runs only when changes are detected.
8. The Vibe Coder Security Feed can fetch and summarize trusted sources.
9. The test suite covers CLI, storage, scanner harness, agent permissions, reports, scheduler, and intel.
10. No secrets are committed or printed in reports/logs.
