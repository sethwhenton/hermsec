# Hermsec Electron Plan

## Current Decision

Scratch the terminal-first CLI/TUI direction for the main user experience.

Hermsec should become a small local-first Electron desktop app with a polished chat-style UI, a restricted security scan harness, local reports, security intelligence, and optional model-backed explanations.

Recommended path:

1. Use Synara as a visual and architectural reference.
2. Do not fork all of Synara as-is for the MVP.
3. Build a smaller Electron + React shell that borrows the useful Synara ideas:
   - left workspace/session sidebar
   - central chat/report surface
   - bottom composer
   - settings/provider picker
   - command palette
   - secure desktop IPC
   - provider adapter pattern
4. Use Pi as the first agent runtime reference where we need an agent harness.
5. Keep Hermes Agent as an optional future integration, not the foundation.

The Hermsec identity should stay very focused: a security agent for vibe coders. It should not become a full coding agent, messaging gateway, skill factory, or terminal automation platform.

## Evidence Reviewed

### Synara Local Folder

Path reviewed:

```text
D:\Downloads\synara-0.1.2\synara-0.1.2
```

Key files reviewed:

```text
README.md
LICENSE
package.json
apps/desktop/package.json
apps/desktop/src/main.ts
apps/web/package.json
apps/web/src/components/ChatView.tsx
apps/server/src/provider/Layers/ProviderAdapterRegistry.ts
apps/server/src/provider/Services/ProviderAdapter.ts
apps/server/src/provider/Layers/PiAdapter.ts
apps/server/src/provider/Layers/ProviderHealth.ts
packages/contracts/src/orchestration.ts
KEYBINDINGS.md
assets/prod/readme-screenshot.png
```

What Synara is:

- A minimal web GUI for coding agents.
- A desktop-capable Electron app.
- A Bun monorepo with `apps/desktop`, `apps/web`, `apps/server`, and shared packages.
- A React 19 + Vite web app.
- An Electron 40 desktop shell.
- A local backend/server that talks to the renderer through HTTP/WebSocket and Electron IPC.
- A multi-provider coding-agent GUI, not a security scanner app.

Important dependencies and shape:

- Root package manager: `bun@1.3.12`
- Electron app: `apps/desktop`, dependency `electron@40.6.0`
- Web app: `apps/web`, React 19, Vite, TanStack Router/Query, xterm, Lexical, cmdk, Base UI, Tabler icons
- Server: Effect-based backend
- Provider architecture includes `codex`, `claudeAgent`, `cursor`, `gemini`, `grok`, `kilo`, `opencode`, and `pi`
- License: MIT, with copyright notice retention required

Synara is reusable, but it is not small. It is a full multi-provider coding-agent desktop/web product with:

- provider health checks
- session runtime
- terminal handling
- browser panel
- update flow
- voice transcription hooks
- git/worktree orchestration
- provider command discovery
- plugin/skill discovery
- desktop auto-updater
- custom browser-use pipe server

That is useful, but it is too much to inherit blindly.

### Hermes Agent

Repository reviewed:

```text
https://github.com/nousresearch/hermes-agent
```

Current HEAD checked with `git ls-remote`:

```text
af8b917dabc07c34c3edaf32ade678bbb7843b4d
```

What Hermes Agent gives us conceptually:

- full agent loop
- terminal UI
- slash commands
- memory and skill learning
- scheduled automations
- messaging gateway
- Telegram/Discord/Slack/WhatsApp/Signal/email style operation
- subagents and parallel workstreams
- remote execution options like VPS, Docker, SSH, and cloud environments
- provider switching

Why Hermes is not the right MVP foundation:

- It is intentionally broad.
- It is closer to a general life/work automation agent than a focused security product.
- It brings many features we explicitly do not want for MVP:
  - arbitrary terminal capability
  - broad memory system
  - messaging gateway
  - self-improving skills
  - subagent spawning
  - cloud/remote execution backends
  - cron style autonomous agent work
- Hermsec needs stricter boundaries than a general agent. The model should explain scan evidence, not roam freely.

What to borrow from Hermes:

- the idea of scheduled security tasks
- the idea of persistent session summaries
- the idea of skills as bounded workflows
- the idea of one conversation continuing across surfaces
- the idea of subagents later, but only as restricted analysis workers

Do not borrow Hermes as the core runtime for MVP.

### Pi

Repository reviewed:

```text
https://github.com/earendil-works/pi
```

Current HEAD checked with `git ls-remote`:

```text
89a92207f1c9303d53d822fd9b0ac21578834cb4
```

What Pi gives us conceptually:

- TypeScript-oriented agent toolkit.
- Coding agent CLI.
- Agent runtime with tool calling and state management.
- Unified multi-provider LLM API.
- TUI and web UI libraries.

Pi packages highlighted by the repository:

```text
@earendil-works/pi-coding-agent
@earendil-works/pi-agent-core
@earendil-works/pi-ai
@earendil-works/pi-tui
```

Why Pi fits Hermsec better than Hermes:

- It is more modular.
- It is TypeScript-native, matching Electron/React/Node.
- Synara already has a Pi provider integration path.
- It can be treated as a harness/provider adapter instead of a whole product worldview.
- It is easier to keep Hermsec's model role narrow.

What to borrow from Pi:

- model/provider abstraction
- direct SDK style runtime
- tool-calling/state concepts
- possibly `pi-ai` for model provider calls
- possibly `pi-agent-core` if we need a formal agent loop

Do not let Pi become a free-form coding agent inside Hermsec. It should only call Hermsec-approved tools.

## UI Recommendation

Synara's UI direction is good for Hermsec.

The screenshot shows a layout that solves the pain we hit with the terminal TUI:

- real clickable UI
- proper sidebar
- readable chat surface
- persistent composer
- visible settings
- room for reports and diff-like evidence
- panels for browser/workspace/details
- desktop-native window behavior

For Hermsec, adapt the visual shell like this:

```text
Left sidebar:
  Workspaces
  Scans
  Reports
  Security Intel
  Schedules
  Settings

Center:
  Chat with Hermsec
  Scan result summaries
  Report explanations
  Finding triage

Right panel:
  Active scan details
  Finding evidence
  Affected files/packages
  CVE/advisory detail
  Suggested fixes

Bottom composer:
  Ask Hermsec
  slash commands
  attach report/finding
  select provider/model
  choose local-only/online mode
```

The app should feel like a security cockpit, not a general coding IDE.

## Reuse Decision: Fork Synara or Start Smaller?

### Option A: Fork Synara Whole

Pros:

- fastest path to a polished visual shell
- Electron, React, server, provider plumbing already exists
- provider settings and session UX are mature
- Pi support is already present
- codebase proves the pattern works

Cons:

- too large for Hermsec MVP
- Bun-only ecosystem may complicate packaging and supply-chain review
- many features must be removed:
  - terminal drawers
  - browser panel
  - git/worktree agent actions
  - auto-updater
  - voice
  - multi-agent coding workflows
  - plugin library
  - PR/diff coding actions
- high risk of dragging old product assumptions into Hermsec
- harder to make it "small lightweight"

### Option B: Build Small Electron App Using Synara as Reference

Pros:

- clean security-first architecture
- smaller dependency surface
- easier packaging
- easier test strategy
- fewer permissions
- no inherited coding-agent behavior
- UI can still look like Synara/OpenCode style

Cons:

- slower initial UI build
- we must implement our own IPC/backend contracts
- we need to recreate only the parts of Synara we like

### Recommendation

Use Option B.

Create a new small Electron app for Hermsec, but copy the useful ideas from Synara:

- desktop main/preload IPC pattern
- React chat shell layout
- sidebar/session model
- provider adapter contract
- keybinding/settings concepts
- folder picker/save file IPC
- secure external URL handling

Avoid copying the whole Synara monorepo unless the goal changes to "ship fast by rebranding and deleting features."

## Proposed Hermsec Desktop Architecture

```text
hermsec-desktop/
  apps/
    desktop/
      Electron main process
      preload bridge
      secure IPC handlers
      scanner worker process manager
    renderer/
      React/Vite UI
      chat surface
      reports/intel/settings screens
  packages/
    core/
      scan harness
      report model
      workspace model
      finding normalization
      scheduler logic
    scanner/
      Semgrep/Gitleaks/Bandit/OSV/pip-audit adapters
      local heuristic scanner
      safe process execution
    intel/
      CISA KEV
      OSV
      GitHub Advisory
      NVD
      cache/summarizer
    agent/
      restricted tool gateway
      provider adapters
      explanation prompts
      redaction
    storage/
      app-data stores
      report indexes
      session history
      workspace config
```

The old CLI can be kept as an internal package if useful, but it should not be the main product interface.

## Runtime Boundaries

Hermsec should have three layers:

### 1. UI Layer

The UI can ask for actions:

- scan this workspace
- explain this finding
- summarize this report
- show today's security intel
- compare this scan to previous scan
- configure model/provider
- schedule a scan

The UI should not directly run shell commands.

### 2. Harness Layer

The harness owns all real work:

- discovering project type
- running scanner CLIs safely
- parsing output
- normalizing findings
- enriching findings with advisories
- writing reports
- storing evidence bundles
- maintaining scan history

The harness is deterministic and testable without a model.

### 3. Agent Layer

The agent only receives structured tool outputs and approved snippets.

Allowed model-facing tools:

```text
scan.workspace
scan.status
report.get
report.list
finding.get
finding.explain
intel.update
intel.list
workspace.list
workspace.get
schedule.list
schedule.create
settings.get
```

Disallowed for MVP:

```text
shell.exec
file.write
git.commit
git.push
package.install
browser.automation
remote.vps.exec
autonomous.subagent.spawn
```

This keeps Hermsec from becoming a general coding agent.

## Harness Recommendation

Use this stack:

```text
Hermsec deterministic scanner harness
  +
Pi-style provider/model adapter
  +
Hermes-inspired scheduling/session ideas
```

Do not choose between "all Hermes" and "all Pi."

Use Pi's simplicity for the model/runtime side. Use Hermes only as inspiration for future long-running workflows.

### Why This Works

Hermsec's core value is not that the agent can do anything.

Hermsec's value is that it can:

- find risky code
- map findings to real advisories
- explain impact clearly
- prioritize fixes
- keep vibe coders aware of current threats
- run locally without leaking private repos

That means the scanner harness is the product's spine. The agent is a narrator, triage assistant, and report explainer.

## MVP Feature Set

### Onboarding

First launch asks:

1. Pick workspace folder.
2. Choose privacy mode:
   - Local only
   - Online intel
   - Cloud explanations
3. Choose report destination:
   - App data
   - Project `.hermsec/reports`
   - Custom folder
4. Configure provider:
   - No model
   - OpenAI
   - Claude
   - Gemini
   - OpenRouter
   - OpenCode Go
   - Ollama/local
   - Pi provider if adopted
5. Run doctor check.
6. Offer first scan.

### Main Screens

#### Dashboard

- workspace health
- last scan
- highest severity findings
- recent advisories
- scheduled scans

#### Chat

- "Ask Hermsec"
- commands surfaced as UI actions
- model-generated explanations when enabled
- scanner-only fallback when no model

#### Scans

- run scan
- active progress
- scanner status
- scan history
- compare previous scan

#### Findings

- severity
- category
- affected file/package
- evidence
- advisory links
- remediation
- false-positive notes

#### Reports

- local report list
- Markdown/HTML/JSON export
- open containing folder
- copy summary

#### Intel

- security news/advisory feed
- CISA KEV
- OSV package advisories
- GitHub Advisory Database
- NVD
- "Am I affected?" matching against workspace manifests

#### Settings

- provider/model
- credential reference
- privacy mode
- report destination
- scanner paths
- schedule settings
- data retention

## Scan Flow

```text
User clicks Scan
  -> UI sends scan.start(workspaceId)
  -> desktop main validates request
  -> scanner worker starts
  -> worker runs allowed scanners
  -> normalized findings stream back
  -> report artifacts are written locally
  -> agent optionally explains findings
  -> UI shows summary and triage queue
```

Scanner adapters:

- Semgrep
- Gitleaks
- Bandit
- OSV-Scanner
- pip-audit
- npm audit through PMG when package-manager access is explicitly allowed
- built-in lightweight heuristics

All scanner execution should use:

- explicit binary discovery
- no package installs by default
- timeouts
- output limits
- structured parser adapters
- redaction before display/model use

## Model Flow

```text
User asks question
  -> intent router decides if this is:
       status question
       finding question
       report summary
       intel question
       scan request
  -> Hermsec tool gateway runs approved action
  -> model sees structured result
  -> model responds with explanation
```

The model never gets raw full-repo access by default.

For code snippets:

- show user which files/snippets will be used
- cap snippet size
- redact secrets
- include only evidence-adjacent lines

## Provider Strategy

Start with:

- No model
- OpenAI-compatible
- OpenAI
- Claude
- Gemini
- OpenRouter
- Ollama
- OpenCode Go

Then add:

- Pi provider adapter

Keep Hermes as:

- external integration option
- future gateway/scheduling reference
- not a first-class model provider

## Data Storage

Use local app data:

```text
%APPDATA%\Hermsec\
  config.json
  workspaces.json
  sessions\
  scans\
  reports\
  intel-cache\
  logs\
```

Per-project local mode:

```text
<workspace>\.hermsec\
  config.json
  reports\
  scans\
```

Never store raw API keys in JSON config.

Provider credentials should be:

1. environment variable references for MVP
2. OS keychain later if needed

## Security Model

Default mode:

```text
local-only
```

Security rules:

- no arbitrary shell execution from chat
- no package install by default
- no lifecycle scripts by default
- no raw secrets in reports
- no full private repo upload to model
- scanner output is capped and redacted
- user confirms any online model explanation
- all report files are local unless explicitly exported

Electron security:

- `contextIsolation: true`
- `nodeIntegration: false`
- `sandbox: true`
- strict preload bridge
- no renderer access to filesystem
- safe external URL allowlist
- validate all IPC payloads
- separate scanner worker from renderer
- never trust renderer input

## Implementation Phases

### Phase 0 - Product Reset

Deliverables:

- archive old CLI/TUI decision
- write this Electron plan
- confirm Synara reuse level
- choose greenfield Electron or Synara fork

Recommended decision: greenfield Electron with Synara-inspired UI.

### Phase 1 - Desktop Skeleton

Deliverables:

- Electron main process
- secure preload bridge
- React/Vite renderer
- local app-data path
- simple dashboard
- workspace picker
- settings stub

Tests:

- Electron launches
- renderer cannot access Node directly
- folder picker IPC works
- settings persist locally

### Phase 2 - Hermsec Core Package

Deliverables:

- workspace model
- scan request/result schema
- finding schema
- report schema
- scanner process runner
- redaction helpers

Tests:

- schema validation
- redaction fixtures
- process timeout behavior
- output size limits

### Phase 3 - Scanner Harness

Deliverables:

- built-in heuristics
- Semgrep adapter
- Gitleaks adapter
- Bandit adapter
- OSV adapter
- pip-audit adapter
- report writer

Tests:

- vulnerable fixtures
- clean fixtures
- scanner missing behavior
- parser snapshots
- precision/recall/F1 evaluation fixture

### Phase 4 - UI Scan Experience

Deliverables:

- scan progress screen
- finding table
- finding detail drawer
- report list
- open report
- compare with previous scan

Tests:

- renderer unit tests
- scan IPC integration test
- Electron E2E run against toy vulnerable project

### Phase 5 - Security Intel

Deliverables:

- CISA KEV fetcher
- OSV fetcher
- GitHub Advisory fetcher
- NVD fetcher
- local cache
- "Am I affected?" matching
- Intel screen

Tests:

- cached offline behavior
- fetch failure fallback
- advisory dedupe
- manifest-to-advisory matching

### Phase 6 - Agent/Model Layer

Deliverables:

- restricted tool gateway
- no-model summarizer
- OpenAI-compatible adapter
- provider settings UI
- model explanation flow
- redaction before model calls

Tests:

- model prompt fixtures
- tool allowlist enforcement
- invented CVE rejection
- no raw secret leakage

### Phase 7 - Pi Adapter

Deliverables:

- evaluate direct `pi-ai` provider use
- evaluate `pi-agent-core` only if needed
- add Pi-style model/provider adapter
- keep tool access restricted to Hermsec tools

Tests:

- provider health check
- model list if available
- restricted tool call enforcement
- fallback when Pi is unavailable

### Phase 8 - Scheduling

Deliverables:

- schedule model
- daily/weekly scan configuration
- run-on-change option
- manual schedule runner
- OS scheduler adapter later

Tests:

- schedule parsing
- missed-run handling
- git-change detection
- duplicate-run prevention

### Phase 9 - Packaging

Deliverables:

- Windows installer
- portable dev build
- app icon/branding
- release smoke test
- code signing plan later

Tests:

- packaged launch
- scan fixture from packaged app
- report creation
- app-data cleanup

## Testing Plan

### Unit Tests

- schemas
- scanner parsers
- redaction
- advisory matching
- report rendering
- provider configuration
- IPC payload validation

### Integration Tests

- scan vulnerable Node fixture
- scan vulnerable Python fixture
- scan clean fixtures
- run with scanner binaries missing
- run with no internet
- run with stale intel cache
- run with no model provider

### Electron E2E Tests

- first-run onboarding
- pick workspace
- run scan
- open finding
- generate local report
- change report destination
- show security intel
- configure provider reference
- verify renderer has no direct filesystem access

### Evaluation Tests

Keep a benchmark folder:

```text
tests/fixtures/vulnerable-repos/
tests/fixtures/clean-repos/
tests/ground-truth/
```

Metrics:

- precision
- recall
- F1
- severity confusion matrix
- category confusion matrix
- duplicate noise rate
- missed critical findings

## What I Would Build First

First build a tiny proof:

```text
Electron window
  -> pick local repo folder
  -> run built-in heuristic scanner
  -> show findings in Synara-style UI
  -> save JSON/Markdown report locally
  -> chat asks "explain this finding"
  -> no-model explanation first
```

After that works, add external scanners and models.

This avoids repeating the terminal TUI mistake: we prove the shell, the scan harness, and the report loop before adding provider complexity.

## Final Recommendation

Use Synara's UI as the north star, not as a full dependency.

Use Pi's modularity for the agent/provider direction.

Use Hermes Agent only as a reference for future features like scheduled automations, persistent memory, and external messaging.

The product should be:

```text
Small Electron app
Local scanner harness
Restricted model assistant
Security intel feed
Local reports
Provider optional
Hermsec-owned safety boundaries
```

That is the cleanest path to making Hermsec feel powerful without becoming bloated.
