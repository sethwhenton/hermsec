# Hermsec TUI, Onboarding, And Harness Plan

Date: 2026-05-31

## Current Decision

Hermsec should use our own scanner and agent harness as the core product, with a TUI on top.

Do not make Hermes Agent a hard dependency for the MVP.

Instead:

1. Build the Hermsec harness first.
2. Build the TUI as the primary user experience.
3. Expose the same core through CLI commands.
4. Add a Hermes Agent adapter later, once the scan engine and report format are stable.

This gives us a working project we control, while still leaving a clean path to Hermes-style scheduled agent execution.

## Why Not Directly Integrate Hermes First?

Direct Hermes integration sounds attractive because the project idea came from a Hermes-style agent workflow. The problem is that the security scanner has to be reliable before it becomes a background agent.

For the MVP, Hermsec needs these things more than it needs deep Hermes integration:

- predictable repository input handling
- safe scanner execution
- normalized findings
- reproducible Markdown and JSON reports
- clean model boundaries
- local-first privacy rules
- onboarding that verifies setup step by step

If Hermes becomes the foundation too early, we risk making the demo depend on another harness before Hermsec itself is solid.

The better architecture is:

```text
Hermes Agent, cron, CI, or user
        |
        v
Hermsec CLI and TUI
        |
        v
Hermsec core harness
        |
        +-- repository resolver
        +-- scanner orchestrator
        +-- vulnerability intelligence
        +-- model explainer
        +-- report generator
        +-- notification sender
        +-- scheduler and offline queue
```

Hermes can call Hermsec later. Hermsec should not need Hermes to work.

## Relationship To Hermes Agent

Hermsec should feel like Hermes Agent in how it guides the user:

- friendly onboarding
- persistent profile
- step-by-step setup
- connection verification
- clear agent status
- useful defaults
- guided recovery when something fails
- Telegram-style notification option
- scheduled background work as a future extension

But Hermsec should not copy Hermes internally unless there is a direct benefit. The security-specific harness is our product value.

Recommended future integration:

```text
Hermes scheduled agent
        |
        v
Hermes calls:
  hermsec scan <project> --mode online --json --out <report-dir>
        |
        v
Hermsec returns:
  summary.json
  report.md
  findings.json
  notification payload
```

This keeps the boundary simple. Hermes handles agent scheduling and orchestration. Hermsec handles security scanning and explanation.

## GitHub Storage Plan

The working repo should be:

```text
https://github.com/sethwhenton/Security-insider-Lab-II.git
```

Everything we build for Hermsec should live inside:

```text
E:\Programming\Security insider II\Hermsec Proj
```

That folder should be initialized as a git repository with the GitHub URL as `origin`.

Recommended local setup:

```powershell
git init
git branch -M main
git remote add origin https://github.com/sethwhenton/Security-insider-Lab-II.git
git add .
git commit -m "Add Hermsec project plan and research docs"
git push -u origin main
```

If GitHub credentials are not available on this machine, the push will fail but the repo can still be committed locally and pushed later.

Do not commit:

- `.env`
- API keys
- Telegram bot tokens
- AgentMail API keys
- scanner caches
- queued private reports unless the user explicitly wants them committed
- cloned target repositories

## Product Shape

Hermsec should have two entry points:

```powershell
hermsec
```

Launches the interactive TUI.

```powershell
hermsec scan <target>
```

Runs the core engine directly for scripting, demos, CI, and Hermes integration.

The TUI is the primary experience. The CLI is the stable automation surface.

## TUI Stack Recommendation

Use TypeScript.

Recommended stack:

- `commander` or `clipanion` for command routing
- `@inquirer/prompts` for the first onboarding MVP
- `ink` for the richer full-screen React TUI
- `zod` for config and finding schema validation
- Node child process APIs for scanner execution
- plain JSON files for local state at first

Why this split:

- Inquirer is faster for early onboarding.
- Ink gives us a real terminal app feel later.
- The core scanner engine should not depend on either.

MVP can start with interactive prompts and evolve into a richer TUI without rewriting the scanner engine.

## TUI Personality

The TUI should feel like a calm security co-pilot, not a noisy scanner dump.

Tone:

- direct
- practical
- evidence-first
- not fear-based
- privacy-aware
- friendly enough to feel like an agent

Example status lines:

```text
Hermsec is checking repository access...
Bandit is available. Semgrep was not found.
Online enrichment is available.
No model provider is configured yet.
Telegram test message delivered.
```

Avoid pretending certainty when evidence is incomplete.

## First Run Onboarding

The first run should create a user profile and optionally a project profile.

Command:

```powershell
hermsec onboard
```

or simply:

```powershell
hermsec
```

if no profile exists.

### Onboarding Flow

```text
Welcome
  |
  v
Privacy profile
  |
  v
Project source
  |
  v
Access check
  |
  v
Scanner readiness
  |
  v
Online/offline mode
  |
  v
Model provider
  |
  v
Report destination
  |
  v
Notification setup
  |
  v
Schedule/watch setup
  |
  v
Review and save
  |
  v
Dashboard
```

### Step 1: Welcome

Show what Hermsec does in one line:

```text
Hermsec scans a repository, checks dependencies and code risks, explains findings, and writes a developer-ready report.
```

Actions:

- Start setup
- Run a one-time scan
- Open existing profile
- Run doctor

### Step 2: Privacy Profile

Offer three presets:

```text
Local only
  No cloud model calls. Local scanners and local reports only.

Balanced
  Local scanners plus online advisory lookups. Model calls require confirmation.

Cloud assisted
  Online advisories plus configured model provider for explanations.
```

This controls later defaults.

### Step 3: Project Source

The user chooses:

- local folder
- public GitHub URL
- private GitHub URL
- current folder

For GitHub URLs, Hermsec should explain how access works:

```text
Public repositories can be cloned read-only.
Private repositories require your existing GitHub access through gh, SSH, or Git credentials.
Hermsec does not ask for or store your GitHub password.
```

### Step 4: Access Check

For local folders:

- confirm path exists
- confirm it looks like a repository
- detect languages and package managers
- detect whether it is dirty

For public GitHub:

- run a read-only `git ls-remote`
- clone to a temp workspace only for scanning

For private GitHub:

- try local Git credentials
- try SSH if URL is SSH
- optionally detect `gh auth status`
- fail with guidance if not authenticated

Do not store GitHub credentials in Hermsec config.

### Step 5: Scanner Readiness

Run:

```powershell
hermsec doctor
```

Check:

- Git
- Node
- Python
- Bandit
- Semgrep
- Gitleaks
- OSV-Scanner
- pip-audit
- npm availability
- internet availability

Output should classify tools:

```text
Ready
Available but unused for this repo
Missing
Optional
Blocked by offline mode
```

Hermsec should not auto-install scanners during onboarding. It should show install guidance.

### Step 6: Online, Offline, Or Auto Mode

Offer:

```text
Auto
  Use online enrichment when internet is available, otherwise queue it.

Offline
  Local scanners and cached data only.

Online
  Local scanners plus fresh advisory lookups, model explanations, and notifications.
```

Default should be `Auto`.

### Step 7: Model Provider

Offer:

- no model
- Ollama
- LM Studio or OpenAI-compatible local endpoint
- OpenRouter
- custom OpenAI-compatible endpoint

Rules:

- The model never creates CVEs from scratch.
- The model explains scanner evidence.
- The model may suggest likely CWE classes when no CVE applies.
- Cloud model use requires explicit provider setup.
- Redaction preview should be available before cloud calls.

### Step 8: Report Destination

Offer:

- terminal summary
- Markdown report
- JSON report
- both Markdown and JSON

Default:

```text
.hermsec/reports/<timestamp>/
```

For scanning external user projects, ask before writing `.hermsec` into their repo. If they decline, store reports under the Hermsec user data directory.

### Step 9: Notification Setup

Offer:

- no notification
- local only
- email through AgentMail
- Telegram
- both email and Telegram

Do not require notifications for the MVP scan.

### Step 10: AgentMail Setup

Prompt:

```text
Do you want to receive email reports through AgentMail?
```

If yes:

- ask whether user already has an AgentMail API key
- ask for sender inbox or create/select one later
- store the API key outside the repo, preferably environment variable or OS credential store
- send a test report email

Expected env:

```powershell
AGENTMAIL_API_KEY=...
HERMSEC_REPORT_EMAIL=...
```

Never write those values into tracked files.

### Step 11: Telegram Setup

Prompt:

```text
Do you want Telegram alerts?
```

Guided setup:

1. Tell user to open BotFather.
2. Create a bot.
3. Paste the bot token into Hermsec runtime setup.
4. Hermsec calls `getMe` to verify the token.
5. User sends `/start` to the bot.
6. Hermsec fetches updates or asks for chat ID.
7. Hermsec sends a test message.

Expected env:

```powershell
TELEGRAM_BOT_TOKEN=...
TELEGRAM_CHAT_ID=...
```

Never write those values into tracked files.

### Step 12: Schedule And Watch Setup

Offer:

- no automation
- daily scan
- weekday scan
- custom cron expression
- after-idle watch mode
- scan changed files before commit

MVP examples:

```powershell
hermsec schedule add . --daily 18:00 --mode auto
hermsec watch . --after-idle 10m
hermsec scan . --staged
```

For the first implementation, use an in-app scheduler while the Hermsec process is running. Later, add OS-level scheduler integration:

- Windows Task Scheduler
- cron
- systemd timers
- Hermes scheduled agent

### Step 13: Review And Save

Show final config without secrets:

```text
Project: E:\path\to\repo
Mode: Auto
Model: Ollama
Reports: Markdown + JSON
Notifications: Telegram
Schedule: Weekdays at 18:00
Secrets: Stored outside repository
```

Then save profile.

## Main TUI Screens

### 1. Home Dashboard

Purpose:

Show current project, status, last scan, and next actions.

Sections:

- selected project
- online/offline state
- scanner readiness
- last scan summary
- queued reports
- next scheduled scan
- notification status

Actions:

- Run scan
- Review findings
- Change project
- Setup notifications
- Schedule scan
- Open settings
- Run doctor

### 2. Project Picker

Purpose:

Let the user choose a repo quickly.

Options:

- current directory
- recent projects
- paste GitHub URL
- browse local path
- clone public repo
- use private repo with existing Git auth

### 3. Scan Setup

Purpose:

Confirm mode before a scan.

Options:

- full scan
- changed files only
- dependency-only scan
- secrets-only scan
- static-analysis-only scan
- no-model scan
- online enrichment
- offline queue

### 4. Scan Progress

Purpose:

Make the agent work visible.

Display:

```text
Repository discovery     done
Dependency inventory     done
Gitleaks                 running
Bandit                   skipped, no Python files
Semgrep                  running
OSV advisory lookup      queued, offline
Model explanation        waiting for scanner evidence
Report generation        pending
```

The important part is that users see scanner evidence happening before model reasoning.

### 5. Findings List

Purpose:

Show findings grouped by severity and confidence.

Columns:

- severity
- confidence
- source
- title
- file or package
- fix status

Filters:

- critical/high only
- dependency findings
- code findings
- secrets
- new since last scan
- model-reviewed
- scanner-only

### 6. Finding Detail

Purpose:

Show enough evidence to act.

Fields:

- title
- severity
- confidence
- scanner source
- file/package
- line range if available
- CVE/GHSA/OSV ID if available
- CWE if available
- why it matters
- evidence
- suggested fix
- model explanation if enabled
- links to advisories

Actions:

- mark reviewed
- suppress with reason
- copy fix guidance
- open report
- export finding

### 7. Report Center

Purpose:

Make reports easy to find and send.

Features:

- latest report
- previous reports
- Markdown path
- JSON path
- queued notifications
- send now
- sync queued online tasks

### 8. Automation Screen

Purpose:

Manage scheduled and watch scans.

Features:

- list schedules
- add schedule
- pause schedule
- remove schedule
- run now
- show next run
- show last status

### 9. Notification Screen

Purpose:

Manage delivery channels.

Features:

- local report status
- AgentMail setup and test
- Telegram setup and test
- notification routing rules
- minimum severity threshold
- quiet hours

### 10. Settings

Purpose:

Manage global and project config.

Sections:

- privacy profile
- model provider
- scanner paths
- report location
- online/offline preference
- redaction settings
- ignored findings
- telemetry policy, default off unless explicitly enabled

## TUI Navigation Model

Keyboard:

```text
Arrow keys: move
Enter: select
Esc: back
r: run scan
d: doctor
s: schedule
n: notifications
q: quit
?: help
```

Keep it discoverable. Do not require users to memorize shortcuts.

## State And Config Files

Use two layers of config.

### User Config

Windows:

```text
%APPDATA%\Hermsec\config.json
```

Contains:

- recent projects
- preferred mode
- model provider name, not secret key
- report defaults
- notification channel enabled flags
- scanner path overrides

Does not contain:

- API keys
- Telegram tokens
- GitHub tokens

### Project Config

Optional:

```text
<project>/.hermsec/project.json
```

Contains:

- project display name
- scan policy
- ignored findings with reason
- report preferences
- schedule preference if user wants it project-local

Ask before writing this file into a user's project.

### Secrets

Prefer:

- environment variables
- OS credential store
- user-provided runtime prompt

Never store secrets in tracked project files.

## Core Harness Design

The core harness is the engine behind both CLI and TUI.

Suggested modules:

```text
src/
  cli/
    index.ts
    commands/
      scan.ts
      doctor.ts
      onboard.ts
      schedule.ts
      notify.ts
  tui/
    app.tsx
    screens/
    components/
  core/
    repository/
    discovery/
    scanner-plan/
    findings/
    policy/
  scanners/
    bandit.ts
    semgrep.ts
    gitleaks.ts
    osv.ts
    npmAudit.ts
    pipAudit.ts
  intelligence/
    osvClient.ts
    githubAdvisory.ts
    nvdClient.ts
    cisaKev.ts
    npmRegistry.ts
  model/
    providers/
    promptBuilder.ts
    redaction.ts
  reports/
    markdown.ts
    json.ts
    terminal.ts
  notify/
    agentmail.ts
    telegram.ts
    local.ts
  scheduler/
    schedules.ts
    runner.ts
    queue.ts
  storage/
    userConfig.ts
    projectConfig.ts
    reportStore.ts
```

Core rule:

```text
The TUI calls the same functions as the CLI.
The model reads normalized evidence.
The scanner tools create the evidence.
```

## Harness Tool Contract

Each scanner wrapper should return normalized findings plus raw metadata.

Example:

```ts
type ScannerResult = {
  scanner: string;
  status: "ok" | "failed" | "skipped";
  skippedReason?: string;
  findings: Finding[];
  rawOutputPath?: string;
  durationMs: number;
};
```

The model explainer should receive only the selected finding evidence and minimal relevant code context.

Example:

```ts
type ExplanationRequest = {
  finding: Finding;
  relevantSnippets: CodeSnippet[];
  advisoryContext: Advisory[];
  privacyMode: "local-only" | "balanced" | "cloud-assisted";
};
```

## Online And Offline Handling In The TUI

The TUI should always show mode clearly:

```text
Mode: Auto
Network: Offline
Online tasks: queued
```

If offline:

- run local scanners
- use cached advisories if available
- write local report
- queue online enrichment
- queue notifications

If online:

- run local scanners
- fetch fresh advisories
- enrich with current vulnerability data
- run configured model explanations
- send notifications

## Scheduling UX

The scheduler should feel simple:

```text
When should Hermsec scan this project?

> Every day at 18:00
  Weekdays at 18:00
  After coding activity stops for 10 minutes
  Custom cron expression
  Not now
```

For watch mode:

```text
Hermsec is watching this project.
Last change: 17:42
Next scan: after 10 minutes idle
```

For scheduled mode:

```text
Next scan: Monday 18:00
Last scan: Sunday 18:01, 2 high findings
```

## Report Delivery UX

Notification setup should be test-driven.

AgentMail:

```text
AgentMail connected.
Test email sent to seth@example.com.
```

Telegram:

```text
Telegram bot verified.
Test message delivered.
```

If a channel fails:

```text
Telegram token is valid, but no chat ID is configured.
Send /start to the bot, then press Enter to retry.
```

## Demo Flow

For class or presentation:

1. Open Hermsec TUI.
2. First-run onboarding appears.
3. Choose a local vulnerable demo repo or paste GitHub URL.
4. Hermsec checks access.
5. Hermsec checks scanners.
6. Choose Auto mode.
7. Choose no cloud model or local model for privacy.
8. Run scan.
9. Show progress screen.
10. Open findings list.
11. Open one dependency finding.
12. Open one code finding.
13. Show generated Markdown report.
14. Show scheduled scan setup.
15. Show Telegram or AgentMail notification test if ready.

This tells a clean story:

```text
Hermsec is not just a scanner. It is an onboarded security agent workflow.
```

## Implementation Phases

### Phase 0: Repository Bootstrap

- initialize local git repo
- set GitHub remote
- add `.gitignore`
- commit docs
- push to GitHub if credentials are available

### Phase 1: CLI Core Skeleton

- create TypeScript project
- add command routing
- add `hermsec doctor`
- add `hermsec scan <target>`
- add report folder creation
- no scanner execution yet

### Phase 2: Repository Resolver

- local path support
- current folder support
- GitHub URL parsing
- public repo access check
- clone-to-temp support
- private repo guidance

### Phase 3: Onboarding MVP

- build `hermsec onboard` with prompts
- save user config
- no secrets in repo
- run doctor from onboarding
- store recent project

### Phase 4: Scanner Harness

- scanner plan based on detected languages
- Gitleaks wrapper
- Bandit wrapper
- Semgrep wrapper
- npm audit or lockfile advisory wrapper
- OSV-Scanner wrapper
- normalized finding schema

### Phase 5: Reports

- terminal summary
- Markdown report
- JSON report
- report index
- previous scan comparison

### Phase 6: TUI Shell

- home dashboard
- project picker
- scan progress
- findings list
- finding detail
- report center

### Phase 7: Model Explainer

- no-model mode
- local model provider
- OpenRouter provider
- redaction preview
- evidence-only explanation prompt

### Phase 8: Automation

- in-app schedules
- watch after idle
- offline queue
- sync command

### Phase 9: Notifications

- Telegram setup and test
- AgentMail setup and test
- severity threshold
- queued delivery

### Phase 10: Hermes Adapter

- define stable JSON output contract
- create `hermsec scan --json`
- create Hermes wrapper script or adapter
- let Hermes call Hermsec on schedule
- keep Hermsec independently usable

## MVP Boundary

For the first working project, build:

- local project scan
- GitHub URL access check
- onboarding prompts
- doctor command
- scanner readiness screen
- one or two scanner wrappers
- Markdown and JSON reports
- simple findings screen
- no-model mode

Then add:

- model explanations
- online advisory enrichment
- scheduler
- Telegram or AgentMail
- full Hermes adapter

## Final Recommendation

Build Hermsec as its own harness and TUI.

Make it feel like Hermes Agent through onboarding, verification, memory, scheduling, and notifications.

Integrate Hermes later as an orchestration layer that calls Hermsec, not as the required foundation of Hermsec.

That gives us:

- a project we can demo without hidden dependencies
- a reusable CLI engine
- a real TUI experience
- safe local-first behavior
- a clean future story for Hermes scheduled agents

