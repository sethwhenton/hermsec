# Hermsec Automation, Online/Offline Modes, And Notifications

Date: 2026-05-31

## Why This Matters

Hermsec should not only be a manual scanner. The stronger product idea is:

```text
Hermsec watches the project while humans or coding agents are changing files,
then scans at the right time and sends a clear report to the developer.
```

This makes Hermsec feel like a practical security companion rather than a one-off class demo.

## Correct Mode Names

The idea should be split into two explicit modes:

### Offline Mode

Offline mode means Hermsec has no internet access or the user chooses not to use the internet.

Hermsec can still run local checks:

- Bandit with installed/local rules
- Semgrep with bundled/local rules
- Gitleaks with local rules
- lockfile/manifests inspection
- suspicious package-script heuristics
- report generation
- local history comparison

Hermsec cannot reliably do fresh checks for:

- latest npm advisories
- latest OSV records
- latest CISA KEV entries
- latest GitHub Advisory Database records
- cloud model explanations
- AgentMail/Telegram delivery

Offline mode should save a scan bundle for later enrichment:

```text
.hermsec/
  queue/
    2026-05-31T18-30-00.scan.json
```

When internet is back, Hermsec can run:

```bash
hermsec sync
```

That enriches queued findings with OSV/NVD/GitHub/CISA data, asks the model for explanation if enabled, and sends pending reports.

### Online Mode

Online mode means Hermsec can use the network.

It runs everything from offline mode plus:

- npm audit
- OSV-Scanner online queries
- pip-audit vulnerability-service lookups
- OSV.dev API enrichment
- GitHub Advisory Database enrichment
- NVD CVE enrichment
- CISA KEV priority checks
- model explanation through OpenRouter or other cloud/local network endpoints
- AgentMail email reports
- Telegram reports
- current supply-chain topic checks

Online mode should still be privacy-aware:

- ask before sending code snippets to cloud models
- redact secrets
- allow local model providers
- allow "online advisories only, no cloud model" mode

## Suggested Mode Matrix

| Capability | Offline Mode | Online Mode |
|---|---:|---:|
| Local code scan | yes | yes |
| Secret scan | yes | yes |
| Dependency manifest parsing | yes | yes |
| Fresh npm audit | no | yes |
| Fresh OSV scan | no | yes |
| Cached advisory matching | yes, if cache exists | yes |
| CISA KEV update | no | yes |
| NVD enrichment | no | yes |
| Cloud model explanation | no | optional |
| Local model explanation | yes, if local server is running | yes |
| Email/Telegram delivery | queued | yes |
| Markdown/JSON report | yes | yes |

## Scheduled Automation Feature

Hermsec should let users schedule scans.

Example commands:

```bash
hermsec schedule add ./my-project --daily 18:00 --mode auto --notify email
hermsec schedule add ./my-project --cron "0 18 * * 1-5" --notify telegram
hermsec schedule list
hermsec schedule run <schedule-id>
hermsec schedule remove <schedule-id>
```

TUI flow:

```text
Automation Setup

Project path:
> E:\work\my-project

When should Hermsec scan?
> Every weekday at 18:00

Mode:
> Auto: offline scan first, online enrichment when available

Notify:
> Email and Telegram
```

### Scheduling Implementation Options

Start with a local schedule registry:

```text
.hermsec/
  schedules.json
  queue/
  history/
```

Use two execution paths:

1. In-app scheduler while Hermsec is running.
2. OS scheduler registration for durable automation.

In-app scheduler:

- good for demo
- can use `node-cron`
- easy to start/stop from TUI
- not reliable after reboot unless the app is launched again

OS scheduler:

- Windows: Task Scheduler / `schtasks`
- macOS/Linux: cron or systemd timer
- more reliable for real use

MVP recommendation:

- build in-app scheduler for demo
- store schedules in `.hermsec/schedules.json`
- later add OS scheduler install command:

```bash
hermsec schedule install-service
```

## Agent-Aware Scan Triggers

Because this project is meant for a world where coding agents modify project files, Hermsec should have "agent-aware" triggers.

### 1. End-Of-Day Scan

Runs at a time selected by the user.

Use case:

```text
The user lets AI coding agents work during the day. At 18:00, Hermsec scans the repo and reports what changed or became risky.
```

### 2. After-Inactivity Scan

Hermsec watches file changes and runs a scan after no changes happen for a set time.

Example:

```bash
hermsec watch ./my-project --after-idle 10m
```

Use case:

```text
An agent edits files for 30 minutes. Once edits stop for 10 minutes, Hermsec scans only changed files and dependency files.
```

### 3. Git Diff Scan

Hermsec scans changed files only.

Example:

```bash
hermsec scan --changed-since HEAD~1
hermsec scan --staged
```

Use case:

```text
Before committing agent-generated changes, scan only the diff and dependency changes.
```

### 4. Pre-Push Hook

Future extension:

```bash
hermsec hooks install pre-push
```

Use case:

```text
Before code leaves the machine, Hermsec runs a lightweight scan and blocks only critical confirmed issues.
```

### 5. Agent Session Boundary

Future extension:

```bash
hermsec agent-session start ./project
hermsec agent-session finish
```

Hermsec records before/after state and scans what changed.

This is useful if the developer runs multiple coding agents and wants a security review after each work session.

## Notification And Report Delivery

Hermsec should ask how the user wants reports delivered.

Options:

- local only
- email through AgentMail
- Telegram bot
- both email and Telegram
- future: Slack/Discord/webhook

Setup flow:

```text
How should Hermsec deliver reports?

[1] Local files only
[2] Email
[3] Telegram
[4] Email and Telegram
```

## AgentMail Integration

AgentMail is a good fit because it gives an AI agent its own email inbox. According to the AgentMail docs, an inbox can send, receive, reply, forward, manage threads, send attachments, and use webhooks or WebSockets for incoming messages. The API base URL is:

```text
https://api.agentmail.to/v0/
```

Pricing research:

- Free tier currently lists 3 inboxes, 3K emails, and 3GB storage.
- Paid plans add more inboxes/storage and API/custom domain features.

Hermsec use case:

```text
Hermsec creates or uses a configured AgentMail inbox.
After a scan, it emails the report to the user.
For severe issues, it sends a short urgent message plus the full Markdown or PDF as an attachment.
```

Configuration:

```bash
hermsec notify email setup
```

Prompt flow:

```text
Email provider:
> AgentMail

Do you already have an AgentMail API key?
> yes/no

Recipient email:
> user@example.com

Send test email?
> yes
```

Environment variable:

```text
AGENTMAIL_API_KEY=am_...
```

Security rules:

- do not store API keys in project files
- prefer environment variables or OS credential storage
- let user choose whether reports include code snippets
- attach Markdown/JSON only after redacting secrets

Email report levels:

- daily digest
- critical-only alert
- full report attached
- summary with link/path to local report

## Telegram Integration

Telegram is useful for quick alerts and matches the Hermes-agent notification idea.

Setup command:

```bash
hermsec notify telegram setup
```

Guided flow:

```text
1. Open Telegram and message @BotFather.
2. Create a bot with /newbot.
3. Copy the bot token.
4. Message your new bot once with /start.
5. Hermsec verifies the bot by calling getMe.
6. Hermsec fetches recent updates to find your chat ID, or asks you to paste it.
7. Hermsec sends a test report message.
```

Environment variables:

```text
TELEGRAM_BOT_TOKEN=...
TELEGRAM_CHAT_ID=...
```

Telegram report style:

```text
Hermsec scan complete: my-project

Critical: 1
High: 2
Medium: 3
Known exploited CVEs: 1
Secrets: 0

Top action:
Upgrade package X from 1.2.0 to 1.2.5.

Full report:
E:\work\my-project\.hermsec\reports\2026-05-31.md
```

Security rules:

- do not print bot token after setup
- store token outside repo
- send concise summaries, not full private code
- optionally send Markdown as a file later

## Notification Routing Rules

Recommended defaults:

| Event | Local Report | Email | Telegram |
|---|---:|---:|---:|
| Offline scan complete | yes | queued | queued |
| Online scan no findings | yes | optional digest | no |
| Medium/high findings | yes | yes | optional |
| Critical finding | yes | yes | yes |
| Secret found | yes | yes, redacted | yes, redacted |
| Known exploited CVE | yes | yes | yes |

## Current Supply-Chain Awareness

Online mode should include a "current risk" layer.

Initial version:

- check dependency CVEs from OSV/npm/GHSA
- check if any CVE is in CISA KEV
- flag npm malware advisories when available
- warn about missing lockfile
- warn about dependency install scripts in direct dependencies/manifests if visible

Future version:

- npm provenance checks
- OpenSSF Scorecard for direct dependency source repos
- package age and recent maintainer/package changes
- newly published dependency versions used in lockfile
- package typosquatting similarity for direct dependencies
- advisories changed since last scan

## Additional Feature Ideas

### Security Delta Report

Compare current scan to previous scan:

- new findings
- fixed findings
- worsened findings
- unchanged findings

This is ideal for scheduled automation because users care what changed.

### Risk Budget

Let users set thresholds:

```bash
hermsec policy set --fail-on critical
hermsec policy set --max-high 3
```

Useful for pre-push and CI.

### Agent Change Review

If a coding agent modified files, Hermsec can generate:

```text
Security review of changes made since last clean scan.
```

This keeps scans focused and fast.

### Dependency Lockfile Guardian

Special npm/Python mode:

- detect lockfile changes
- summarize added/removed packages
- check only new package versions
- warn on missing lockfiles
- warn on direct dependency install scripts

### Redaction Preview

Before sending to a cloud model or email:

```bash
hermsec privacy preview
```

Show exactly what would leave the machine.

### Report Inbox Replies

With AgentMail receive/reply support, future Hermsec could support email replies like:

```text
Reply "details HERM-003" to get more context.
Reply "ignore HERM-004 7d" to suppress for a week.
```

This is a very agent-native feature, but keep it future scope.

### Fix PR Drafts

Future online mode could generate safe patch suggestions or PR drafts for simple dependency upgrades.

Guardrail:

- never auto-apply code fixes without confirmation
- dependency updates should be reviewed and tested

### SBOM Export

Generate CycloneDX SBOM when possible and include it in reports.

This makes the project more serious and links to modern supply-chain security practice.

### Local Dashboard

Later:

```bash
hermsec dashboard
```

Shows scan history, trends, and open findings in browser.

## Revised Product Modes

Hermsec should have four user-facing modes:

### 1. Manual Scan

```bash
hermsec scan ./project
```

Immediate scan.

### 2. Watch Mode

```bash
hermsec watch ./project --after-idle 10m
```

Scan after coding/agent activity settles.

### 3. Scheduled Mode

```bash
hermsec schedule add ./project --daily 18:00
```

Scan at the user's chosen time.

### 4. Sync Mode

```bash
hermsec sync
```

Take offline scans and enrich/send them when online.

## Updated MVP Recommendation

For the first presentable build:

1. Manual scan of local path.
2. Offline/online mode flag.
3. Markdown and JSON report.
4. Simple schedule registry and in-app scheduled scan.
5. Notification preference setup, local-only first.
6. Telegram test message or AgentMail test email if time allows.
7. Offline queue for reports that could not be sent.

Do not start with full daemon/service complexity. Present it as future extension after the demo works.

## Sources

- AgentMail inbox capabilities: https://docs.agentmail.to/knowledge-base/inbox-capabilities
- AgentMail API welcome/base URL: https://docs.agentmail.to/api-reference
- AgentMail quickstart: https://www.agentmail.to/docs/quickstart
- AgentMail pricing/free tier: https://agentmail.to/pricing
- Telegram Bot API: https://core.telegram.org/bots/api
- node-cron docs: https://www.nodecron.com/
- node-cron background tasks: https://nodecron.com/background-tasks.html

