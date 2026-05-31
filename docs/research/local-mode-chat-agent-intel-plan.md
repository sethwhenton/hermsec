# Hermsec Local Mode Chat Agent And Security Intel Plan

Date: 2026-05-31

## Product Identity

Hermsec is the security agent for vibe coders.

It is meant for developers who use AI coding agents, move quickly, and need a local security companion that watches projects, understands git changes, runs safe scanners, and explains risks clearly.

The local version should run on the user's machine first. A VPS mode can come later.

## Current Local Mode Scope

For now, remove report delivery through Telegram and AgentMail from the local MVP.

Reports should be saved locally only.

The user must be able to configure the report destination during onboarding and later through chat or config.

Example:

```text
Hermsec: Where should I save reports for this workspace?

> D:\Hermsec Reports
  ./hermsec-reports
  Ask every scan
  Use default app folder
```

Example output layout:

```text
D:\Hermsec Reports\
  ecommerce-api\
    2026-05-31_09-00-00\
      report.html
      report.md
      summary.json
      findings.json
      evidence.json
      agent-summary.json
```

Notifications can return later after the core local experience is stable.

## Experience Goal

Running:

```powershell
hermsec
```

should open a chatbot-style terminal app.

The user should talk to Hermsec:

```text
scan this folder
watch this repo every morning
explain the high findings
save reports to D:\Security Reports
use Ollama for private explanations
show me today's security news for this stack
```

Hermsec should feel like a small OpenCode-style agent, but it should be security-specific and heavily restricted.

## Architecture

```text
User chat
  |
  v
Hermsec chat TUI
  |
  v
Restricted agent loop
  |
  +-- intent router
  +-- workspace/session manager
  +-- allowed tool dispatcher
  +-- provider router
  |
  v
Hermsec harness
  |
  +-- git change detector
  +-- repository inventory
  +-- scanner scripts
  +-- vulnerability intelligence cache
  +-- finding normalizer
  +-- report renderer
  +-- local scheduler
```

The scanners and scripts do the security work.

The agent explains evidence, asks the user questions, and writes summaries.

## Agent Boundary

The agent is not a general coding agent.

Allowed:

- talk with the user
- select a workspace
- ask approved Hermsec tools to run
- read normalized scan results
- read selected snippets through the Hermsec read tool
- explain findings
- summarize security news from trusted feeds
- write report narrative sections
- manage local schedules through the scheduler tool

Not allowed in MVP:

- edit source code
- run arbitrary shell commands
- install packages
- execute dependency lifecycle scripts
- read files outside the selected workspace
- read secrets directly
- send private code to cloud models without explicit permission
- invent CVEs or advisory IDs
- mark findings fixed without a new scan

The model can suggest. The harness decides what is safe.

## Pi Assessment

Pi is a minimal terminal coding harness. Its docs describe it as small at the core and extensible through TypeScript extensions, skills, prompt templates, themes, and packages. It has sessions, providers, settings, custom models, custom providers, SDK usage, RPC mode, JSON event stream mode, and TUI components.

Pi is interesting for Hermsec because it already has concepts we want:

- sessions
- project settings
- skills
- prompt templates
- provider setup
- extensions
- JSON event streams
- TUI components

The `pi-agents` package is more advanced: it supports markdown-defined agents, workflows, runs, persisted flows, subprocess isolation, sequences, forks, joins, loops, and mermaid export.

However, Hermsec does not need a broad multi-agent coding system for the local MVP.

Recommended use of Pi:

- Use Pi as inspiration for sessions, skills, and event streams.
- Consider Pi integration only if we want to run Hermsec as a Pi extension or package.
- Do not depend on `pi-agents` for the scanner core.

Pi can be a future host. Hermsec's security harness should remain ours.

## OpenRouter Agent TUI Assessment

OpenRouter's "Build Your Own Agent TUI" cookbook is a strong fit for the TUI scaffold.

It creates a TypeScript terminal agent project and uses `@openrouter/agent` for:

- model calls
- tool execution
- multi-turn loops
- stop conditions
- streaming
- shared context
- cost tracking

The cookbook also supports customizable tool display, input styles, session persistence, slash commands, and optional HTTP API entry points.

The warning for Hermsec:

The default generated tool set includes broad coding-agent tools such as file write, edit, shell, and directory search. Hermsec must not ship with those defaults enabled.

Recommended use:

- Use the OpenRouter TUI cookbook as a scaffold or design blueprint.
- Keep only restricted Hermsec tools.
- Disable file write, edit, shell, generic web fetch, sub-agent spawn, and arbitrary JS REPL.
- Add custom Hermsec tools for scan, report, schedule, workspace, and intel.

If we use `@openrouter/agent`, OpenRouter becomes the easiest model route. If we want direct user API keys for OpenAI, Claude, Gemini, Ollama, and OpenCode Go, we may still need a provider router outside OpenRouter.

Best practical path:

1. Start with a TypeScript chat TUI inspired by OpenRouter's scaffold.
2. Use our own restricted tool registry.
3. Support OpenRouter as one provider.
4. Add direct provider adapters after the core loop works.

## Agent Runtime Recommendation

Use our own restricted Hermsec harness as the center.

Use one of these two approaches:

### Option A: OpenRouter Agent TUI Scaffold

Pros:

- fastest path to a working chat TUI
- TypeScript
- built-in agent loop
- streaming and session persistence
- customizable terminal UI

Cons:

- OpenRouter-first
- default tools must be removed
- direct provider support needs extra adapter work

Recommended if we want speed.

### Option B: Custom Mini Agent Loop

Pros:

- maximum control
- direct support for OpenAI, Claude, Gemini, Ollama, OpenCode Go, OpenRouter
- smallest safety surface
- no unwanted coding-agent tools

Cons:

- more code to build
- need to implement streaming/session persistence ourselves

Recommended if we want long-term product control.

### Decision

For MVP, use OpenRouter's TUI cookbook as a reference or scaffold, but keep Hermsec's tool system locked down.

If the scaffold stays clean after we remove broad tools, we can use it directly.

If it pulls in too much, build our own mini loop.

## Provider Plan

Initial providers:

- OpenRouter
- OpenAI
- Anthropic Claude
- Google Gemini
- Ollama
- OpenCode Go

Provider setup happens during onboarding or later through chat.

Example:

```text
User: use Ollama
Hermsec: I will check whether Ollama is running locally.
Hermsec: I found llama3.1 and qwen2.5-coder. Which model should explain findings?
```

Example:

```text
User: use OpenAI
Hermsec: I need an OpenAI API key. I will not store it in this repository.
Hermsec: Choose key storage: environment variable, OS credential store, or this session only.
```

Provider credentials must never be committed to git.

## Sessions And Work Directories

Hermsec should manage workspaces like a coding-agent TUI, but security-focused.

Definitions:

```text
Workspace
  A repository or folder Hermsec protects.

Session
  A chat/security-review conversation tied to one workspace.

Profile
  Saved workspace configuration.
```

Home screen:

```text
Hermsec Workspaces

> ecommerce-api
  E:\Projects\ecommerce-api
  Last scan: today 09:02
  Status: 1 high, 3 medium

  portfolio-site
  E:\Projects\portfolio
  Last scan: yesterday
  Status: clean

  add new workspace
```

Each workspace profile stores:

- project path
- display name
- report directory
- scan mode
- schedule rules
- last scanned commit
- ignored findings
- model provider preference
- privacy mode
- security-news interests

Each chat session stores:

- messages
- tool calls
- scan IDs discussed
- finding IDs discussed
- user decisions
- summaries for compaction

## Local Git-Aware Scheduled Scans

The scheduler should use git to avoid unnecessary scans.

Example request:

```text
User: every day at 9am check this repo for changes and scan it if changed
```

Hermsec creates:

```json
{
  "workspaceId": "ecommerce-api",
  "schedule": "0 9 * * *",
  "mode": "auto",
  "changePolicy": "scan-if-git-changed",
  "lastScannedCommit": "abc123"
}
```

At 09:00:

1. Check that the workspace path exists.
2. Check that it is still a git repo.
3. Read current branch and HEAD.
4. Compare with last scanned commit.
5. If no change, log "skipped, no git changes".
6. If changed, list changed files.
7. Classify changes.
8. Choose scan depth.
9. Run scanners.
10. Save local report.
11. Update last scanned commit only after a successful scan.

Change classification:

```text
dependency files changed
  package.json, package-lock.json, pnpm-lock.yaml, requirements.txt, poetry.lock
  -> dependency scan plus supply-chain checks

security-sensitive files changed
  auth, middleware, config, env templates, docker, CI, permissions
  -> static scan plus high-attention review

source files changed
  -> changed-file static scan

docs only changed
  -> skip or light scan
```

## Error Handling

Hermsec should fail usefully.

Examples:

```text
Workspace missing
  The folder no longer exists. Keep the schedule disabled until the user fixes the path.

Git missing
  Run a full folder scan if allowed, otherwise explain that git change detection is unavailable.

Repo has no commits
  Run initial scan and store baseline.

Scanner missing
  Mark scanner as unavailable, continue with other scanners, and show install guidance.

Network offline
  Run local scanners, use cached advisories, skip fresh intel update.

Model unavailable
  Generate scanner-only report and mark explanation as skipped.

Report destination unavailable
  Fall back to app data report directory and show the user where the report was saved.
```

Every scheduled run should have a run log:

```text
.hermsec/runs/<run-id>/run.json
```

## Local Report Generation

Report generation should be mostly deterministic.

Scripts generate:

- scan metadata
- scanner status
- normalized findings
- severity counts
- advisory links
- changed file list
- raw evidence paths

The agent generates:

- executive summary
- developer-friendly explanation
- prioritized next actions
- "what changed since last scan"
- security-news relevance note

The renderer creates:

- `report.html`
- `report.md`
- `summary.json`
- `findings.json`
- `evidence.json`

The HTML should use a stable template. The agent fills content, not layout.

## Security Intelligence Layer

Hermsec needs two types of security information:

1. Project-specific vulnerability data.
2. General security news for vibe coders.

Do not let an agent freely search the web on a timer.

Use deterministic API/RSS fetchers first. The agent summarizes only after the data is fetched and normalized.

## Machine-Readable Vulnerability Sources

### OSV.dev

Use for package vulnerability matching across open-source ecosystems.

Use cases:

- query package name and version
- batch query dependency inventories
- retrieve OSV vulnerability records

Recommended priority: very high.

### GitHub Advisory Database

Use for GitHub Security Advisories and CVE/GHSA data across ecosystems.

Use cases:

- advisory enrichment
- package vulnerability checks
- GitHub ecosystem-specific context
- local clone of advisory database if needed

Recommended priority: high.

### NVD CVE API

Use for CVE enrichment, CVSS, CPE, references, published dates, modified dates, and broader vulnerability context.

Use cases:

- enrich CVE IDs from scanners
- fetch recent CVEs
- support news dashboard

Recommended priority: high, but avoid relying on NVD alone for package-version matching.

### CISA KEV Catalog

Use for prioritization.

If a CVE is in CISA KEV, Hermsec should raise urgency because the vulnerability is known to be exploited in the wild.

Recommended priority: very high.

### FIRST EPSS

Use for exploitation probability.

EPSS helps rank CVEs beyond CVSS by estimating how likely a CVE is to be exploited.

Recommended priority: high.

### npm Audit

Use for npm projects when the user allows registry queries.

Use cases:

- audit npm dependency tree
- compare with OSV and GitHub advisories

Privacy note:

`npm audit` submits dependency information to the configured registry. Hermsec should disclose this before running in privacy-sensitive mode.

### deps.dev

Use for dependency graph, package metadata, licenses, advisories, and release information.

Recommended priority: medium-high.

### GitLab Advisory Database

Use as supplemental advisory data.

Note:

GitLab states its open-source edition is delayed relative to the main database.

Recommended priority: medium.

### OpenSSF Scorecard

Use for open-source dependency health and repository security posture.

Use cases:

- risky dependency context
- unmaintained or weakly secured upstream projects
- supply-chain risk notes

Recommended priority: medium.

### endoflife.date

Use to detect unsupported runtimes and frameworks.

Use cases:

- Node.js EOL
- Python EOL
- Django, Angular, PHP, PostgreSQL, Redis, etc.

Recommended priority: medium.

### Sigstore Rekor

Use later for provenance and signature checks.

Recommended priority: future.

## Security News Sources

The news section should be called:

```text
Vibe Coder Security Feed
```

It should show items relevant to the user's stack.

Initial trusted feed sources:

- CISA Cybersecurity Alerts and Advisories RSS
- CISA KEV JSON changes
- OpenSSF blog
- GitHub Blog supply-chain-security tag
- GitHub Advisory Database recent advisories
- OSV recently modified vulnerabilities
- NVD recently published/modified CVEs
- Socket alerts, if API access is available
- Phylum intelligence, if API access is available
- vendor security feeds based on detected stack

Vendor feeds should be selected by project inventory:

```text
Node project
  Node.js security releases, npm audit, OSV, GHSA, Socket optional

Python project
  Python security releases, PyPI advisories through OSV/GHSA, pip-audit

Next.js project
  Next.js/Vercel advisories, npm ecosystem feeds

Docker/Kubernetes project
  Docker, Kubernetes, CISA, NVD, OSV

GitHub Actions-heavy project
  GitHub Actions advisories, GitHub blog, CISA, OpenSSF
```

## News Matching

Hermsec should not show every security story.

It should match news against:

- package names in the repo
- package ecosystems
- runtime versions
- frameworks
- GitHub Actions used
- Docker images
- CI/CD tools
- known findings from previous scans
- KEV and EPSS severity

Example:

```text
Hermsec: Today's relevant security feed

1. New CISA KEV item affects a package family similar to one in this workspace.
2. OSV added a high severity advisory for a transitive npm dependency you use.
3. Node.js 20 remains supported; Node.js 18 is approaching EOL.
```

## Intel Update Flow

Command:

```powershell
hermsec intel update
```

Chat:

```text
User: update security news
```

Flow:

1. Fetch trusted API/RSS sources.
2. Store raw source snapshots.
3. Normalize into `SecurityIntelItem`.
4. Deduplicate by CVE/GHSA/OSV/source URL.
5. Enrich with KEV and EPSS where possible.
6. Match against workspace inventory.
7. Cache locally.
8. Let the agent summarize relevant items.

## Normalized Intel Schema

```ts
type SecurityIntelItem = {
  id: string;
  source: "osv" | "github-advisory" | "nvd" | "cisa-kev" | "epss" | "rss" | "socket" | "phylum" | "vendor";
  title: string;
  summary?: string;
  url: string;
  publishedAt?: string;
  modifiedAt?: string;
  identifiers: {
    cve?: string[];
    ghsa?: string[];
    osv?: string[];
  };
  ecosystems: string[];
  packages: string[];
  affectedVersions?: string[];
  fixedVersions?: string[];
  severity?: "critical" | "high" | "medium" | "low" | "unknown";
  cvss?: number;
  epss?: number;
  cisaKev?: boolean;
  tags: string[];
  relevance?: {
    workspaceId: string;
    reason: string;
    score: number;
  };
};
```

## Local App Data

Use app-level storage for Hermsec's own state.

Windows:

```text
%APPDATA%\Hermsec\
  config.json
  workspaces.json
  sessions\
  intel\
  schedules.json
  logs\
```

Project-local `.hermsec` should be optional.

Ask before writing into a user's repo.

## Local MVP Build Order

1. `hermsec` opens chat TUI.
2. Onboarding creates first workspace.
3. User selects report directory.
4. Workspace/session manager works.
5. Git change detector works.
6. Manual scan through harness works.
7. Report renderer saves local HTML/Markdown/JSON.
8. Scheduled git-aware scan works.
9. Agent explains scanner findings.
10. Security intel update fetches OSV, GHSA, NVD, CISA KEV, EPSS.
11. Vibe Coder Security Feed summarizes relevant news.
12. Provider router adds OpenRouter/OpenAI/Claude/Gemini/Ollama/OpenCode Go.

## Final Recommendation

Use the OpenRouter agent TUI cookbook as a reference or scaffold, but keep Hermsec's tool system locked down.

Use Pi as inspiration for sessions, skills, packages, and event streams. Do not make Pi required for the first local MVP.

Build Hermsec as:

```text
restricted chat agent
+ local workspace/session manager
+ git-aware scheduler
+ scanner harness
+ local report renderer
+ curated security-intel feed
```

That gives us a focused product: a local security agent for vibe coders.

## Sources

- Pi docs: https://pi.dev/docs/latest
- Pi agents package: https://pi.dev/packages/pi-agents
- OpenRouter Agent TUI cookbook: https://openrouter.ai/docs/cookbook/building-agents/create-agent-harness-tui
- OpenRouter Agent SDK: https://openrouter.ai/docs/agent-sdk/overview
- OSV API: https://google.github.io/osv.dev/api/
- GitHub Advisory Database repository: https://github.com/github/advisory-database
- GitHub GraphQL security advisories: https://docs.github.com/en/graphql/reference/security-advisories
- NVD CVE API: https://nvd.nist.gov/developers/vulnerabilities
- CISA KEV catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- FIRST EPSS: https://www.first.org/epss/
- npm audit docs: https://docs.npmjs.com/cli/audit/
- deps.dev: https://deps.dev/
- GitLab Advisory Database: https://docs.gitlab.com/user/application_security/gitlab_advisory_database/
- OpenSSF Scorecard: https://openssf.org/scorecard/
- endoflife.date API: https://endoflife.date/docs/api
- Sigstore Rekor: https://docs.sigstore.dev/logging/overview/
- CISA RSS updates: https://www.cisa.gov/about/contact-us/subscribe-updates-cisa
- Socket alerts: https://socket.dev/alerts
- Phylum docs: https://docs.phylum.io/

