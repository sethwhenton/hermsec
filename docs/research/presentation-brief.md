# Hermsec Presentation Brief

Date: 2026-05-31

## One-Sentence Pitch

Hermsec is a local-first AI security assistant that scans a GitHub repository or local codebase, combines evidence from static analysis and vulnerability databases, and produces a developer-friendly report with severity, CVE/CWE context, confidence, and suggested fixes.

## The Core Story

Developers already have scanners, but scanner output is scattered, noisy, and hard to prioritize.

Hermsec solves this by acting as an evidence coordinator:

1. It runs existing security tools.
2. It checks package versions against advisory databases.
3. It normalizes everything into one finding format.
4. It asks a model to explain the evidence, not invent new claims.
5. It writes a report that a developer can act on.

The strongest phrase for the presentation:

```text
Scanners find evidence. The model explains evidence.
```

## What Manual Mode Does

Manual mode is the first version.

User flow:

```text
User opens Hermsec TUI
User enters GitHub URL or local path
User chooses manual, scheduled, or watch mode
Hermsec prepares a scan workspace
Hermsec detects language and dependency files
Hermsec runs scanners
Hermsec enriches CVE/advisory data
Hermsec asks the selected model for explanations
Hermsec produces terminal, Markdown, and JSON reports
Hermsec can optionally notify through email or Telegram
```

Example commands:

```bash
hermsec scan ./examples/vulnerable-python-app
hermsec scan https://github.com/team/repo --md report.md --json report.json
hermsec
```

## Slide Outline

### Slide 1: Problem

Title: Developers ship fast, security feedback is scattered

Points:

- Security checks are often manual or delayed.
- Existing tools produce raw technical output.
- Dependency CVEs, code smells, and leaked secrets live in separate reports.
- Developers need prioritized, understandable next steps.

Speaker line:

```text
The problem is not that security tools do not exist. The problem is that their output is fragmented and hard to act on quickly.
```

### Slide 2: Solution

Title: Hermsec TUI

Diagram:

```text
GitHub URL / Local Repo
        |
        v
Hermsec Scan Engine
        |
        +-- Code scan: Bandit, Semgrep
        +-- Secret scan: Gitleaks
        +-- Dependency scan: npm audit, pip-audit, OSV-Scanner
        +-- Advisory context: OSV, GitHub Advisories, NVD, CISA KEV
        |
        v
AI Explanation Layer
        |
        v
Markdown + JSON + TUI Report
```

Speaker line:

```text
Hermsec is not trying to replace scanners. It is trying to coordinate them and make their evidence understandable.
```

### Slide 3: Manual Mode Demo

Title: How the user runs it

Show:

```text
HERMSEC

Target:
> ./examples/vulnerable-python-app

Plan:
[x] Bandit
[x] Semgrep
[x] Gitleaks
[x] pip-audit
[x] OSV-Scanner

Model:
Ollama local / OpenRouter / no model
```

Then show final summary:

```text
Findings:
Critical: 1
High: 2
Medium: 1
Secrets: 1
Known exploited CVEs: 0

Report written:
reports/hermsec-report.md
reports/hermsec-report.json
```

### Slide 4: Evidence Sources

Title: Where Hermsec gets security truth

Sources:

- npm audit for npm package advisories
- OSV.dev / OSV-Scanner for multi-ecosystem vulnerability checks
- GitHub Advisory Database for CVEs, GHSAs, and npm malware advisories
- NVD for CVSS/CWE enrichment
- CISA KEV for exploited-in-the-wild prioritization
- Bandit/Semgrep/Gitleaks for local code evidence

Speaker line:

```text
Known vulnerable packages come from advisory databases. Code-level risks come from static analysis. The model is only allowed to explain what those sources found.
```

### Slide 5: Model Role

Title: The model is grounded, not trusted blindly

Model receives:

- finding JSON
- scanner message
- advisory IDs
- small code snippet if allowed

Model returns:

- plain-language impact
- suggested fix
- confidence reason
- safe next steps

Guardrails:

- no invented CVEs
- no exploit instructions
- no full private repo sent by default
- secrets redacted

Speaker line:

```text
If a CVE is not in the evidence, Hermsec will not let the model pretend it exists.
```

### Slide 6: Access And Privacy

Title: Public, private, and local repositories

Public:

- clone read-only into a temp workspace

Private:

- prefer local clone
- or use existing `gh auth`
- or use SSH/PAT already configured by the user

Privacy:

- local model option
- cloud model warning
- snippets only, never whole repo by default
- no token storage

Speaker line:

```text
For private code, the safest path is scanning a local clone and using a local model.
```

### Slide 7: Build Plan

Title: Implementation phases

Phases:

1. CLI scan skeleton
2. GitHub/local workspace prep
3. repository discovery
4. scanner wrappers
5. normalized finding schema
6. advisory enrichment
7. model explanation
8. reports
9. TUI wrapper
10. scheduled scans and notification setup
11. demo apps and final presentation

Speaker line:

```text
We build the reusable scan engine first, then the TUI. That keeps the project real beyond the demo.
```

### Slide 8: Why This Is A Good Project

Title: Practical, current, and defensible

Points:

- Uses current security topics: supply-chain risk, CVEs, npm malware, leaked secrets, AI-assisted development.
- Does not require training a large model.
- Uses existing trusted tools.
- Produces a visible demo.
- Has clear future extensions: Hermes scheduled agent, GitHub Actions, pre-push hooks, daily reports.
- Can support offline local scans and online enriched scans.
- Can deliver reports through local files, email, or Telegram.

Speaker line:

```text
Hermsec is realistic for our resources because the hard detection work comes from established tools, while our contribution is orchestration, evidence normalization, AI explanation, and developer workflow.
```

## Demo Script

### Setup

Use a controlled local vulnerable repo:

```bash
hermsec scan ./examples/vulnerable-python-app --md reports/demo.md --json reports/demo.json
```

Expected demo findings:

- SQL injection or command injection pattern
- hardcoded fake secret
- old vulnerable dependency
- Semgrep custom rule finding

### Live Walkthrough

1. Start the TUI.
2. Enter local demo repo path.
3. Show scanner plan.
4. Run scan.
5. Open top finding.
6. Show evidence and model explanation.
7. Open Markdown report.

### What To Say If A Tool Is Missing

```text
Hermsec is designed to degrade gracefully. If a scanner is not installed, it records that scanner as skipped and continues with the rest of the evidence.
```

## Expected Questions And Answers

### Are we building a TUI or a CLI?

Both, but in the right order. The CLI scan engine is the core. The TUI is the interactive wrapper for the user and the presentation.

### How do we scan private GitHub repositories?

We do not bypass access. The user must already have access through a local clone, GitHub CLI authentication, SSH, or a read-only token. Hermsec should not store GitHub tokens.

### Where do npm vulnerability updates come from?

From npm audit, OSV.dev, and GitHub Advisory Database. GitHub Advisory Database also includes npm malware advisories. NVD and CISA KEV enrich priority and CVE details.

### What is offline mode?

Offline mode runs local scanners and saves reports locally. It queues advisory enrichment and notifications for later because fresh npm/OSV/NVD/CISA lookups require internet access.

### What is online mode?

Online mode runs local scanners plus fresh vulnerability lookups, supply-chain advisory checks, model explanations, and optional email or Telegram delivery.

### How do scheduled scans work?

The user picks a time, such as every weekday at 18:00. Hermsec scans the project, stores the report locally, and sends notifications if online. If offline, it queues the report and syncs later.

### Are we just running static analysis?

No. Static analysis is one layer. Hermsec combines SAST, secret scanning, dependency vulnerability scanning, advisory enrichment, model explanation, and reporting.

### When does the model take over?

After scanner evidence exists. The model explains, deduplicates, prioritizes, and suggests fixes. It does not decide CVE truth by itself.

### Why not train our own vulnerability model?

Training a useful security model is expensive and hard to evaluate. For this project, using established scanners plus a grounded explanation model is more realistic and more defensible.

### How do we avoid model hallucination?

We use evidence-only prompts, structured output, and code-level guardrails that only permit CVEs from scanner/advisory evidence.

### What makes this different from running Bandit or Semgrep directly?

Hermsec combines multiple sources, deduplicates findings, adds dependency CVE context, prioritizes known exploited vulnerabilities, and explains fixes in one report.

## Strong Final Statement

```text
Hermsec turns raw security scanner output into a developer-ready security review. It is local-first, evidence-grounded, and practical enough to demo now, while leaving room for future Hermes scheduled-agent integration.
```
