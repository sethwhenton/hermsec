# Hermsec Project Context

## Purpose

Hermsec is a local-first, CVE-aware AI security assistant for repositories. The first build target is manual mode: a user provides a local repository path or GitHub URL, Hermsec runs defensive scanners, normalizes the evidence, optionally asks a bring-your-own model to explain the findings, and writes terminal, Markdown, and JSON reports.

## Current Decision

Build the CLI scan engine first, then put a TUI on top of it. The TUI is for the demo and day-to-day ergonomics; the CLI engine is the reusable core for future CI, pre-push, and Hermes background modes.

## Current Research Artifacts

Read this before implementation:

```text
docs/research/manual-mode-start-to-finish.md
docs/research/automation-online-offline-notifications.md
docs/research/tui-onboarding-harness-plan.md
```

These contain the end-to-end architecture, scanner choices, vulnerability intelligence sources, GitHub access strategy, model role, data schema, automation and notification design, TUI onboarding plan, harness boundary, implementation phases, and presentation plan.

## Planned Stack

- TypeScript for CLI, TUI, orchestration, normalization, reports, and model providers.
- Custom Hermsec harness as the core engine.
- TUI and CLI as two frontends over the same core.
- Hermes Agent integration later through an adapter that calls Hermsec, not as an MVP dependency.
- Scanner CLIs for evidence:
  - Bandit
  - Semgrep
  - Gitleaks
  - pip-audit
  - npm audit
  - OSV-Scanner
- Bring-your-own model providers:
  - OpenRouter
  - Ollama
  - LM Studio or any OpenAI-compatible local endpoint
  - no-model fallback
- Optional automation and notification features:
  - scheduled scans
  - watch/after-idle scans
  - offline queue and online sync
  - AgentMail email reports
  - Telegram report alerts

## Safety Rules

- Do not install project dependencies during scanning by default.
- Do not run package lifecycle scripts by default.
- Prefer lockfile scanning.
- Do not invent CVEs. CVEs must come from scanner or advisory evidence.
- Do not send full private repositories to cloud models by default.
- Redact secrets before model calls and report output.
- Keep the project defensive: scan, explain, prioritize, and suggest fixes.

## Next Work

1. Initialize the local Hermsec folder as a git repository and connect it to `https://github.com/sethwhenton/Security-insider-Lab-II.git`.
2. Create the TypeScript project skeleton.
3. Implement `hermsec doctor`.
4. Implement `hermsec scan <target>` with local path metadata only.
5. Add onboarding prompts for privacy mode, project source, scanner readiness, report destination, notifications, and schedule choice.
6. Add GitHub URL clone-to-temp support.
7. Add repository discovery and scanner plan.
8. Add scanner wrappers one at a time.
9. Normalize findings into the shared schema.
10. Add Markdown/JSON reports.
11. Add TUI dashboard, scan progress, findings list, finding detail, and report center.
12. Add model explanation.
13. Add scheduled/offline/online mode support.
14. Add notification setup for local files, AgentMail email, and Telegram.
15. Add Hermes Agent adapter after the Hermsec core is stable.
16. Create demo vulnerable repos and presentation materials.
