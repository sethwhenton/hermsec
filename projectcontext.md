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
docs/research/local-mode-chat-agent-intel-plan.md
implementationplan.md
```

These contain the end-to-end architecture, scanner choices, vulnerability intelligence sources, GitHub access strategy, model role, data schema, local-mode chat agent plan, workspace/session model, git-aware scheduler, harness boundary, implementation phases, benchmark evaluation plan, testing plan, and presentation plan.

## Planned Stack

- TypeScript for CLI, TUI, orchestration, normalization, reports, and model providers.
- Custom Hermsec harness as the core engine.
- Chat TUI and CLI as two frontends over the same core.
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
  - local report directory configuration
  - security intelligence feed
  - AgentMail and Telegram later, after the local MVP

## Safety Rules

- Do not install project dependencies during scanning by default.
- Do not run package lifecycle scripts by default.
- Prefer lockfile scanning.
- Do not invent CVEs. CVEs must come from scanner or advisory evidence.
- Do not send full private repositories to cloud models by default.
- Redact secrets before model calls and report output.
- Keep the project defensive: scan, explain, prioritize, and suggest fixes.

## Next Work

1. Follow `implementationplan.md` as the source of truth for workstream ownership, implementation phases, schemas, tool contracts, and test coverage.
2. Create the TypeScript project skeleton with `.npmrc` hardening and no lifecycle install scripts.
3. Implement app-data storage, workspaces, sessions, and local report destination config.
4. Implement `hermsec doctor`.
5. Implement `hermsec scan <target>` with local path metadata only.
6. Add repository discovery, scanner planning, and safe process execution.
7. Add one scanner wrapper at a time, beginning with a fixture-backed scanner path.
8. Normalize findings into the shared schema.
9. Add HTML/Markdown/JSON local report rendering and report index.
10. Add chatbot-first TUI onboarding, dashboard, scan progress, findings list, finding detail, and report center.
11. Add restricted agent runtime, provider router, redaction, and structured-output validation.
12. Add scheduled/offline/online mode support with git-aware baselines.
13. Add security intelligence update and Vibe Coder Security Feed.
14. Add evaluation benchmarks, generated vulnerable fixtures, metrics runner, scorecards, and final-report evidence outputs.
15. Add AgentMail and Telegram later, after the local MVP.
16. Add Hermes Agent or VPS/GitHub adapter after the Hermsec core is stable.
17. Create demo vulnerable repos and presentation materials.
