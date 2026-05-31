# Hermsec Project Context

## Purpose

Hermsec is a local-first, CVE-aware AI security assistant for repositories. The first build target is manual mode: a user provides a local repository path or GitHub URL, Hermsec runs defensive scanners, normalizes the evidence, optionally asks a bring-your-own model to explain the findings, and writes terminal, Markdown, and JSON reports.

## Current Implementation Status

Hermsec now has a working local MVP scaffold:

- TypeScript CLI package with `hermsec` bin.
- Chatbot-style TUI entry point with safe non-interactive fallback.
- Local offline scan harness with repository discovery and built-in heuristics for secrets, JS/TS, Python, package/lockfile, and config/supply-chain patterns.
- JSON-backed app data, user config, workspaces, schedules, sessions, report indexes, and security-intel cache.
- Deterministic local JSON/Markdown/HTML reports with redaction, evidence bundles, and delta artifacts.
- Restricted model/provider layer with env-only credentials and no-model fallback.
- Evaluation matcher/metrics for precision, recall, F1, category/confusion scoring, and safe vulnerable/clean fixture repos.
- Local install verified with `npm link --ignore-scripts`; `hermsec --version`, `hermsec doctor`, and `hermsec scan` work from PATH.

Latest verified commands:

```text
npm run build
npm test
npm link --ignore-scripts
hermsec --version
hermsec doctor --json
hermsec scan tests\fixtures\repos\node-express-vulnerable --mode offline --out .hermsec\installed-reports-2 --json
```

Current verified test status: `18` Node tests passing, `0` failing, `0` skipped.

Known local shortcomings:

- Optional external scanners are not installed on this PC: PMG, Bandit, Semgrep, Gitleaks, OSV-Scanner, and pip-audit are reported as warnings.
- The MVP uses built-in offline heuristics; external scanner execution and live online advisory enrichment are still future integration work.
- Model-assisted explanations are scaffolded but not part of the verified local workflow because provider credentials are intentionally env-only and were not used.
- The benchmark/evaluation runner works on generated fixture suites, not yet on downloaded official OWASP/NIST benchmark corpora.

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

1. Add optional external scanner execution behind the existing safe process policy.
2. Expand online advisory enrichment and cache freshness controls.
3. Connect model-assisted report explanations to the verified scan/report workflow while preserving redaction and grounded-output validation.
4. Add official OWASP/NIST benchmark acquisition behind explicit opt-in commands.
5. Improve evaluation precision by tuning generated fixture ground truth and duplicate finding handling.
6. Add OS-level schedule registration if needed; current scheduler storage and manual `schedule run` work locally.
7. Add AgentMail and Telegram later, after the local MVP.
8. Add Hermes Agent or VPS/GitHub adapter after the Hermsec core is stable.
9. Create demo presentation materials from the verified local run.
