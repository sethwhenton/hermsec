# Hermsec Project Context

## Purpose

Hermsec is a local-first, CVE-aware AI security assistant for repositories. The first build target is manual mode: a user provides a local repository path or GitHub URL, Hermsec runs defensive scanners, normalizes the evidence, optionally asks a bring-your-own model to explain the findings, and writes terminal, Markdown, and JSON reports.

## Current Implementation Status

Hermsec now has a hardened local production-readiness milestone:

- TypeScript CLI package with `hermsec` bin.
- Chatbot-style TUI entry point with safe non-interactive fallback.
- Local scan harness with repository discovery, built-in heuristics for secrets, JS/TS, Python, package/lockfile, and config/supply-chain patterns, plus optional external scanner execution.
- JSON-backed app data, user config, workspaces, schedules, sessions, report indexes, and security-intel cache.
- Deterministic local JSON/Markdown/HTML reports with redaction, evidence bundles, and delta artifacts.
- Restricted model/provider layer with env-only credentials, safe credential-reference validation, non-secret provider verification fingerprints, and no-model fallback.
- Evaluation matcher/metrics for precision, recall, F1, category/confusion scoring, duplicate-noise classification, and safe vulnerable/clean fixture repos.
- Online security intelligence has deterministic trusted-source fetchers for CISA KEV, OSV.dev, GitHub Advisory Database, and NVD, plus source TTL/cache metadata and offline fallback behavior.
- Verified model-backed report explanations through the env-only Gemini provider path; OpenAI-compatible, OpenAI, OpenRouter, Claude, OpenCode Go, Ollama, and no-model adapters are wired through the same router.
- Local install verified with `npm link --ignore-scripts`; `hermsec --version`, `hermsec doctor`, and `hermsec scan` work from PATH.

Latest verified commands:

```text
npm run build
npm test
node dist/src/bin/hermsec.js doctor --json
node dist/src/bin/hermsec.js intel update --source cisa-kev
node dist/src/bin/hermsec.js intel update --source nvd
node dist/src/bin/hermsec.js scan tests\fixtures\repos\node-express-vulnerable --mode online --out .hermsec\production-hardening-node --json --md --html --no-model
node dist/src/bin/hermsec.js scan tests\fixtures\repos\python-flask-vulnerable --mode online --out .hermsec\production-hardening-python --json --no-model
node dist/src/bin/hermsec.js scan tests\fixtures\repos\node-express-vulnerable --mode online --out .hermsec\verify-model-reports --json --md --html
node dist/src/bin/hermsec.js eval run --mode scanner-only --out .hermsec\verify-eval
```

Current verified scanner/tool status on this PC: Semgrep, Gitleaks, Bandit, OSV-Scanner, and pip-audit are installed and detected by `doctor`; SafeDep PMG is still missing and reported as a recommended warning because machine-level PMG setup needs explicit approval.

Current verified intel status: CISA KEV live update cached `1607` items, NVD bounded live update cached `47` recent CVEs, and offline cache reuse works.

Current full-suite status on May 31, 2026: `npm test` builds successfully and runs `40` Node tests; `40` pass, `0` fail, and `0` skip.

Current verified eval status: the Node vulnerable fixture scanner-only run reports precision `1.00`, recall `1.00`, and F1 `1.00` after aligning the JSON ground truth with all intentionally planted findings.

Production verification script: `scripts/verify-production.ps1` runs tool discovery, `npm test`, `hermsec doctor --json`, and the scanner-only eval gate. It fails when PMG is missing unless `-AllowMissingPmg` is supplied for pre-approval verification. PMG setup instructions are in `docs/pmg-setup.md`.

Known local shortcomings:

- SafeDep PMG is not installed on this PC. Global instructions require explicit user approval before installing or globally configuring PMG.
- External scanner binaries are machine-local prerequisites, not repository contents; `doctor` is the source of truth for a specific laptop/VPS.
- EPSS, RSS/security-news feeds beyond GitHub/NVD recency, deps.dev, Scorecard, Socket, Phylum, and official OWASP/NIST benchmark acquisition remain future integrations.
- OS-level schedule registration remains a future adapter; current scheduler storage, manual `schedule run`, and watch mode work locally.

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
  - SafeDep PMG-wrapped npm audit
  - OSV-Scanner
- Bring-your-own model providers:
  - OpenRouter
  - OpenAI
  - Claude
  - Gemini
  - OpenCode Go
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

1. Get explicit approval before installing or globally configuring SafeDep PMG on this machine, then rerun `hermsec doctor --json` and `.\scripts\verify-production.ps1`.
2. Add official OWASP/NIST benchmark acquisition behind explicit opt-in commands.
3. Add EPSS, Scorecard/deps.dev/Socket/Phylum, and curated security-news feed adapters.
4. Add OS-level schedule registration if needed; current scheduler storage, manual `schedule run`, and watch mode work locally.
5. Add AgentMail and Telegram later, after the local core stays stable.
6. Add Hermes Agent or VPS/GitHub adapter after the Hermsec core is stable.
7. Create demo presentation materials from the verified local run.
