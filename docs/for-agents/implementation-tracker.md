# Hermsec Tool-Agent Harness Implementation Tracker

Last updated: 2026-07-26

Exact continuation instructions, dirty-worktree ownership, artifact paths, open
review findings, and ordered commands are maintained in
`docs/for-agents/current-handoff.md`.

## Status Legend

- `BACKLOG`: not started
- `IN PROGRESS`: active implementation
- `REVIEW`: implementation complete; independent review pending
- `CHANGES REQUIRED`: reviewer found unresolved issues
- `VERIFIED`: acceptance criteria and review are complete
- `BLOCKED`: external dependency prevents meaningful progress

## Non-Negotiable Constraints

- Work only in `C:\Users\whent\Documents\Personal Proj\hermsec refined`.
- Work on `research-harness-laptop-handoff`; do not merge or push `main`
  without explicit user approval.
- Keep the seven canonical experiment modes.
- Do not add the rejected one-shot Single Agent ablation.
- Use read-only, repository-confined agent tools.
- Do not let models erase raw scanner evidence.
- Stop live model requests before cumulative cost can exceed USD 3.25.
- Keep provider credentials in ignored local environment storage only.

## Review Protocol

Every implementation track follows:

1. Worker implements a disjoint file scope.
2. Worker runs focused tests and records results.
3. `gpt-5.6-terra` at `xhigh` reviews correctness, security and tests.
4. The worker or lead resolves every actionable finding.
5. A focused re-review verifies the correction.
6. The lead integrates and updates this tracker.

The integrated system receives a final `gpt-5.6-sol` `xhigh` audit.

## Workstreams

| ID | Workstream | Owner | Status | Depends On | Acceptance Evidence |
| --- | --- | --- | --- | --- | --- |
| H00 | Clean isolated baseline and local branch | Lead | VERIFIED | - | Baseline `1ca6da5`; laptop handoff branch `research-harness-laptop-handoff` |
| H01 | Repository architecture map and contracts | Lead | VERIFIED | H00 | `harness-architecture.md`; four independent audits; ownership confirmed |
| H02 | Bounded read-only tool runtime | Agent A | VERIFIED | H01 | Commit `6e9a691`; confined tools, limits, traces and adversarial tests |
| H03 | Evidence provenance and prompt-injection boundaries | Agent A | VERIFIED | H02 | Commit `6e9a691`; evidence IDs, untrusted-data framing and grounded candidate validation |
| H04 | Canonical Single Agent loop | Agent B | VERIFIED | H02,H03 | Commit `f5c1925`; five bounded rounds and grounded structured findings |
| H05 | Scanner + Single independent fusion | Agent B | VERIFIED | H04,H07 | Commit `f5c1925`; both detector paths preserved and fused deterministically |
| H06 | MoA role planning and specialist loops | Agent C | VERIFIED | H02,H03 | Relevant Low roles; all High roles; isolated budgets |
| H07 | Canonical finding identity and deterministic fusion | Agent D | VERIFIED | H01 | Commit `3abed43`; stable IDs, cross-tool dedupe and immutable provenance |
| H08 | Judge, aggregator and coverage auditor | Agent C | VERIFIED | H06,H07 | Three-state verdict; ID-constrained aggregation; gap report |
| H09 | Scanner + MoA orchestration | Agent C | VERIFIED | H07,H08 | Commit `f5c1925`; independent paths and immutable scanner evidence |
| H10 | Cost accounting and hard budget enforcement | Agent E2 | VERIFIED | H01 | Commit `2e77de3`; per-call usage, exact routing, shared ledger and USD 3.25 kill switch |
| H11 | Replay cassettes and run manifests | Agent E2 | VERIFIED | H02,H10 | Commit `2e77de3`; sanitized replay, immutable manifests, tamper detection and cross-process locks |
| H12 | Evaluation repair and category metrics | Agent E1 | VERIFIED | H07 | Commit `65e52d8`; precision/recall/F1, per-class, abstention and completeness |
| H13 | Capability- and cost-normalized analysis | Agent E1 | VERIFIED | H10,H12 | Commit `65e52d8`; deterministic capability and cost-normalized rows |
| H14 | Micro fixtures and truth set | Agent E1 | VERIFIED | H07 | Commits `65e52d8` and `ea6757a`; paired micro and medium clean/vulnerable fixtures |
| H15 | Desktop IPC and mode integration | Agent F | IN PROGRESS | H04,H09,H10 | Seven modes, progress, cancel, partial-state and results |
| H16 | Focused worker reviews and corrections | Reviewers | VERIFIED | H02-H15 | Provenance, tool-loop/redaction, live-contract, and packaging slices approved with no unresolved P1/P2 |
| H17 | Core unit/integration verification | Lead | VERIFIED | H16 | Core build and complete 499-test suite pass |
| H18 | Micro and medium mock-provider matrices | Lead | VERIFIED | H11-H17 | Fresh v9 all-fixture mock/replay: 42/42 each, 234 succeeded scoped calls each, deterministic summaries byte-identical |
| H19 | Budget-capped live OpenRouter matrix | Lead | BLOCKED | H18 | Strict micro v7 validated routing through MoA Low, then stopped on a typed exact-model `provider_unavailable` generation in MoA High; no all-fixture run |
| H20 | Desktop build, smoke and visual verification | Lead | IN PROGRESS | H15-H17 | Runtime/package slice reviewed; packaged scan and packaged renderer/UI smoke remain |
| H21 | Fresh standalone paper | Paper agent | BLOCKED | H18,H19,H20 | Scaffold audited; quantitative work waits for one eligible final live suite |
| H22 | Paper compilation and factual audit | Lead/Reviewer | BACKLOG | H21 | PDF compiles; tables match artifacts; claims are evidenced |
| H23 | Final integrated security/architecture audit | Sol reviewer | BACKLOG | H17-H22 | All critical/high findings resolved or explicitly documented |
| H24 | Launch Electron preview | Lead | BACKLOG | H20,H23 | Hermsec window remains open for user review |

## Canonical Agent Tool Contract

Allowed:

- `inspect_project`
- `list_files`
- `search_code`
- `read_file_snippet`
- `read_manifest`
- `read_dependency_inventory`

Forbidden:

- shell/process execution
- file writes or patches
- package installation
- arbitrary network access
- paths outside the selected repository
- reading ignored secret files

Default research ceilings:

- Single Agent: five model rounds
- Specialist: three model rounds
- Specialist concurrency: two
- One bounded coverage gap-fill round
- One structured-output repair attempt
- Duplicate tool-call loop detection
- Per-run byte, token, call, timeout and dollar ceilings

## OpenRouter Live-Test Budget

| Mode family | Initial per-project ceiling |
| --- | ---: |
| Scanner only | USD 0.000 |
| Single Agent | USD 0.015 |
| Scanner + Single | USD 0.015 |
| MoA Low | USD 0.060 |
| Scanner + MoA Low | USD 0.060 |
| MoA High | USD 0.120 |
| Scanner + MoA High | USD 0.120 |

Global live-test ceiling: USD 3.25.

Model allowlist:

- Single Agent, all specialists, and specialist gap-fill:
  `deepseek/deepseek-v4-flash`
- MoA evidence judge: `xiaomi/mimo-v2.5`
- MoA aggregator: `minimax/minimax-m3`

No model-family fallback is permitted during scored runs. Exact-model endpoint
failover may use another endpoint only when it serves the same requested model.
Any non-success live cell or non-succeeded physical call trips one suite-wide
fail-fast latch, drains in-flight cleanup, and prevents later physical
dispatch.

## Verification Log

| Time | Scope | Command/Test | Result | Notes |
| --- | --- | --- | --- | --- |
| 2026-07-25 | Baseline | `git rev-parse HEAD` | PASS | `1ca6da53dc9970d7c91321d5482cd74c05019bae` |
| 2026-07-25 | Isolation | `git branch --show-current` | PASS | `experiment-harness-rebuild` |
| 2026-07-25 | Core baseline | `pmg npm test` | PASS | 108/108 tests passed |
| 2026-07-25 | Desktop baseline | `pmg npm run typecheck` | PASS | Renderer and main TypeScript projects passed |
| 2026-07-25 | Desktop dependency audit | `pmg npm audit --json` | WARN | Development-chain advisories: `esbuild` low, `postcss` high; no automatic fix applied |
| 2026-07-25 | Architecture audit | Four read-only subagents | PASS | Tool, mode/fusion, evaluator and desktop/paper boundaries mapped |
| 2026-07-25 | Integrated implementation checkpoint | `pmg npm test` | PASS | 186/186 tests passed; independent review corrections still pending |
| 2026-07-25 | Progress contract | Targeted strict TypeScript compilation | PASS | Run-scoped stage/tool fields and explicit terminal statuses compile |
| 2026-07-25 | Canonical seven-mode harness | Focused build and 34 core tests | PASS | Scanner, Single, MoA Low/High and all hybrid orchestration contracts passed |
| 2026-07-25 | Report-boundary cancellation | Focused integration suite | PASS | Cancellation returns `SCAN_CANCELED` and leaves no report artifacts |
| 2026-07-25 | Replay multi-process lock | 12 consecutive Windows concurrency runs | PASS | Unique record occurrences and persistent cursors remained deterministic |
| 2026-07-25 | Experiment runner correction | Focused runner/mock suite | PASS | 6/6 tests; provenance mutation fails closed; mock/replay ledgers exist and are empty |
| 2026-07-25 | Experiment runner review | Terra `xhigh` focused re-review | PASS | No P1/P2 findings; local commit `93f4fe3` |
| 2026-07-25 | Pricing snapshot | `pmg npm run research:validate-pricing` | PASS | Exact three-model allowlist; pinned digest valid; zero network requests |
| 2026-07-25 | All-fixture mock matrix | Seven-mode mock runner | PASS | 6 fixtures, 42 cells, zero failed cells and zero spend |
| 2026-07-25 | All-fixture replay matrix | Seven-mode cassette replay | PASS | 6 fixtures, 42 cells, zero failed cells; metrics and completeness exactly match mock |
| 2026-07-25 | Mock/replay integrity | `validateSuiteIndex` for both fresh suites | PASS | Both immutable suite indexes valid with zero errors |
| 2026-07-26 | Scoped replay regression | Focused research build and tests | PASS | 13 replay, 15 runner, 6 runtime, 13 metering, 2 concurrent replay and 57 summary assertions passed |
| 2026-07-26 | Scoped all-fixture mock matrix | `final-v4-scoped/mock-suite` | PASS | 6 fixtures, 42 successful cells, valid immutable index and zero spend |
| 2026-07-26 | Scoped all-fixture replay matrix | `final-v4-scoped/replay-suite` | PASS | 6 fixtures, 42 successful cells, valid immutable index and zero spend |
| 2026-07-26 | Scoped reproducibility | Integrity-bound mock/replay summaries | PASS | Metrics, completeness, cost and LaTeX tables are byte-identical |
| 2026-07-26 | Earlier zero-cost gate | Fresh all-fixture mock and replay | PASS | 42/42 cells each; 222 scoped call references each; superseded by the evidence-before-final protocol |
| 2026-07-26 | Live-contract focused verification | Core build plus tool-loop/canonical/redaction suites | PASS | 51/51 tests; Terra xhigh review approved |
| 2026-07-26 | Diagnostic live micro | Seven modes on paired micro fixtures | WARN | 14 cells: 6 success, 6 degraded, 2 partial; USD 0.006720598 actual; evidence-before-final gate still required |
| 2026-07-26 | Laptop handoff | `git branch --show-current` | PASS | `research-harness-laptop-handoff` |
| 2026-07-26 | Evidence-before-final focused verification | Core build; tool-loop/canonical/MoA, summary/runner, and paper-export suites | PASS | 45/45, 79/79, and 20/20 tests passed; Terra xhigh re-review approved |
| 2026-07-26 | Evidence-before-final zero-cost gate | Fresh all-fixture mock and offline replay | PASS | 42/42 cells each; 234 scoped call references each; suite indexes valid; five deterministic CSV/LaTeX outputs byte-identical |
| 2026-07-26 | Capability-routed v9 zero-cost gate | Fresh all-fixture mock and replay | PASS | 42/42 cells each; 234/234 calls succeeded; zero route mismatches; suite indexes valid; five CSV/LaTeX outputs byte-identical |
| 2026-07-26 | Pricing refresh | OpenRouter catalog plus offline verifier | PASS | DeepSeek price updated to USD 0.14/M input and USD 0.28/M output; sealed digest `6f8d00241ac08042056be6181027d1b6b40ce0a9eee0467912de2f370ad3b49d` |
| 2026-07-26 | Full core verification | `npm test` | PASS | 499/499 tests passed after capability routing, strict fail-fast, pricing, and typed blank-generation handling |
| 2026-07-26 | Paid micro v4 | Strict live micro | WARN | Aggregator eligibility contradiction; 4 success, 2 partial, 8 canceled; USD 0.004459928 |
| 2026-07-26 | Paid micro v5 | Strict live micro | WARN | MoA Low passed; MiMo tool roles emitted inert JSON pseudo-tools; 6 success, 2 degraded, 6 canceled; USD 0.006336238 |
| 2026-07-26 | Paid micro v6 | Strict live micro | WARN | MiMo judge failed after dispatch without a safe diagnostic; 4 success, 10 canceled; USD 0.002396484 settled / 0.003599224 conservative |
| 2026-07-26 | Paid micro v7 | Strict live micro | BLOCKED | Single and MoA Low passed exact capability routing; MoA High stopped on typed DeepSeek `provider_unavailable`; 6 success, 8 canceled; USD 0.006308035 settled / 0.011166735 conservative |

## Review Log

| Track | Reviewer | Verdict | Findings | Resolution |
| --- | --- | --- | --- | --- |
| H06/H08 | Terra `xhigh` | APPROVED | Conflicting/malformed judgments, duplicate role coverage, skipped/unselected claims and unknown-file integrity | Corrected; focused re-review approved |
| H07 | Terra `xhigh` | APPROVED | Finding identity, cross-source provenance and deterministic fusion | Corrected; focused re-review approved |
| H02-H05/H09 | Terra `xhigh` | APPROVED | Provider absence classification, canonical mode metadata, cancellation propagation and report-boundary artifacts | Corrected in `f5c1925`; focused 10-test re-review approved |
| H10/H11 | Terra `xhigh` | APPROVED | Mutable policy/accessor bypass, exact allowlist, shared ledger, prototype-sensitive replay keys and Windows lock initialization | Corrected in `2e77de3`; final focused re-review approved |
| H18 runner/CLI | Terra `xhigh` | APPROVED | Gap-fill call bounds, real zero-cost ledgers, source mutation boundaries, role routing and CLI gates | Corrected in `93f4fe3`; fresh mock/replay matrices approved |
| H15 desktop packaging/runtime | Terra `xhigh` | APPROVED | Scanner override, runtime integrity, launcher reproducibility, inherited Node environment | Corrected; 71 desktop tests passed with 2 expected skips |
| H18 summary/provenance | Terra `xhigh` | APPROVED | Suite/hash/ledger binding, cassette policy, exact replay scope and concurrent recorder ownership | Corrected; adversarial tests and v9 mock/replay gate passed |
| H19 live contract | Terra `xhigh` | APPROVED | Provider timeout, specialist budget, parser-aware repair, definite-assignment redaction | Corrected and focused 51-test suite passed; evidence-before-final follow-up is recorded below |
| H19 evidence-before-final | Terra `xhigh` | APPROVED | Premature finals, native-only recovery, repair isolation, penultimate recovery, gap-fill rounds and summary bounds | Corrected; no remaining P1/P2 findings |
| H19 suite fail-fast and capability routing | Parallel read-only reviewers | APPROVED | Trigger causality, sibling cancellation, exact role mapping, aggregator eligibility filtering and replay invalidation | Producer, trace validator, summarizer and tests agree; no unresolved P1/P2 |

## Open Decisions

- Do not run the all-fixture live matrix while the exact-model route is
  returning empty/provider-unavailable generations.
- Any future paid retry requires explicit approval and must first pass one
  14/14-cell micro with zero non-succeeded physical calls.
- Add packaged scan and packaged renderer/UI smoke coverage.
- Generate quantitative paper content only from a future eligible final live
  suite and its offline replay.
