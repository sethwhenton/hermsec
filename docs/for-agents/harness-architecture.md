# Hermsec Seven-Mode Harness Architecture

## Canonical Modes

| Mode | Detector paths | Model finalizer |
| --- | --- | --- |
| `scanner-only` | Scanner stack | None |
| `single-agent` | One bounded tool agent | None |
| `moa-low` | Three project-relevant specialists | Tri-state judge plus ID-only reconciliation |
| `moa-high` | Five specialists | Tri-state judge plus ID-only reconciliation |
| `scanner-single` | Scanner stack and Single Agent independently | None |
| `scanner-moa-low` | Scanner stack and three specialists independently | Agent-only tri-state judge plus ID-only reconciliation |
| `scanner-moa-high` | Scanner stack and five specialists independently | Agent-only tri-state judge plus ID-only reconciliation |

Legacy inputs remain readable but resolve to a canonical mode before execution:

- `deep-assisted` and `scanner-model-summary` -> `scanner-only`
- `moa-assisted` -> `moa-low` unless a stored High preset is present
- `scanner-moa-assisted` -> `scanner-moa-low` unless a stored High preset is present

Historical report documents are read as stored and are not rewritten.

## Detector Result Contract

Each detector path returns an immutable result:

```ts
type DetectorResult = {
  detectorId: string;
  status: "success" | "partial" | "degraded" | "failed" | "canceled";
  findings: Finding[];
  rawFindingIds: string[];
  coverage: CoverageReport;
  traces: ToolTrace[];
  usages: ModelUsage[];
  limitations: string[];
};
```

Hybrid orchestration never replaces scanner output with model output. It combines
detector results only after every path has terminated.

## Agent Investigation Loop

```text
deterministic project profile
-> role/coverage objective
-> model requests a bounded read-only tool
-> harness validates and executes the call
-> redacted result is returned as untrusted data
-> agent may follow one more evidence path
-> agent emits structured candidate findings
-> local evidence revalidation
```

Allowed tools:

- `inspect_project`
- `list_files`
- `search_code`
- `read_file_snippet`
- `read_manifest`
- `read_dependency_inventory`

The model never receives shell, write, install, arbitrary network, secret-file,
or outside-repository capabilities.

The final model round has no tools and must produce structured findings.
Single and specialist roles must produce at least one successful native
inspection result before a finding or abstention is accepted. Evidence-free
text is rejected as premature and may receive a bounded native-tool retry
without consuming the structured-output repair state.

## Tool Limits

| Limit | Single | Specialist |
| --- | ---: | ---: |
| Model rounds | 5 | 3 |
| Calls per round | 8 | 16 |
| Total calls | 8 | 16 |
| Repeated identical call | 1 retry | 1 retry |
| Concurrent agents | 1 | 2 across specialists |
| Structured-output repair | 1 | 1 |

Byte, token, duration and dollar limits are explicit configuration values. Every
limit exit produces a terminal reason and a partial/degraded status.

## Evidence And Prompt Safety

- Tool arguments are validated before dispatch.
- Paths are normalized, realpath-checked at use time and confined to the root.
- Secret-bearing files such as `.env` are never exposed to a model.
- Tool output is redacted with the full model redactor.
- Source text is enclosed in explicit untrusted-data boundaries.
- Tool-call and output digests are logged; full snippets are not duplicated in
  progress events.
- Every finding cites one or more evidence IDs.
- A local validator confirms the path, line range and evidence relationship.

## MoA

The deterministic profiler scores five roles against detected languages,
frameworks, manifests and candidate hints:

1. Injection and execution
2. Identity and request security
3. Sensitive data and cryptography
4. Dependencies and supply chain
5. Platform, storage and deployment

Low runs the top three with deterministic tie-breaking. High runs all five.

Specialists have isolated tool budgets and may not see one another's prose.
Every tool-using role, including Single Agent, specialists, and gap-fill, uses
the exact `deepseek/deepseek-v4-flash` route. The structured evidence judge
uses `xiaomi/mimo-v2.5`; the constrained aggregator alone uses
`minimax/minimax-m3`. This capability routing is duplicated intentionally in
the producer, trace validator, and standalone summarizer so a rehashed
role/model rewrite fails closed.

The judge receives normalized candidate summaries and cited evidence, not broad
repository tools. Verdicts are:

- `accepted`
- `rejected`
- `needs-review`

Missing output and provider failures become `needs-review`.

The aggregator may return groups of known candidate IDs and a short rationale.
It cannot create findings. Deterministic code retains all accepted and
needs-review candidates, applies canonical fusion, and records rejected
candidates separately.

## Canonical Fusion

Stable identity derives from normalized vulnerability class/CWE, repository
path, sink range, package identity and evidence digest. Fusion:

1. Keeps every raw finding unchanged in detector artifacts.
2. Groups only sufficiently equivalent findings.
3. Produces a canonical finding with all source finding IDs and source labels.
4. Uses deterministic severity/confidence rules.
5. Never lets model prose determine whether scanner evidence survives.

## Completion And Progress

Progress is scoped by `runId` and contains:

- canonical mode
- stage
- component/role
- round and tool name
- status
- duration
- bytes/result count
- redacted terminal reason

Terminal run statuses:

- `success`
- `partial`
- `degraded`
- `canceled`
- `failed`
- `unchanged`

Late events from a canceled/restarted run are ignored by run ID.

## Research Artifacts

Every cell writes an immutable run directory with:

- `run-manifest.json`
- raw detector findings
- canonical findings
- judgments and review queue
- tool trace index
- coverage/completeness report
- scanner and model versions
- token/cost ledger
- artifact hashes
- evaluator matches and metrics

Mock and replay execution never reads provider credentials. Live execution
requires `--allow-spend`, an exact model allowlist, environment-only credential
reference, no model-family fallback and a successful cost reservation.

Live suites share one fail-fast latch. The first non-success cell or
non-succeeded physical call synchronously blocks new dispatch, aborts
already-dispatched siblings, drains provider and ledger cleanup, and seals all
remaining agent/hybrid cells as explicit zero-cost cancellations. The
initiating call remains the sole failed trigger; induced siblings remain
canceled. Before dispatch, a failed reservation is known not charged; after
dispatch, an unresolved request remains conservatively unknown; an
authoritative settlement is never discarded. Empty OpenRouter generations are
typed as `provider_unavailable`.

## Evaluation

- Truth is finding-level, not a unique-CWE set.
- Matching requires compatible vulnerability class/category and evidence
  location; severity does not create a detection match.
- Assignment uses maximum-weight one-to-one matching.
- Clean controls have explicit empty truth sets.
- Report overall and per-class precision, recall, F1 and support.
- Report clean-case specificity, false findings per KLOC, duplicate rate,
  abstention/selective precision, run completeness, cost and latency.
- Unsupported categories are reported as unsupported, not scored as perfect.

## Paper Isolation

The fresh paper lives at:

`docs/research/task5-hermsec-moa/overleaf-paper-seven-mode-tool-agent/`

It may reuse ACM class/style files but no empirical text, metrics, tables or
figures from the previous paper. Every numerical claim must be generated from a
new immutable seven-mode run artifact.
