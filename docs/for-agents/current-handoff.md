# Hermsec Laptop Handoff

Last updated: 2026-07-26

## Resume Here

This is the authoritative continuation checkpoint for the isolated Hermsec
research rebuild.

- Repository: `C:\Users\whent\Documents\Personal Proj\hermsec refined`
- Remote: `https://github.com/sethwhenton/hermsec.git`
- Handoff branch: `research-harness-laptop-handoff`
- Baseline before this work: `1ca6da5`
- Canonical experiment modes: exactly seven
- One-shot Single Agent ablation: intentionally excluded
- Live experiment ceiling: USD 3.25 per suite

On another machine:

```powershell
git clone https://github.com/sethwhenton/hermsec.git
cd hermsec
git switch research-harness-laptop-handoff
```

Then read, in order:

1. `AGENTS.md`
2. `docs/for-agents/projectcontext.md`
3. `docs/for-agents/implementation-tracker.md`
4. this file

Do not merge to or push `main` unless the user explicitly asks. Do not run a
paid live matrix without explicit user approval to pass the runner's
`--allow-spend` gate.

## Research Contract

Keep these exact modes:

1. `scanner-only`
2. `single-agent`
3. `moa-low`
4. `moa-high`
5. `scanner-single`
6. `scanner-moa-low`
7. `scanner-moa-high`

The canonical Single Agent and every MoA specialist use bounded, read-only
repository tools. Raw scanner evidence and raw agent evidence remain visible.
Fusion is deterministic. The judge may classify candidate relevance, and the
aggregator may group known IDs, but neither may erase scanner evidence or
invent a finding.

Exact live role routes:

- Single Agent, every tool-using specialist, and specialist gap-fill:
  `deepseek/deepseek-v4-flash`
- MoA evidence judge: `xiaomi/mimo-v2.5`
- MoA aggregator: `minimax/minimax-m3`

No fallback model is permitted in scored runs.

## Completed And Reviewed

### Provenance and replay

- Explicit cassette policies: `none`, `recorded`, and `replay`.
- Every cassette reference is bound to fixture digest, harness version,
  prompt version, mode, request fingerprint, and occurrence.
- Recording roots are claimed atomically and cannot be silently reused.
- Suite summaries re-derive exact scope IDs and reject wrong-scope cassettes.
- Run manifests bind trace policy and artifact hashes.
- Independent Terra xhigh review: approved, no unresolved P1/P2.

### Bounded tool agents

- Native function calls are the only executable model tool path.
- JSON pseudo-tools are never executed.
- Single agents and MoA specialists have hard rounds, calls, bytes, tokens,
  timeouts, duplicate-call protection, and one bounded final repair.
- Judge and aggregator share a hard structured-role token budget.
- Provider adapters must support external abort and structured JSON.
- Candidate findings are validated against local evidence IDs, repository
  paths, and line ranges before acceptance.
- Redaction covers typed variables, class fields, function parameters,
  TypeScript definite-assignment fields, JSON-escaped snippets, credential
  URLs, provider tokens, and secret-like assignments.
- Independent Terra xhigh reviews: approved, no unresolved P1/P2.

### Live-contract reliability correction

The first diagnostic live candidate exposed 30-second provider timeouts,
five-call specialist starvation, overlong abstention rejection, and generic
repair prompts. The current branch now:

- uses a 90-second OpenRouter request timeout;
- keeps each Single/Specialist loop bounded to 180 seconds;
- allows each specialist at most 16 tool calls and 16 calls per round;
- passes safe local parser error codes into one bounded repair;
- requires an exact candidate envelope and rejects prose/pseudo-tool keys;
- accepts concise abstention reasons up to 1,200 characters;
- preserves the six-request hard ceiling;
- has focused tests for the repair contract and long abstentions.

Independent Terra xhigh review: approved.

### Strict live suite fail-fast

- One suite-scoped latch stops new physical model dispatch as soon as any live
  cell is non-success or any physical call is non-succeeded.
- A local timeout trips the latch before provider cancellation cleanup
  finishes. Dispatched siblings are aborted and drained; later roles and cells
  never start.
- The initiating timeout/failure is the sole failed trigger. Induced siblings
  remain canceled.
- Ledger state distinguishes known-not-charged pre-dispatch failure, unknown
  post-dispatch charge, and authoritative settlement without erasing a failed
  trace.
- The live CLI exits with code 2 for partial, degraded, canceled, or failed
  cells and for any non-succeeded physical call.
- Empty OpenRouter generations are typed as `provider_unavailable` rather than
  an opaque provider failure.

### Evidence-before-final gate

- Canonical Single and MoA inspection roles require a successful native,
  evidence-producing repository tool result before accepting a finding or
  abstention.
- Evidence-free text and plain-JSON pseudo-tools are rejected as premature;
  they are never executed and do not consume structured-output repair state.
- Recovery remains inside the provider, token, tool-call, byte, timeout and
  cost ceilings, including a penultimate-round recovery path.
- Failed or rejected calls do not satisfy the gate; a successful zero-match
  inspection does.
- Gap-fill permits two one-call tool turns, a final envelope, and its one
  bounded structured-output repair.
- Independent Terra xhigh re-review: approved with no remaining P1/P2.

### Packaging and runtime integrity

- Packaged Doctor and scans use verified execution leases.
- Ambient/user scanner path overrides cannot replace bundled tools.
- The integrity anchor covers the bundled CLI, runtime tools, manifests, and
  launchers.
- `NODE_OPTIONS` and `NODE_EXTRA_CA_CERTS` are removed from child runtime
  environments; the Electron fuse disables Node options injection.
- Windows launcher builds use reproducibility flags and two-build byte
  comparison.
- Desktop focused/full tests passed previously: 71 passed, 2 expected skips.
- Independent Terra xhigh review: approved, no unresolved P1/P2.

## Verified Zero-Cost Evidence

The latest protocol-compatible zero-cost gate is local and ignored by Git:

`C:\Users\whent\Documents\Personal Proj\hermsec refined\.hermsec\research\evidence-before-final-v9`

Results:

- 6 fixtures
- 7 modes
- 42/42 mock cells successful
- 42/42 replay cells successful
- 18 physical agent traces recorded
- 18 physical agent traces replayed
- 234 model-call references in each suite
- 234/234 physical model calls succeeded in each suite
- exact capability routing has zero role/model mismatches
- exact scoped cassette references validated
- deterministic `metrics.csv`, `completeness.csv`, `cost.csv`,
  `metrics-table.tex`, and `cost-table.tex` are byte-identical
- harness version:
  `canonical-seven-mode-v8-capability-routed-typed-provider-unavailable-required-evidence-suite-live-fail-fast`
- model-call trace schema/role-plan versions: `2.0` / `2.0`

Focused current verification:

```text
Core TypeScript build: PASS
Full core test suite: 499/499 PASS
Fresh pricing snapshot verifier: PASS
Mock and replay physical calls: 234/234 PASS each
Paper exporter: 20/20 PASS
Mock and replay suite indexes: PASS
```

## Diagnostic Live Runs: Do Not Use In The Paper

These artifacts are intentionally under ignored `.hermsec/` paths and are not
portable through Git.

### Rejected all-fixture candidate

Path:

`E:\Programming\hermsec\.hermsec\research\final-live-v1-reviewed`

The run was stopped after early cells showed systematic contract degradation.
It has no complete suite index and is ineligible for results or paper claims.

- settled spend: approximately USD 0.00608
- unresolved conservative commitment: approximately USD 0.00670

### Completed micro diagnostic

Path:

`E:\Programming\hermsec\.hermsec\research\live-micro-v2-contract`

- 2 fixtures
- 14 cells
- 6 successful
- 6 degraded
- 2 partial
- actual physical spend: USD 0.006720598
- conservative committed amount: USD 0.008594723

This suite is also ineligible for the paper. It proved that a specialist can
still return a valid abstention before using any tool, and a gap-fill role can
emit a tool schema as plain JSON instead of making a native function call.

### Laptop diagnostic v4: aggregation contradiction

Path:

`C:\Users\whent\Documents\Personal Proj\hermsec refined\.hermsec\research\evidence-before-final-live-v4`

- 14 sealed cells: 4 success, 2 partial, 8 canceled
- 14 settled physical calls
- actual and conservative cost: USD 0.004459928
- trigger: the aggregator was given a judge-rejected candidate while the
  prompt described every supplied candidate as eligible

The producer now filters both candidate and judgment payloads to non-rejected
IDs before aggregation while retaining the complete sets for deterministic
reconciliation.

### Laptop diagnostic v5: native-tool incompatibility

Path:

`C:\Users\whent\Documents\Personal Proj\hermsec refined\.hermsec\research\evidence-before-final-live-v5`

- 14 sealed cells: 6 success, 2 degraded, 6 canceled
- 36 settled physical calls
- actual and conservative cost: USD 0.006336238
- MoA Low succeeded after the aggregation fix
- trigger: MiMo tool-using roles returned tool-shaped JSON text rather than
  native tool calls, so the evidence gate correctly kept it inert

This run established the capability route now encoded in the harness:
DeepSeek for every tool-using role, MiMo for the structured judge, and Minimax
for aggregation.

### Laptop diagnostic v6: untyped judge provider failure

Path:

`C:\Users\whent\Documents\Personal Proj\hermsec refined\.hermsec\research\evidence-before-final-live-v6`

- 14 sealed cells: 4 success, 10 canceled
- 13 succeeded calls and 1 failed MiMo judge call
- authoritative settled cost: USD 0.002396484
- conservative committed amount: USD 0.003599224
- the judge request failed after dispatch without a safe upstream diagnostic

The suite index and standalone summary validate. The adapter now records an
empty OpenRouter generation as typed `provider_unavailable` instead of a
generic provider failure.

### Laptop diagnostic v7: typed provider-unavailable trigger

Path:

`C:\Users\whent\Documents\Personal Proj\hermsec refined\.hermsec\research\evidence-before-final-live-v7`

- 14 sealed cells: 6 success, 8 canceled
- Single Agent and MoA Low completed successfully with the final capability
  route, including successful MiMo judgment and Minimax aggregation
- the suite recorded 22 succeeded calls; MoA High contributed 6 of them,
  followed by 1 failed DeepSeek call typed `provider_unavailable` and 1
  induced canceled sibling
- authoritative settled cost: USD 0.006308035
- conservative committed amount: USD 0.011166735

The suite index and standalone summary validate. This is an external
availability/no-content failure, not an evidence, route, ledger, or local
timeout bypass. Strict fail-fast behaved as designed.

Combined laptop v4-v7 authoritative settled spend is USD 0.019500685. The
conservative committed maximum is USD 0.025562125. None of these diagnostic
suites is eligible for quantitative paper claims.

## Immediate Remaining Gate

The implementation, 499-test regression suite, fresh pricing snapshot, and v9
zero-cost mock/replay gate are complete. Paid work is stopped because the final
micro retry recorded an exact-model OpenRouter `provider_unavailable`
generation during MoA High. Do not launch the all-fixture live matrix.

Resume paid work only after the user explicitly authorizes another attempt and
there is evidence that the exact-model route is available. A fresh two-fixture
micro must finish 14/14 cells successfully with every physical call succeeded
before the all-fixture gate may run. Do not weaken grounding, native-tool,
exact-model, or suite fail-fast validation to improve completion.

## Required Continuation Order

1. Preserve the v9 zero-cost evidence and the sealed v4-v7 diagnostics.
2. Confirm exact-model provider availability and obtain explicit approval
   before any new paid request.
3. Run one fresh live micro; require 14 successful cells and zero
   non-succeeded physical calls.
4. Only then run one fresh live all-fixture suite under USD 3.25.
5. Validate its suite index, 42 cells, exact routes, ledger chain, statuses,
   scoped cassette references, and summary.
6. Replay the final live cassettes offline and create a validated live/replay
   comparison artifact.
7. Generate the standalone paper only from the final validated live artifacts.
8. Run full core and desktop verification.
9. Add packaged scan and packaged renderer/UI smokes.
10. Run a Sol xhigh integrated audit and resolve every P1/P2.
11. Build the Windows installer from a clean/disposable release checkout.
12. Launch packaged Hermsec without DevTools and leave the app visible.

## Paper State

Paper directory:

`docs/research/task5-hermsec-moa/overleaf-paper-seven-mode-tool-agent`

It is a scaffold, not a final paper. Do not copy quantitative claims from older
papers or from any diagnostic live run.

Known blockers:

- current TeX build fails near the OpenRouter citation;
- placeholder macros omit `PartialCellCount` and `CanceledCellCount`;
- no deterministic promotion step moves exporter output into the paper;
- the exporter still says `original v3 suite` in places that should say
  `validated source suite`;
- methods need exact dataset, scanner, prompt, model, runtime, matching, and
  bootstrap details;
- results need per-category performance, clean-fixture false positives,
  completeness/degradation, uncertainty, token/runtime distributions,
  adjudication counts, and live/replay agreement.

Local LaTeX tooling is available: `latexmk`, `pdflatex`, `bibtex`,
`acmart.cls`, and `ACM-Reference-Format.bst`.

## Packaging State

Do not call the installer release-ready yet.

Known remaining work:

- packaged smoke currently covers Doctor but not a packaged scan;
- packaged smoke does not render and exercise the packaged renderer/UI;
- `cl.exe` is not active in the normal shell;
- use an x64 Visual Studio Developer Command Prompt for the release build;
- packaging regenerates staged CLI/runtime directories and may fetch pinned
  assets and locked Python wheels, so run it from a clean/disposable checkout.

Expected Windows outputs under `desktop/release`:

- `win-unpacked/Hermsec.exe`
- versioned NSIS setup
- versioned portable executable

## Safe Commands

```powershell
$env:PMG_DISABLE_TELEMETRY = "true"
$pmg = "C:\Users\whent\.local\bin\pmg.exe"

& $pmg npm run build:core
& $pmg npm test
& $pmg npm --prefix desktop run typecheck
& $pmg npm --prefix desktop test
```

Do not run an install or package executor without reviewing manifests and the
repository safety policy. Never commit API keys, `.env` files, `.hermsec`
artifacts, scanner caches, or raw provider responses containing secrets.
