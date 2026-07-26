# Hermsec Laptop Handoff

Last updated: 2026-07-26

## Resume Here

This is the authoritative continuation checkpoint for the isolated Hermsec
research rebuild.

- Repository: `E:\Programming\hermsec`
- Remote: `https://github.com/sethwhenton/hermsec.git`
- Handoff branch: `research-harness-laptop-handoff`
- Baseline before this work: `9a4e0d8`
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

Do not merge to or push `main` unless the user explicitly asks. Do not run the
final paid all-fixture matrix until the remaining live evidence gate below is
fixed and reviewed.

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

Exact live model routes:

- `deepseek/deepseek-v4-flash`
- `xiaomi/mimo-v2.5`
- `minimax/minimax-m3` for aggregation only

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
- allows each specialist at most eight tool calls and eight calls per round;
- passes safe local parser error codes into one bounded repair;
- requires an exact candidate envelope and rejects prose/pseudo-tool keys;
- accepts concise abstention reasons up to 1,200 characters;
- preserves the six-request hard ceiling;
- has focused tests for the repair contract and long abstentions.

Independent Terra xhigh review: approved.

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

`E:\Programming\hermsec\.hermsec\research\final-v9-live-contract`

Results:

- 6 fixtures
- 7 modes
- 42/42 mock cells successful
- 42/42 replay cells successful
- 18 physical agent traces recorded
- 18 physical agent traces replayed
- 222 model-call references in each suite
- exact scoped cassette references validated
- deterministic `metrics.csv`, `completeness.csv`, `cost.csv`,
  `metrics-table.tex`, and `cost-table.tex` are byte-identical

Focused current verification:

```text
Core TypeScript build: PASS
Tool-loop, canonical harness, integration, and redaction: 51/51 PASS
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

## Immediate Remaining Fix

Enforce at least one real evidence-producing tool call before accepting a
specialist finding or abstention.

Recommended implementation:

1. Add an explicit `requireEvidenceBeforeFinal` option to the bounded loop.
2. Enable it for canonical Single and MoA inspection roles.
3. If a model returns text before any evidence while tools remain available,
   reject it as a premature final without consuming the one structured-output
   repair. Tell it to use a native inspection tool, then continue within the
   existing hard round/call/token/time limits.
4. Never execute JSON pseudo-tools.
5. Give gap-fill enough bounded rounds for:
   native inspection -> one narrow read -> final envelope.
6. Add tests for:
   - premature valid abstention;
   - plain-JSON tool schema;
   - successful recovery through a native call;
   - exhaustion without evidence;
   - no extra request beyond the hard provider-round ceiling.
7. Run a new mock/replay gate in a fresh directory.
8. Run a new 2-fixture live micro gate. Continue only if no provider-contract
   failure remains; evidence-validation rejection may be reported explicitly,
   but must not be hidden.

Do not weaken grounding validation merely to improve a score.

## Required Continuation Order

1. Implement and test the evidence-before-final gate.
2. Obtain Terra xhigh P1/P2 approval for that slice.
3. Run fresh all-fixture mock plus replay and compare deterministic hashes.
4. Run one fresh live micro gate.
5. If healthy, run one fresh live all-fixture suite under USD 3.25.
6. Validate its suite index, 42 cells, exact routes, ledger chain, statuses,
   scoped cassette references, and summary.
7. Replay the final live cassettes offline and create a validated live/replay
   comparison artifact.
8. Generate the standalone paper only from the final validated live artifacts.
9. Run full core and desktop verification.
10. Add packaged scan and packaged renderer/UI smokes.
11. Run a Sol xhigh integrated audit and resolve every P1/P2.
12. Build the Windows installer from a clean/disposable release checkout.
13. Launch packaged Hermsec without DevTools and leave the app visible.

## Paper State

Paper directory:

`docs/research/task5-hermsec-moa/overleaf-paper-seven-mode-tool-agent`

It is a scaffold, not a final paper. Do not copy quantitative claims from older
papers or from either diagnostic live run.

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
