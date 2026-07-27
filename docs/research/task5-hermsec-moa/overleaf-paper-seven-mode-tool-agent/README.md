# HermSec Seven-Mode Tool-Agent Paper

This is a standalone ACM-style manuscript for the rebuilt HermSec experiment.
It describes only the current seven-mode bounded tool-agent study. It does not
reuse quantitative values from another paper or experiment.

## Files

- `main.tex`: manuscript source
- `references.bib`: primary tool documentation and research references
- `generated/results-macros.tex`: the only quantitative-results input

The visible placeholders in `generated/results-macros.tex` are intentional.
Quantitative macros must never be edited manually. A result-bearing build is
blocked until both deterministic generation gates below succeed.

## Compile

From this directory:

```powershell
latexmk -pdf -interaction=nonstopmode -halt-on-error main.tex
```

Equivalent explicit sequence:

```powershell
pdflatex -interaction=nonstopmode -halt-on-error main.tex
bibtex main
pdflatex -interaction=nonstopmode -halt-on-error main.tex
pdflatex -interaction=nonstopmode -halt-on-error main.tex
```

Clean generated LaTeX files:

```powershell
latexmk -C
```

## Fail-Closed Quantitative Data Gate

Run all ingestion commands from the repository root. Select one immutable
seven-mode suite as the sole quantitative source, then create a fresh summary
directory that does not contain output from another run:

```powershell
node scripts/research/summarize-seven-mode.mjs --suite <immutable-suite> --out <fresh-summary-dir>
```

Stop immediately if this command exits non-zero, reports an invalid manifest
or digest, omits an expected cell, or leaves a requested output missing. The
paper may consume only the validated `summary.json`, CSV, and LaTeX outputs
written into that fresh summary directory by this successful command. Raw run
files, prose summaries, historical tables, and manually calculated values are
not valid quantitative inputs.

Before any result-bearing LaTeX compilation, a repository-owned deterministic
macro-generation command must consume only those validated summarizer outputs
and atomically generate:

- `generated/results-macros.tex`
- a machine-readable provenance artifact recording the immutable suite ID,
  source summary digest, generator version, output digest, and generation time

The macro generator must fail if a required value is absent, non-finite,
ambiguous, or derived from an incomplete cell without an explicit status. It
must be repeatable: identical validated inputs must produce byte-identical
quantitative macros. Until this generator and provenance artifact exist and
succeed, keep the visible placeholders and treat the paper as a scaffold only.
Never type, paste, or hand-correct a quantitative macro.

## Current-Results Ingestion Checklist

1. Run the summarizer command above successfully against one immutable suite.
2. Use only its validated `summary.json`, CSV, and LaTeX outputs.
3. Confirm its suite index contains all expected fixture-mode cells.
4. Validate every run manifest and source-tree digest.
5. Confirm each cell has exactly one terminal status:
   - `success`
   - `partial`
   - `degraded`
   - `canceled`
   - `failed`
6. Treat `needs-review` only as a finding-level adjudication verdict, never as
   a terminal cell status.
7. Confirm the exact seven mode IDs:
   - `scanner-only`
   - `single-agent`
   - `moa-low`
   - `moa-high`
   - `scanner-single`
   - `scanner-moa-low`
   - `scanner-moa-high`
8. Confirm no scored run silently changed model, provider, or mode.
9. Verify the OpenRouter requested model, actual model, provider, generation
   ID, routing policy, token use, latency, and cost for each paid call.
10. Verify every paid call exactly once in one shared physical cost ledger and
    verify the USD 3.25 kill switch.
11. Verify per-cell and per-mode attributed cost records against that shared
    physical ledger without treating attributed cost as additional spend.
12. Generate metrics from the truth-set matcher:
   - TP, FP, FN
   - precision, recall, and F1
   - per-category metrics
   - clean-fixture false positives
   - finding-level abstention or `needs-review` adjudication counts
   - counts for every supported terminal cell status
13. Generate Wilson intervals for binomial precision and recall.
14. Generate paired bootstrap uncertainty for F1 and paired mode differences.
15. Verify mock results are labelled as harness validation, not model quality.
16. Replay the live cassettes without network access and compare scored output.
17. Run the deterministic macro generator and validate its provenance artifact.
18. Regenerate the macros with identical input and require byte-identical output.
19. Search the compiled source and PDF for `generated from current results`.
    Submission is blocked until no placeholder remains.
20. Compare every table and abstract claim with the validated `summary.json`,
    CSV, and LaTeX outputs.
21. Record the final suite ID, source commit, dirty-state digest, runtime
    versions, scanner versions, and paper build command.
22. Compile twice after BibTeX and visually inspect every PDF page.

## Claim Rules

- Scanner evidence remains visible even when a model disagrees.
- Mock and replay runs demonstrate harness behavior, not live model quality.
- Gitleaks reports secret-like material, not credential validity.
- OSV-Scanner and pip-audit cover disclosed dependency vulnerabilities; they
  do not prove that application source is secure.
- MoA literature motivates the experiment but does not prove that MoA improves
  vulnerability detection.
- Do not report Wilson intervals for F1. Use paired bootstrap uncertainty.
- Persist paid calls once in one shared physical cost ledger. Per-cell and
  per-mode attributed cost records are analytical views, not additional spend.
- Do not manually edit any quantitative macro or populate one from prose, raw
  run files, historical tables, or an unvalidated summary.
