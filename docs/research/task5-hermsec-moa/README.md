# HermSec Task 5 Research Bundle

This folder contains the paper source, compiled PDF, figures, and sanitized finding summaries for the Security Insider Lab II Task 5 write-up.

## Contents

- `overleaf-paper/` - ACM/Overleaf-ready paper source and compiled PDF.
- `overleaf-paper/hermsec_moa_paper.tex` - main paper file.
- `overleaf-paper/hermsec_moa_refs.bib` - bibliography.
- `overleaf-paper/hermsec_moa_paper.pdf` - compiled paper.
- `overleaf-paper/figures/` - app screenshots and result charts used by the paper.
- `findings/` - sanitized benchmark/model summaries used for the paper tables.

## Paper Direction

The paper presents HermSec as a user-friendly desktop repository security scanner, then compares:

- static scanner-backed review through Deep assisted scan,
- Single Agent inspection,
- MoA inspection,
- Scanner + MoA hybrid review.

The final small-fixture comparison used OpenCode Go with `deepseek-v4-flash`. `mimo-v2.5` and `minimax-m3` were configured or considered for future MoA routing, but they were not used in the final metric table.

## Findings

The `findings/` files are sanitized copies of local run outputs. Local absolute paths are replaced with placeholders such as `<hermsec-repo>` so the results can be committed safely.

Important files:

- `parallel-mode-summary.json` - Deep assisted, Single Agent, and MoA aggregate results.
- `parallel-aggregate-report.md` - readable summary of the parallel subagent run.
- `scanner-moa-scored-summary.json` - Scanner + MoA scored result.
- `scanner-moa-run-summary.json` - Scanner + MoA run metadata.
- `groundtruth-normalized.json` - normalized answer key used for scoring.
