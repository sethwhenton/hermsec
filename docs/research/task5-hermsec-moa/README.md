# HermSec Task 5 Research Bundle

This folder contains the paper source, figures, and refreshed results for the Security Insider Lab II Task 5 write-up.

## Contents

- `overleaf-paper/` - ACM/Overleaf-ready paper source.
- `overleaf-paper/hermsec_moa_paper.tex` - main paper file.
- `overleaf-paper/hermsec_moa_refs.bib` - bibliography.
- `overleaf-paper/figures/` - app screenshots used by the refreshed paper.
- `results/latest/results.json` - source of truth for the refreshed actual-run metrics.

## Paper Direction

The paper presents HermSec as a user-friendly desktop repository security scanner, then compares:

- static scanner-backed review through Deep assisted scan,
- Single Agent inspection,
- MoA inspection,
- Scanner + MoA hybrid review.

The product overview should stay prominent: chat-driven project selection, adaptive scanner setup, scanner settings, agent/provider settings, Doctor checks, automations, live progress, and HTML/PDF/JSON reports.

The refreshed run is now available in `results/latest/results.json` with `executionMode: "actual"`. It completed 24 of 24 mode-and-fixture runs across four controlled fixtures with 12 expected findings. The paper tables are filled from that artifact, and the old scanner-only claims and earlier result charts are not carried forward.

The final model mix uses OpenCode Go only: `deepseek-v4-flash` for Deep assisted and Single Agent, `deepseek-v4-flash` plus `mimo-v2.5` for specialist work, `deepseek-v4-pro` for false-positive judging, and `minimax-m3` for aggregation.

## Results

Use `results/latest/results.json` and `results/latest/metrics.csv` for the current comparison. Earlier sanitized run summaries were removed so the folder does not mix old development numbers with the refreshed actual-run metrics.
