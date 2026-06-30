import type { HermsecProductScanAssistMode, HermsecVisibleScanAssistMode } from "@/types/scan";

export const scanModeOptions: Array<{
  id: HermsecVisibleScanAssistMode;
  label: string;
  shortLabel: string;
  description: string;
  status: string;
}> = [
  {
    id: "deep-assisted",
    label: "Deep assisted scan",
    shortLabel: "Deep",
    description: "Runs scanner tools, merges duplicate evidence, then uses the model to explain and prioritize scanner-backed findings.",
    status: "More context, more tokens",
  },
  {
    id: "single-agent",
    label: "Single agent inspection",
    shortLabel: "Single",
    description: "Uses one configured agent to inspect focused code candidates without running scanner tools.",
    status: "Focused agent review",
  },
  {
    id: "moa-assisted",
    label: "MoA inspection",
    shortLabel: "MoA",
    description: "Runs specialist agents, a false-positive judge, and an aggregator over focused code candidates without scanner tools.",
    status: "Multi-agent review",
  },
  {
    id: "scanner-moa-assisted",
    label: "Scanner + MoA inspection",
    shortLabel: "Scan+MoA",
    description: "Runs scanners and MoA independently, then validates, deduplicates, and merges both evidence sources.",
    status: "Hybrid review",
  },
];

export function normalizeScanAssistMode(value: string | undefined): HermsecProductScanAssistMode {
  if (value === "single-agent" || value === "single-agent-inspection") return "single-agent";
  if (value === "moa-assisted" || value === "moa-inspection") return "moa-assisted";
  if (
    value === "scanner-moa-assisted" ||
    value === "scanner-moa" ||
    value === "scanner-plus-moa" ||
    value === "scanner+moa" ||
    value === "hybrid"
  ) {
    return "scanner-moa-assisted";
  }
  if (value === "deep-assisted" || value === "scanner-model-summary") return "deep-assisted";
  return "deep-assisted";
}

export function scanModeLabel(value: string | undefined): string {
  return scanModeOptions.find((option) => option.id === normalizeScanAssistMode(value))?.label ?? scanModeOptions[0].label;
}
