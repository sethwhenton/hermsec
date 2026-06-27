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
    description: "Runs scanners, merges matching findings across tools, and lets the model support deeper triage.",
    status: "More context, more tokens",
  },
  {
    id: "single-agent",
    label: "Single agent inspection",
    shortLabel: "Single",
    description: "Uses one configured agent to inspect bounded code snippets and produce a focused security review.",
    status: "Focused agent review",
  },
  {
    id: "moa-assisted",
    label: "MoA assisted inspection",
    shortLabel: "MoA",
    description: "Runs specialist agents, a false-positive judge, and an aggregator over bounded code evidence.",
    status: "Multi-agent review",
  },
];

export function normalizeScanAssistMode(value: string | undefined): HermsecProductScanAssistMode {
  if (value === "single-agent" || value === "single-agent-inspection") return "single-agent";
  if (value === "moa-assisted" || value === "moa-inspection") return "moa-assisted";
  if (value === "deep-assisted" || value === "scanner-model-summary") return "deep-assisted";
  return "deep-assisted";
}

export function scanModeLabel(value: string | undefined): string {
  return scanModeOptions.find((option) => option.id === normalizeScanAssistMode(value))?.label ?? scanModeOptions[0].label;
}
