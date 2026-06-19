import type { HermsecScanAssistMode } from "@/types/scan";

export const scanModeOptions: Array<{
  id: HermsecScanAssistMode;
  label: string;
  shortLabel: string;
  description: string;
  status: string;
}> = [
  {
    id: "scanner-model-summary",
    label: "Scanner + model summary",
    shortLabel: "Summary",
    description: "Runs the scanner stack first, then uses the model only to summarize scanner-backed evidence.",
    status: "Fastest, lowest token use",
  },
  {
    id: "deep-assisted",
    label: "Deep assisted scan",
    shortLabel: "Deep",
    description: "Runs scanners, merges matching findings across tools, and lets the model support deeper triage.",
    status: "More context, more tokens",
  },
];

export function normalizeScanAssistMode(value: string | undefined): HermsecScanAssistMode {
  return value === "deep-assisted" ? "deep-assisted" : "scanner-model-summary";
}

export function scanModeLabel(value: string | undefined): string {
  return scanModeOptions.find((option) => option.id === normalizeScanAssistMode(value))?.label ?? scanModeOptions[0].label;
}

