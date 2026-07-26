import {
  hermsecCanonicalScanAssistModes,
  type HermsecLegacyScanAssistMode,
  type HermsecProductScanAssistMode,
  type HermsecVisibleScanAssistMode,
} from "@/types/scan";

export const scanModeOptions: Array<{
  id: HermsecVisibleScanAssistMode;
  label: string;
  shortLabel: string;
  description: string;
  status: string;
  requiresModel: boolean;
  usesScanners: boolean;
}> = [
  {
    id: "scanner-only",
    label: "Scanner only",
    shortLabel: "Scanner",
    description: "Runs deterministic security scanners and writes raw, reproducible evidence without calling a model.",
    status: "No model required",
    requiresModel: false,
    usesScanners: true,
  },
  {
    id: "single-agent",
    label: "Single agent",
    shortLabel: "Single",
    description: "Uses one configured agent to inspect focused code candidates without running scanner tools.",
    status: "Focused agent review",
    requiresModel: true,
    usesScanners: false,
  },
  {
    id: "moa-low",
    label: "MoA Low",
    shortLabel: "MoA Low",
    description: "Uses three specialist agents, a bounded judge, and an aggregator without scanner tools.",
    status: "Three specialists",
    requiresModel: true,
    usesScanners: false,
  },
  {
    id: "moa-high",
    label: "MoA High",
    shortLabel: "MoA High",
    description: "Uses five specialist agents, a bounded judge, and an aggregator without scanner tools.",
    status: "Five specialists",
    requiresModel: true,
    usesScanners: false,
  },
  {
    id: "scanner-single",
    label: "Scanner + Single",
    shortLabel: "Scan+Single",
    description: "Runs scanners and one bounded agent independently, then deterministically fuses both evidence sources.",
    status: "Hybrid evidence",
    requiresModel: true,
    usesScanners: true,
  },
  {
    id: "scanner-moa-low",
    label: "Scanner + MoA Low",
    shortLabel: "Scan+Low",
    description: "Runs scanners plus the three-specialist MoA independently, then preserves and fuses the evidence.",
    status: "Hybrid, three specialists",
    requiresModel: true,
    usesScanners: true,
  },
  {
    id: "scanner-moa-high",
    label: "Scanner + MoA High",
    shortLabel: "Scan+High",
    description: "Runs scanners plus the five-specialist MoA independently, then preserves and fuses the evidence.",
    status: "Hybrid, five specialists",
    requiresModel: true,
    usesScanners: true,
  },
];

const canonicalModes = new Set<string>(hermsecCanonicalScanAssistModes);

export function isCanonicalScanAssistMode(value: unknown): value is HermsecProductScanAssistMode {
  return typeof value === "string" && canonicalModes.has(value);
}

export function normalizeScanAssistMode(value: unknown): HermsecProductScanAssistMode {
  return isCanonicalScanAssistMode(value) ? value : "scanner-only";
}

export function migratePersistedScanAssistMode(value: unknown): HermsecProductScanAssistMode {
  if (isCanonicalScanAssistMode(value)) return value;

  switch (value as HermsecLegacyScanAssistMode) {
    case "single-agent-inspection":
      return "single-agent";
    case "moa-assisted":
    case "moa-inspection":
      return "moa-low";
    case "scanner-moa-assisted":
    case "scanner-moa-inspection":
    case "scanner-moa":
      return "scanner-moa-low";
    case "deep-assisted":
    case "scanner-model-summary":
    default:
      return "scanner-only";
  }
}

export function scanModeRequiresModel(value: HermsecProductScanAssistMode): boolean {
  return scanModeOptions.find((option) => option.id === value)?.requiresModel ?? false;
}

export function scanModeUsesScanners(value: HermsecProductScanAssistMode): boolean {
  return scanModeOptions.find((option) => option.id === value)?.usesScanners ?? true;
}

export function scanModeLabel(value: string | undefined): string {
  return scanModeOptions.find((option) => option.id === normalizeScanAssistMode(value))?.label ?? scanModeOptions[0].label;
}
