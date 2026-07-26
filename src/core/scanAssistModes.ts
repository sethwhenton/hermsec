export const canonicalScanAssistModes = [
  "scanner-only",
  "single-agent",
  "moa-low",
  "moa-high",
  "scanner-single",
  "scanner-moa-low",
  "scanner-moa-high",
] as const;

export type CanonicalScanAssistMode = (typeof canonicalScanAssistModes)[number];

export type LegacyScanAssistMode =
  | "deep-assisted"
  | "scanner-model-summary"
  | "moa-assisted"
  | "scanner-moa-assisted"
  | "single-agent-inspection"
  | "moa-inspection"
  | "scanner-moa-inspection"
  | "scanner-moa";

export type ScanAssistModeInput = CanonicalScanAssistMode | LegacyScanAssistMode;

export type ScanAssistModeSpec = {
  id: CanonicalScanAssistMode;
  label: string;
  runsScanners: boolean;
  agentPath: "none" | "single" | "moa";
  moaLevel?: "low" | "high";
  requiresModel: boolean;
};

const modeSpecs: Record<CanonicalScanAssistMode, ScanAssistModeSpec> = {
  "scanner-only": {
    id: "scanner-only",
    label: "Scanner only",
    runsScanners: true,
    agentPath: "none",
    requiresModel: false,
  },
  "single-agent": {
    id: "single-agent",
    label: "Single Agent",
    runsScanners: false,
    agentPath: "single",
    requiresModel: true,
  },
  "moa-low": {
    id: "moa-low",
    label: "MoA Low",
    runsScanners: false,
    agentPath: "moa",
    moaLevel: "low",
    requiresModel: true,
  },
  "moa-high": {
    id: "moa-high",
    label: "MoA High",
    runsScanners: false,
    agentPath: "moa",
    moaLevel: "high",
    requiresModel: true,
  },
  "scanner-single": {
    id: "scanner-single",
    label: "Scanner + Single",
    runsScanners: true,
    agentPath: "single",
    requiresModel: true,
  },
  "scanner-moa-low": {
    id: "scanner-moa-low",
    label: "Scanner + MoA Low",
    runsScanners: true,
    agentPath: "moa",
    moaLevel: "low",
    requiresModel: true,
  },
  "scanner-moa-high": {
    id: "scanner-moa-high",
    label: "Scanner + MoA High",
    runsScanners: true,
    agentPath: "moa",
    moaLevel: "high",
    requiresModel: true,
  },
};

export function isCanonicalScanAssistMode(value: unknown): value is CanonicalScanAssistMode {
  return typeof value === "string" && (canonicalScanAssistModes as readonly string[]).includes(value);
}

export function resolveScanAssistMode(
  value: string | undefined,
  options: { legacyMoaLevel?: "low" | "high" } = {},
): CanonicalScanAssistMode {
  if (isCanonicalScanAssistMode(value)) {
    return value;
  }

  const legacyMoaLevel = options.legacyMoaLevel ?? "low";
  switch (value) {
    case "single-agent-inspection":
      return "single-agent";
    case "moa-assisted":
    case "moa-inspection":
      return legacyMoaLevel === "high" ? "moa-high" : "moa-low";
    case "scanner-moa-assisted":
    case "scanner-moa-inspection":
    case "scanner-moa":
      return legacyMoaLevel === "high" ? "scanner-moa-high" : "scanner-moa-low";
    case "deep-assisted":
    case "scanner-model-summary":
    case undefined:
    default:
      return "scanner-only";
  }
}

export function scanAssistModeSpec(mode: CanonicalScanAssistMode): ScanAssistModeSpec {
  return modeSpecs[mode];
}

export function scanAssistModeLabel(mode: CanonicalScanAssistMode): string {
  return scanAssistModeSpec(mode).label;
}

export function scanAssistModeRunsScanners(mode: CanonicalScanAssistMode): boolean {
  return scanAssistModeSpec(mode).runsScanners;
}

export function scanAssistModeRequiresModel(mode: CanonicalScanAssistMode): boolean {
  return scanAssistModeSpec(mode).requiresModel;
}
