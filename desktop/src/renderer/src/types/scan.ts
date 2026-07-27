export type HermsecScanMode = "online";
export const hermsecCanonicalScanAssistModes = [
  "scanner-only",
  "single-agent",
  "moa-low",
  "moa-high",
  "scanner-single",
  "scanner-moa-low",
  "scanner-moa-high",
] as const;

export type HermsecProductScanAssistMode = (typeof hermsecCanonicalScanAssistModes)[number];

// These values only exist to migrate persisted desktop settings from earlier
// releases. They are never sent to the CLI for a new scan.
export type HermsecLegacyScanAssistMode =
  | "deep-assisted"
  | "moa-assisted"
  | "scanner-moa-assisted"
  | "scanner-model-summary"
  | "single-agent-inspection"
  | "moa-inspection"
  | "scanner-moa-inspection"
  | "scanner-moa";

export type HermsecVisibleScanAssistMode = HermsecProductScanAssistMode;
export type ScanTerminalStatus = "success" | "partial" | "degraded" | "canceled" | "failed" | "unchanged";

export interface ProjectStateFingerprint {
  kind: "git" | "filesystem";
  fingerprint: string;
  gitHead?: string;
  gitBranch?: string;
  gitDirty?: boolean;
  gitStatusHash?: string;
  fileStateHash?: string;
  capturedAt: string;
}

export type ScanProgressStatus = "waiting" | "running" | "completed" | "skipped" | "failed" | "canceled" | "degraded";

export interface ScanProgressDetail {
  id?: string;
  label: string;
  status: ScanProgressStatus;
  message?: string;
  value?: string;
}

export interface ScanProgressEvent {
  runId?: string;
  id: string;
  label: string;
  status: ScanProgressStatus;
  message?: string;
  parentId?: string;
  details?: ScanProgressDetail[];
  chips?: string[];
  assistMode?: HermsecProductScanAssistMode;
  assistModeLabel?: string;
  terminalStatus?: ScanTerminalStatus;
  degradationReasons?: string[];
  timestamp: number;
}

export interface ScanProjectRequest {
  runId?: string;
  targetPath?: string;
  reportDir?: string;
  mode?: HermsecScanMode;
  assistMode?: HermsecProductScanAssistMode;
  useModel?: boolean;
  skipIfUnchanged?: boolean;
  previousProjectState?: ProjectStateFingerprint;
}

export interface ScanSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface ScanProjectResult {
  ok: boolean;
  message: string;
  canceled?: boolean;
  unchanged?: boolean;
  targetPath?: string;
  reportDir?: string;
  htmlPath?: string;
  dashboardHtmlPath?: string;
  onepagerHtmlPath?: string;
  onepagerPdfPath?: string;
  scanId?: string;
  runId?: string;
  assistMode?: HermsecProductScanAssistMode;
  assistModeLabel?: string;
  assistArtifactPath?: string;
  summary?: ScanSummary;
  durationMs?: number;
  projectState?: ProjectStateFingerprint;
  terminalStatus?: ScanTerminalStatus;
  degradationReasons?: string[];
  error?: string;
}

export interface ScanControlResult {
  ok: boolean;
  message: string;
  runId?: string;
}

export interface OpenReportLocationRequest {
  path: string;
}

export interface OpenReportLocationResult {
  ok: boolean;
  message: string;
}
