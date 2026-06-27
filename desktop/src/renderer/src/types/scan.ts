export type HermsecScanMode = "online";
export type HermsecLegacyScanAssistMode = "scanner-model-summary";
export type HermsecVisibleScanAssistMode = "deep-assisted" | "single-agent" | "moa-assisted" | "scanner-moa-assisted";
export type HermsecScanAssistMode = HermsecLegacyScanAssistMode | HermsecVisibleScanAssistMode;
export type HermsecProductScanAssistMode = HermsecVisibleScanAssistMode;

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

export type ScanProgressStatus = "waiting" | "running" | "completed" | "skipped" | "failed" | "canceled";

export interface ScanProgressDetail {
  id?: string;
  label: string;
  status: ScanProgressStatus;
  message?: string;
  value?: string;
}

export interface ScanProgressEvent {
  id: string;
  label: string;
  status: ScanProgressStatus;
  message?: string;
  parentId?: string;
  details?: ScanProgressDetail[];
  chips?: string[];
  assistMode?: HermsecScanAssistMode;
  assistModeLabel?: string;
  timestamp: number;
}

export interface ScanProjectRequest {
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
  assistMode?: HermsecProductScanAssistMode;
  assistModeLabel?: string;
  assistArtifactPath?: string;
  summary?: ScanSummary;
  durationMs?: number;
  projectState?: ProjectStateFingerprint;
  error?: string;
}

export interface ScanControlResult {
  ok: boolean;
  message: string;
}

export interface OpenReportLocationRequest {
  path: string;
}

export interface OpenReportLocationResult {
  ok: boolean;
  message: string;
}
