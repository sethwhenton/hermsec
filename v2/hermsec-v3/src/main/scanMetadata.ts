export const SCAN_METADATA_FILE = "scan-metadata.json";

export interface LocalScanMetadata {
  projectPath: string;
  reportDir: string;
  scanId: string;
  mode: "online";
  assistMode?: "scanner-model-summary" | "deep-assisted";
  assistModeLabel?: string;
  startedAt: string;
  finishedAt: string;
  reportGeneratedAt: string;
  durationMs: number;
  gitBranch?: string;
  gitCommit?: string;
  dirtyWorkingTree?: boolean;
  projectStateKind: "git" | "filesystem";
  projectFingerprint: string;
}
