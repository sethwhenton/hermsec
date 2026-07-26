import type { HermsecVisibleScanAssistMode, ScanTerminalStatus } from "../renderer/src/types/scan";

export const SCAN_METADATA_FILE = "scan-metadata.json";

export interface LocalScanMetadata {
  projectPath: string;
  reportDir: string;
  scanId: string;
  runId?: string;
  mode: "online";
  assistMode?: HermsecVisibleScanAssistMode;
  assistModeLabel?: string;
  terminalStatus?: ScanTerminalStatus;
  degradationReasons?: string[];
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
