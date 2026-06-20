export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type FindingCategory =
  | "code"
  | "dependency"
  | "secret"
  | "supply-chain"
  | "config";

export type ScanMode = "auto" | "offline" | "online";

export type ScanAssistMode = "scanner-model-summary" | "deep-assisted";

export type ScanProgressStage =
  | "repository"
  | "scanner"
  | "model"
  | "report";

export type ScanProgressStatus =
  | "waiting"
  | "running"
  | "completed"
  | "skipped"
  | "failed";

export type ScanProgressDetail = {
  id?: string;
  label: string;
  status?: ScanProgressStatus | ScannerStatus["status"];
  message?: string;
  value?: string;
};

export type ScanProgressEvent = {
  schemaVersion: "1.0";
  id: string;
  stage: ScanProgressStage;
  scannerId?: string;
  label: string;
  status: ScanProgressStatus;
  message: string;
  details?: ScanProgressDetail[];
  findingCount?: number;
  durationMs?: number;
  assistMode?: ScanAssistMode;
  timestamp: string;
};

export type OutputFormat = "json" | "md" | "html";

export type CommandResult<T = unknown> =
  | { ok: true; message: string; data?: T }
  | { ok: false; errorCode: string; message: string; remediation?: string };

export type Finding = {
  id: string;
  title: string;
  category: FindingCategory;
  severity: Severity;
  confidence: "low" | "medium" | "high" | "confirmed";
  description: string;
  evidence: string;
  remediation: string;
  tool: string;
  ruleId?: string;
  cwe?: string[];
  identifiers?: {
    cve?: string[];
    ghsa?: string[];
    osv?: string[];
  };
  location?: {
    file: string;
    startLine?: number;
    endLine?: number;
  };
  package?: {
    ecosystem: string;
    name: string;
    installedVersion?: string;
  };
  fingerprint: string;
};

export type ScannerStatus = {
  id: string;
  label: string;
  status: "ready" | "missing" | "skipped" | "failed" | "completed";
  message: string;
  durationMs?: number;
};

export type ScanSummary = {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
};

export type ScanRun = {
  schemaVersion: "1.0";
  id: string;
  target: string;
  mode: ScanMode;
  startedAt: string;
  finishedAt: string;
  durationMs: number;
  git?: {
    branch?: string;
    commit?: string;
    dirty?: boolean;
  };
  scannerStatuses: ScannerStatus[];
  findings: Finding[];
  summary: ScanSummary;
};

export type ReportArtifacts = {
  runId: string;
  directory: string;
  jsonPath?: string;
  markdownPath?: string;
  htmlPath?: string;
};

export type HermsecConfig = {
  schemaVersion: "1.0";
  activeWorkspaceId?: string;
  reportDirectory: string;
  privacyMode: "local-only" | "balanced" | "cloud-assisted";
  model: {
    provider: "none" | "opencode-go" | "openai-compatible" | "ollama";
    baseUrl?: string;
    model?: string;
    apiKeyEnv?: string;
  };
  schedules: ScheduleConfig[];
};

export type WorkspaceConfig = {
  id: string;
  name: string;
  path: string;
  createdAt: string;
  lastUsedAt?: string;
};

export type ScheduleConfig = {
  id: string;
  target: string;
  dailyTime: string;
  mode: ScanMode;
  lastRunAt?: string;
  lastGitHead?: string;
};
