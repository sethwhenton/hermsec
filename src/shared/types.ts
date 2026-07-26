export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type FindingCategory =
  | "code"
  | "dependency"
  | "secret"
  | "supply-chain"
  | "config";

export type ScanMode = "auto" | "offline" | "online";

export type ScanAssistMode =
  | "scanner-only"
  | "single-agent"
  | "moa-low"
  | "moa-high"
  | "scanner-single"
  | "scanner-moa-low"
  | "scanner-moa-high";

export type CanonicalScanAssistMode = ScanAssistMode;

export type LegacyScanAssistMode =
  | "deep-assisted"
  | "moa-assisted"
  | "scanner-moa-assisted"
  | "scanner-model-summary"
  | "single-agent-inspection"
  | "moa-inspection"
  | "scanner-moa-inspection"
  | "scanner-moa";

export type ScanAssistModeInput = ScanAssistMode | LegacyScanAssistMode;

export type ScanProgressStage =
  | "repository"
  | "scanner"
  | "model"
  | "report"
  | "profile"
  | "agent"
  | "tool"
  | "judge"
  | "aggregator"
  | "fusion"
  | "evaluation"
  | "candidate"
  | "task"
  | "revalidation"
  | "checkpoint";

export type ScanProgressStatus =
  | "waiting"
  | "running"
  | "completed"
  | "skipped"
  | "failed"
  | "canceled"
  | "degraded";

export type ScanTerminalStatus =
  | "success"
  | "partial"
  | "degraded"
  | "canceled"
  | "failed"
  | "unchanged";

export type ScanProgressDetail = {
  id?: string;
  label: string;
  status?: ScanProgressStatus | ScannerStatus["status"];
  message?: string;
  value?: string;
};

export type ScanProgressEvent = {
  schemaVersion: "1.0";
  runId?: string;
  id: string;
  stage: ScanProgressStage;
  scannerId?: string;
  componentId?: string;
  roleId?: string;
  round?: number;
  toolName?: string;
  label: string;
  status: ScanProgressStatus;
  message: string;
  details?: ScanProgressDetail[];
  findingCount?: number;
  resultCount?: number;
  bytesRead?: number;
  durationMs?: number;
  assistMode?: ScanAssistModeInput;
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
  sourceLocations?: Array<{
    file: string;
    startLine?: number;
    endLine?: number;
  }>;
  package?: {
    ecosystem: string;
    name: string;
    installedVersion?: string;
  };
  agent?: AgentFindingMetadata;
  fingerprint: string;
};

export type AgentFindingMetadata = {
  mode: ScanAssistModeInput;
  source: "scanner-backed" | "single-agent" | "moa-specialist" | "moa-aggregator";
  provider: string;
  model?: string;
  role?: string;
  generatedAt: string;
  candidateIds?: string[];
  sourceFindingIds?: string[];
  judge?: {
    verdict: "accepted" | "rejected" | "needs-review";
    confidence?: "low" | "medium" | "high";
    reason?: string;
    reviewedBy?: string;
  };
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
  assistMode?: CanonicalScanAssistMode;
  terminalStatus?: ScanTerminalStatus;
  degradationReasons?: string[];
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
