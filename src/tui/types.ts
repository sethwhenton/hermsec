import type { CommandResult, ScanMode, ScanSummary } from "../shared/types.js";

export type PrivacyMode = "local-only" | "balanced" | "cloud-assisted";

export type ModelMode = "none" | "local-provider" | "cloud-provider";

export type ReportLocation = "app-data" | "project-local" | "custom" | "ask";

export type ScanPreference = "full" | "changed" | "dependency-only" | "secrets-only";

export type WorkspaceSourceKind = "local" | "github-url";

export type TuiStatus =
  | "pending"
  | "running"
  | "ready"
  | "missing"
  | "skipped"
  | "failed"
  | "complete";

export type ChatRole = "hermsec" | "user" | "system";

export type ChatMessage = {
  role: ChatRole;
  text: string;
  at: string;
};

export type TuiWorkspace = {
  id: string;
  name: string;
  target: string;
  sourceKind: WorkspaceSourceKind;
  reportLocation: ReportLocation;
  privacyMode: PrivacyMode;
  modelMode: ModelMode;
  scanPreference: ScanPreference;
  createdAt: string;
  lastUsedAt?: string;
  lastScanAt?: string;
  lastFindingSummary?: string;
  reportDir?: string;
  scannerReadiness?: string;
};

export type TuiDoctorCheck = {
  label: string;
  status: TuiStatus;
  message: string;
};

export type TuiDoctorReport = {
  summary: string;
  checks: TuiDoctorCheck[];
};

export type TuiScannerStatus = {
  label: string;
  status: TuiStatus;
  message: string;
};

export type TuiScanRequest = {
  target: string;
  mode: ScanMode;
  preference: ScanPreference;
  workspaceId?: string;
};

export type TuiScanResult = {
  id: string;
  target: string;
  status: "queued" | "running" | "skipped" | "completed" | "failed";
  mode: ScanMode;
  preference: ScanPreference;
  startedAt: string;
  finishedAt?: string;
  summary?: ScanSummary;
  reportPath?: string;
  scannerStatuses?: TuiScannerStatus[];
  message?: string;
};

export type TuiReportSummary = {
  title: string;
  path: string;
  createdAt?: string;
  summary?: string;
};

export type TuiScheduleSummary = {
  id: string;
  target: string;
  cadence: string;
  mode: ScanMode;
  nextRunAt?: string;
  lastRunAt?: string;
  status: TuiStatus;
};

export type TuiIntelSummary = {
  status: TuiStatus;
  message: string;
  items: string[];
};

export type TuiSessionSummary = {
  id: string;
  workspaceId: string;
  title: string;
  createdAt: string;
  updatedAt: string;
  messageCount: number;
  toolCallCount: number;
  discussedScanIds: string[];
  discussedFindingIds: string[];
  compactSummary?: string;
};

export type TuiSessionSnapshot = {
  id: string;
  workspaceId: string;
  title: string;
  createdAt: string;
  updatedAt: string;
  messages: ChatMessage[];
  discussedScanIds: string[];
  discussedFindingIds: string[];
  compactSummary?: string;
};

export type TuiState = {
  workspaces: TuiWorkspace[];
  activeWorkspaceId: string | undefined;
  activeSessionId: string;
  privacyMode: PrivacyMode;
  modelMode: ModelMode;
  scanMode: ScanMode;
  scanPreference: ScanPreference;
  reportLocation: ReportLocation;
  reportDir: string | undefined;
  lastScan: TuiScanResult | undefined;
  lastDoctor: TuiDoctorReport | undefined;
  schedules: TuiScheduleSummary[];
  reports: TuiReportSummary[];
  sessions: TuiSessionSummary[];
  transcript: ChatMessage[];
};

export type TuiToolbox = {
  loadState?: () => Promise<Partial<TuiState>>;
  doctor?: () => Promise<CommandResult<TuiDoctorReport>>;
  scan?: (request: TuiScanRequest) => Promise<CommandResult<TuiScanResult>>;
  listReports?: (workspace: TuiWorkspace | undefined) => Promise<CommandResult<TuiReportSummary[]>>;
  listSchedules?: (workspace: TuiWorkspace | undefined) => Promise<CommandResult<TuiScheduleSummary[]>>;
  updateIntel?: (workspace: TuiWorkspace | undefined) => Promise<CommandResult<TuiIntelSummary>>;
  listSessions?: (workspace: TuiWorkspace | undefined) => Promise<CommandResult<TuiSessionSummary[]>>;
  saveSession?: (session: TuiSessionSnapshot) => Promise<CommandResult<TuiSessionSummary>>;
  addWorkspace?: (workspace: TuiWorkspace) => Promise<CommandResult<TuiWorkspace>>;
  useWorkspace?: (workspace: TuiWorkspace) => Promise<CommandResult<TuiWorkspace>>;
};

export type TuiRunOptions = {
  cwd?: string;
  input?: NodeJS.ReadableStream & { isTTY?: boolean };
  output?: NodeJS.WritableStream & { columns?: number; isTTY?: boolean };
  tools?: TuiToolbox;
  initialState?: Partial<TuiState>;
  forceInteractive?: boolean;
  skipOnboarding?: boolean;
  forceOnboarding?: boolean;
};

export type TuiRunSummary = {
  exitReason: "user-exit" | "non-interactive" | "input-closed";
  state: TuiState;
};
