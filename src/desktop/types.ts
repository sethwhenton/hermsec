import type { ProviderHealth } from "../model/provider.js";
import type { ReportIndexEntry } from "../reports/schema.js";
import type { ScanMode, ScanRun } from "../shared/types.js";
import type { UserConfig } from "../storage/userConfig.js";
import type { SessionRecord } from "../storage/sessionStore.js";
import type { WorkspaceProfile } from "../storage/workspaceStore.js";

export type DesktopIntelItem = {
  id: string;
  title: string;
  source: string;
  severity?: string;
  url?: string;
  whyShown: string[];
  cacheStatus: string;
};

export type DesktopProviderOption = {
  id: string;
  label: string;
  local: boolean;
  models: string[];
};

export type DesktopSettings = {
  privacyMode: UserConfig["privacyMode"];
  defaultReportLocation: UserConfig["defaultReportLocation"];
  customReportDir?: string;
  preferredModelProvider: NonNullable<UserConfig["preferredModelProvider"]>;
  providerCredentialEnv?: string;
  model: string;
  allowRemoteProviders: boolean;
};

export type DesktopState = {
  cwd: string;
  envFile?: string;
  config: UserConfig;
  settings: DesktopSettings;
  workspaces: WorkspaceProfile[];
  activeWorkspace?: WorkspaceProfile;
  sessions: SessionRecord[];
  reports: ReportIndexEntry[];
  intel: DesktopIntelItem[];
  providerHealth: ProviderHealth;
  providerFallbackReason?: string;
  providerOptions: DesktopProviderOption[];
};

export type ScanWorkspaceInput = {
  workspaceId?: string;
  target?: string;
  mode?: ScanMode;
};

export type ScanWorkspaceResult = {
  run: ScanRun;
  workspace: WorkspaceProfile;
  report: {
    htmlPath?: string;
    markdownPath?: string;
    documentPath: string;
    reportDir: string;
  };
  summaryText: string;
};

export type UpdateIntelResult = {
  message: string;
  summaryText?: string;
  feed: DesktopIntelItem[];
};

export type DoctorDesktopResult = {
  message: string;
  summary?: {
    pass: number;
    warn: number;
    fail: number;
    skip: number;
  };
};

export type ChatTurnInput = {
  workspaceId?: string;
  sessionId?: string;
  content: string;
};

export type ChatTurnResult = {
  message: string;
  session?: SessionRecord;
  scan?: ScanWorkspaceResult;
  intel?: UpdateIntelResult;
};

export type SaveSettingsInput = Partial<DesktopSettings>;

export type HermsecDesktopBridge = {
  getState(): Promise<DesktopState>;
  pickWorkspace(): Promise<WorkspaceProfile | undefined>;
  addWorkspace(rootPath: string): Promise<WorkspaceProfile>;
  setActiveWorkspace(workspaceId: string): Promise<WorkspaceProfile>;
  scanWorkspace(input: ScanWorkspaceInput): Promise<ScanWorkspaceResult>;
  updateIntel(offline?: boolean): Promise<UpdateIntelResult>;
  runDoctor(): Promise<DoctorDesktopResult>;
  ask(input: ChatTurnInput): Promise<ChatTurnResult>;
  saveSettings(input: SaveSettingsInput): Promise<DesktopState>;
  openPath(filePath: string): Promise<void>;
  showInFolder(filePath: string): Promise<void>;
};
