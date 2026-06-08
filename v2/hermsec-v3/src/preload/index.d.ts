import type {
  AppSettings,
  DeepPartial,
  ProviderTestRequest,
  ProviderTestResult,
} from "../renderer/src/types/settings";
import type {
  OpenReportLocationRequest,
  OpenReportLocationResult,
  ScanControlResult,
  ScanProgressEvent,
  ScanProjectRequest,
  ScanProjectResult,
} from "../renderer/src/types/scan";
import type { ProjectActionResult, ProjectDirectory } from "../renderer/src/types/projects";
import type {
  ChatSessionRecord,
  ChatSessionSummary,
  CreateChatSessionRequest,
  SessionActionResult,
  UpdateChatSessionRequest,
} from "../renderer/src/types/sessions";
import type {
  DashboardBundleRequest,
  DashboardBundleResult,
  ExplainReportRequest,
  ExplainReportResult,
  LatestReportResult,
  OpenArtifactRequest,
  OpenArtifactResult,
} from "../renderer/src/types/reports";

export interface HermsecApi {
  settings: {
    get: () => Promise<AppSettings>;
    set: (partial: DeepPartial<AppSettings>) => Promise<AppSettings>;
    chooseReportDirectory: (currentPath?: string) => Promise<string | null>;
    chooseProjectDirectory: (currentPath?: string) => Promise<string | null>;
  };
  provider: {
    test: (request: ProviderTestRequest) => Promise<ProviderTestResult>;
  };
  projects: {
    list: () => Promise<ProjectDirectory[]>;
    archive: (projectPath: string) => Promise<ProjectActionResult>;
    delete: (projectPath: string) => Promise<ProjectActionResult>;
  };
  sessions: {
    list: (projectPath?: string) => Promise<ChatSessionSummary[]>;
    get: (id: string) => Promise<ChatSessionRecord | null>;
    create: (request: CreateChatSessionRequest) => Promise<ChatSessionRecord>;
    update: (request: UpdateChatSessionRequest) => Promise<ChatSessionRecord>;
    archive: (id: string) => Promise<SessionActionResult>;
    delete: (id: string) => Promise<SessionActionResult>;
  };
  reports: {
    explain: (request: ExplainReportRequest) => Promise<ExplainReportResult>;
    latest: (projectPath?: string) => Promise<LatestReportResult>;
    dashboardBundle: (request: DashboardBundleRequest) => Promise<DashboardBundleResult>;
    openArtifact: (request: OpenArtifactRequest) => Promise<OpenArtifactResult>;
  };
  scan: {
    project: (request: ScanProjectRequest) => Promise<ScanProjectResult>;
    cancel: () => Promise<ScanControlResult>;
    onProgress: (listener: (event: ScanProgressEvent) => void) => () => void;
    openReportLocation: (
      request: OpenReportLocationRequest,
    ) => Promise<OpenReportLocationResult>;
  };
  window: {
    minimize: () => Promise<void>;
    maximize: () => Promise<void>;
    close: () => Promise<void>;
  };
}

declare global {
  interface Window {
    hermsec: HermsecApi;
  }
}

export {};
