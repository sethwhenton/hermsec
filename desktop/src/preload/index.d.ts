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
import type { DoctorProgressEvent, DoctorRunResult } from "../renderer/src/types/doctor";
import type {
  ScannerActionResult,
  ScannerListRequest,
  ScannerStatusItem,
} from "../renderer/src/types/scanners";
import type {
  ChatSessionRecord,
  ChatSessionSummary,
  CreateChatSessionRequest,
  SessionActionResult,
  UpdateChatSessionRequest,
} from "../renderer/src/types/sessions";
import type {
  ConverseReportRequest,
  ConverseReportResult,
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
  doctor: {
    run: (runId?: string) => Promise<DoctorRunResult>;
    onProgress: (listener: (event: DoctorProgressEvent) => void) => () => void;
  };
  scanners: {
    list: (request?: ScannerListRequest) => Promise<ScannerStatusItem[]>;
    status: (request?: ScannerListRequest) => Promise<ScannerStatusItem[]>;
    install: (scannerId: string) => Promise<ScannerActionResult>;
    uninstall: (scannerId: string) => Promise<ScannerActionResult>;
    update: (scannerId: string) => Promise<ScannerActionResult>;
  };
  projects: {
    list: () => Promise<ProjectDirectory[]>;
    add: (projectPath: string) => Promise<ProjectActionResult>;
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
    converse: (request: ConverseReportRequest) => Promise<ConverseReportResult>;
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
    new: () => Promise<void>;
    minimize: () => Promise<void>;
    maximize: () => Promise<void>;
    close: () => Promise<void>;
    toggleFullscreen: () => Promise<void>;
    zoomIn: () => Promise<void>;
    zoomOut: () => Promise<void>;
    actualSize: () => Promise<void>;
  };
}

declare global {
  interface Window {
    hermsec: HermsecApi;
  }
}

export {};
