import { contextBridge, ipcRenderer } from "electron";
import type {
  AppSettings,
  DeepPartial,
  ProviderPreset,
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
  ReportControlResult,
} from "../renderer/src/types/reports";

const hermsecApi = {
  settings: {
    get: (): Promise<AppSettings> => ipcRenderer.invoke("settings:get"),
    set: (partial: DeepPartial<AppSettings>): Promise<AppSettings> =>
      ipcRenderer.invoke("settings:set", partial),
    chooseReportDirectory: (currentPath?: string): Promise<string | null> =>
      ipcRenderer.invoke("settings:choose-report-directory", currentPath),
    chooseProjectDirectory: (currentPath?: string): Promise<string | null> =>
      ipcRenderer.invoke("settings:choose-project-directory", currentPath),
  },
  provider: {
    presets: (): Promise<ProviderPreset[]> => ipcRenderer.invoke("provider:presets"),
    test: (request: ProviderTestRequest): Promise<ProviderTestResult> =>
      ipcRenderer.invoke("provider:test", request),
  },
  doctor: {
    run: (runId?: string): Promise<DoctorRunResult> => ipcRenderer.invoke("doctor:run", runId),
    onProgress: (listener: (event: DoctorProgressEvent) => void): (() => void) => {
      const handler = (_event: Electron.IpcRendererEvent, progress: DoctorProgressEvent) => listener(progress);
      ipcRenderer.on("doctor:progress", handler);
      return () => ipcRenderer.removeListener("doctor:progress", handler);
    },
  },
  scanners: {
    list: (request?: ScannerListRequest): Promise<ScannerStatusItem[]> =>
      ipcRenderer.invoke("scanners:list", request),
    status: (request?: ScannerListRequest): Promise<ScannerStatusItem[]> =>
      ipcRenderer.invoke("scanners:status", request),
    install: (scannerId: string): Promise<ScannerActionResult> =>
      ipcRenderer.invoke("scanners:install", scannerId),
    uninstall: (scannerId: string): Promise<ScannerActionResult> =>
      ipcRenderer.invoke("scanners:uninstall", scannerId),
    update: (scannerId: string): Promise<ScannerActionResult> =>
      ipcRenderer.invoke("scanners:update", scannerId),
  },
  projects: {
    list: (): Promise<ProjectDirectory[]> => ipcRenderer.invoke("projects:list"),
    add: (projectPath: string): Promise<ProjectActionResult> =>
      ipcRenderer.invoke("projects:add", projectPath),
    archive: (projectPath: string): Promise<ProjectActionResult> =>
      ipcRenderer.invoke("projects:archive", projectPath),
    delete: (projectPath: string): Promise<ProjectActionResult> =>
      ipcRenderer.invoke("projects:delete", projectPath),
  },
  sessions: {
    list: (projectPath?: string): Promise<ChatSessionSummary[]> =>
      ipcRenderer.invoke("sessions:list", projectPath),
    get: (id: string): Promise<ChatSessionRecord | null> =>
      ipcRenderer.invoke("sessions:get", id),
    create: (request: CreateChatSessionRequest): Promise<ChatSessionRecord> =>
      ipcRenderer.invoke("sessions:create", request),
    update: (request: UpdateChatSessionRequest): Promise<ChatSessionRecord> =>
      ipcRenderer.invoke("sessions:update", request),
    archive: (id: string): Promise<SessionActionResult> =>
      ipcRenderer.invoke("sessions:archive", id),
    delete: (id: string): Promise<SessionActionResult> =>
      ipcRenderer.invoke("sessions:delete", id),
  },
  reports: {
    explain: (request: ExplainReportRequest): Promise<ExplainReportResult> =>
      ipcRenderer.invoke("reports:explain", request),
    converse: (request: ConverseReportRequest): Promise<ConverseReportResult> =>
      ipcRenderer.invoke("reports:converse", request),
    cancel: (): Promise<ReportControlResult> => ipcRenderer.invoke("reports:cancel"),
    latest: (projectPath?: string): Promise<LatestReportResult> =>
      ipcRenderer.invoke("reports:latest", projectPath),
    dashboardBundle: (request: DashboardBundleRequest): Promise<DashboardBundleResult> =>
      ipcRenderer.invoke("reports:dashboard-bundle", request),
    openArtifact: (request: OpenArtifactRequest): Promise<OpenArtifactResult> =>
      ipcRenderer.invoke("reports:open-artifact", request),
  },
  scan: {
    project: (request: ScanProjectRequest): Promise<ScanProjectResult> =>
      ipcRenderer.invoke("scan:project", request),
    cancel: (): Promise<ScanControlResult> => ipcRenderer.invoke("scan:cancel"),
    onProgress: (listener: (event: ScanProgressEvent) => void): (() => void) => {
      const handler = (_event: Electron.IpcRendererEvent, progress: ScanProgressEvent) => listener(progress);
      ipcRenderer.on("scan:progress", handler);
      return () => ipcRenderer.removeListener("scan:progress", handler);
    },
    openReportLocation: (
      request: OpenReportLocationRequest,
    ): Promise<OpenReportLocationResult> =>
      ipcRenderer.invoke("scan:open-report-location", request),
  },
  window: {
    new: (): Promise<void> => ipcRenderer.invoke("window:new"),
    minimize: (): Promise<void> => ipcRenderer.invoke("window:minimize"),
    maximize: (): Promise<void> => ipcRenderer.invoke("window:maximize"),
    close: (): Promise<void> => ipcRenderer.invoke("window:close"),
    toggleFullscreen: (): Promise<void> => ipcRenderer.invoke("window:toggle-fullscreen"),
    zoomIn: (): Promise<void> => ipcRenderer.invoke("window:zoom-in"),
    zoomOut: (): Promise<void> => ipcRenderer.invoke("window:zoom-out"),
    actualSize: (): Promise<void> => ipcRenderer.invoke("window:actual-size"),
  },
};

contextBridge.exposeInMainWorld("hermsec", hermsecApi);
