import { BrowserWindow, dialog, ipcMain } from "electron";
import type { AppSettings, DeepPartial, ProviderTestRequest } from "../renderer/src/types/settings";
import type {
  DashboardBundleRequest,
  ExplainReportRequest,
  OpenArtifactRequest,
} from "../renderer/src/types/reports";
import type { OpenReportLocationRequest, ScanProjectRequest } from "../renderer/src/types/scan";
import type { CreateChatSessionRequest, UpdateChatSessionRequest } from "../renderer/src/types/sessions";
import { testProvider } from "./providerTest";
import { archiveProjectDirectory, deleteProjectDirectory, listProjectDirectories } from "./projects";
import { explainReport, getDashboardBundle, latestReport, openArtifact } from "./reports";
import { cancelActiveScan, openReportLocation, scanProject } from "./scan";
import {
  archiveChatSession,
  createChatSession,
  deleteChatSession,
  getChatSession,
  listChatSessions,
  updateChatSession,
} from "./sessions";
import { readSettings, updateSettings } from "./store";

export function registerIpcHandlers(): void {
  ipcMain.handle("settings:get", (): AppSettings => readSettings());

  ipcMain.handle(
    "settings:set",
    (_event, partial: DeepPartial<AppSettings>): AppSettings => updateSettings(partial),
  );

  ipcMain.handle("settings:choose-report-directory", async (_event, currentPath?: string) => {
    const result = await dialog.showOpenDialog({
      title: "Choose Hermsec report directory",
      defaultPath: currentPath,
      properties: ["openDirectory", "createDirectory"],
    });

    if (result.canceled || result.filePaths.length === 0) {
      return null;
    }

    return result.filePaths[0];
  });

  ipcMain.handle("settings:choose-project-directory", async (_event, currentPath?: string) => {
    const result = await dialog.showOpenDialog({
      title: "Choose Hermsec project folder",
      defaultPath: currentPath,
      properties: ["openDirectory"],
    });

    if (result.canceled || result.filePaths.length === 0) {
      return null;
    }

    return result.filePaths[0];
  });

  ipcMain.handle("provider:test", async (_event, request: ProviderTestRequest) =>
    testProvider(request),
  );

  ipcMain.handle("projects:list", () => listProjectDirectories());

  ipcMain.handle("projects:archive", (_event, projectPath: string) =>
    archiveProjectDirectory(projectPath),
  );

  ipcMain.handle("projects:delete", (_event, projectPath: string) =>
    deleteProjectDirectory(projectPath),
  );

  ipcMain.handle("sessions:list", (_event, projectPath?: string) => listChatSessions(projectPath));

  ipcMain.handle("sessions:get", (_event, id: string) => getChatSession(id));

  ipcMain.handle("sessions:create", (_event, request: CreateChatSessionRequest) =>
    createChatSession(request),
  );

  ipcMain.handle("sessions:update", (_event, request: UpdateChatSessionRequest) =>
    updateChatSession(request),
  );

  ipcMain.handle("sessions:archive", (_event, id: string) => archiveChatSession(id));

  ipcMain.handle("sessions:delete", (_event, id: string) => deleteChatSession(id));

  ipcMain.handle("reports:explain", (_event, request: ExplainReportRequest) =>
    explainReport(request),
  );

  ipcMain.handle("reports:latest", (_event, projectPath?: string) =>
    latestReport(projectPath),
  );

  ipcMain.handle("reports:dashboard-bundle", (_event, request: DashboardBundleRequest) =>
    getDashboardBundle(request),
  );

  ipcMain.handle("reports:open-artifact", (_event, request: OpenArtifactRequest) =>
    openArtifact(request),
  );

  ipcMain.handle("scan:project", async (event, request: ScanProjectRequest) =>
    scanProject(request, (progress) => event.sender.send("scan:progress", progress)),
  );

  ipcMain.handle("scan:cancel", () => cancelActiveScan());

  ipcMain.handle("scan:open-report-location", async (_event, request: OpenReportLocationRequest) =>
    openReportLocation(request),
  );

  ipcMain.handle("window:minimize", (event) => {
    const win = BrowserWindow.fromWebContents(event.sender);
    win?.minimize();
  });

  ipcMain.handle("window:maximize", (event) => {
    const win = BrowserWindow.fromWebContents(event.sender);
    if (!win) return;
    if (win.isMaximized()) {
      win.unmaximize();
    } else {
      win.maximize();
    }
  });

  ipcMain.handle("window:close", (event) => {
    const win = BrowserWindow.fromWebContents(event.sender);
    win?.close();
  });
}
