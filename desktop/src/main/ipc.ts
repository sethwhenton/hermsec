import { BrowserWindow, dialog, ipcMain } from "electron";
import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
import type { AppSettings, DeepPartial, ProviderTestRequest } from "../renderer/src/types/settings";
import type {
  ConverseReportRequest,
  DashboardBundleRequest,
  ExplainReportRequest,
  OpenArtifactRequest,
} from "../renderer/src/types/reports";
import type { OpenReportLocationRequest, ScanProjectRequest } from "../renderer/src/types/scan";
import type { ScannerListRequest } from "../renderer/src/types/scanners";
import type { CreateChatSessionRequest, UpdateChatSessionRequest } from "../renderer/src/types/sessions";
import { runDoctor } from "./doctor";
import { testProvider } from "./providerTest";
import { archiveProjectDirectory, deleteProjectDirectory, listProjectDirectories, registerProjectDirectory } from "./projects";
import { converseReport, explainReport, getDashboardBundle, latestReport, openArtifact } from "./reports";
import { cancelActiveScan, openReportLocation, scanProject } from "./scan";
import { installScanner, scannerStatuses, uninstallScanner, updateScanner } from "./scanners";
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

  ipcMain.handle("doctor:run", (event, runId?: string) =>
    runDoctor((progress) => event.sender.send("doctor:progress", { ...progress, runId })),
  );

  ipcMain.handle("scanners:list", (_event, request?: ScannerListRequest) =>
    scannerStatuses(request),
  );

  ipcMain.handle("scanners:status", (_event, request?: ScannerListRequest) =>
    scannerStatuses(request),
  );

  ipcMain.handle("scanners:install", (_event, scannerId: string) =>
    installScanner(scannerId),
  );

  ipcMain.handle("scanners:uninstall", (_event, scannerId: string) =>
    uninstallScanner(scannerId),
  );

  ipcMain.handle("scanners:update", (_event, scannerId: string) =>
    updateScanner(scannerId),
  );

  ipcMain.handle("projects:list", () => listProjectDirectories());

  ipcMain.handle("projects:add", (_event, projectPath: string) =>
    registerProjectDirectory(projectPath),
  );

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

  ipcMain.handle("reports:converse", (_event, request: ConverseReportRequest) =>
    converseReport(request),
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

  ipcMain.handle("window:new", (event) => {
    const current = BrowserWindow.fromWebContents(event.sender);
    const win = new BrowserWindow({
      width: 1280,
      height: 860,
      minWidth: 960,
      minHeight: 640,
      show: false,
      frame: false,
      backgroundColor: "#09090b",
      titleBarStyle: "hidden",
      icon: appIconPath(),
      webPreferences: {
        preload: resolve(import.meta.dirname, "../preload/index.cjs"),
        contextIsolation: true,
        nodeIntegration: false,
        sandbox: false,
      },
    });

    win.on("ready-to-show", () => win.show());
    const currentUrl = current?.webContents.getURL();
    if (currentUrl && /^https?:\/\//.test(currentUrl)) {
      void win.loadURL(currentUrl);
    } else {
      void win.loadFile(join(import.meta.dirname, "../renderer/index.html"));
    }
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

  ipcMain.handle("window:toggle-fullscreen", (event) => {
    const win = BrowserWindow.fromWebContents(event.sender);
    if (!win) return;
    win.setFullScreen(!win.isFullScreen());
  });

  ipcMain.handle("window:zoom-in", (event) => {
    const webContents = event.sender;
    webContents.setZoomLevel(Math.min(3, webContents.getZoomLevel() + 0.5));
  });

  ipcMain.handle("window:zoom-out", (event) => {
    const webContents = event.sender;
    webContents.setZoomLevel(Math.max(-3, webContents.getZoomLevel() - 0.5));
  });

  ipcMain.handle("window:actual-size", (event) => {
    event.sender.setZoomLevel(0);
  });
}

function appIconPath(): string | undefined {
  const iconName = process.platform === "win32" ? "icon.ico" : "icon.png";
  const candidates = [
    join(process.resourcesPath, iconName),
    join(process.resourcesPath, "resources", iconName),
    resolve(import.meta.dirname, "../../resources", iconName),
  ];
  return candidates.find((candidate) => existsSync(candidate));
}
