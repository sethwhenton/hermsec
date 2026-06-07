import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { app, BrowserWindow, dialog, ipcMain, shell } from "electron";
import {
  addWorkspaceFromPath,
  chatTurn,
  getDesktopState,
  runDoctor,
  saveDesktopSettings,
  scanWorkspace,
  updateSecurityIntel,
} from "./api.js";
import { loadLocalEnv } from "./localEnv.js";
import type { ChatTurnInput, SaveSettingsInput, ScanWorkspaceInput } from "./types.js";
import { setActiveWorkspace } from "../storage/workspaceStore.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const cwd = process.cwd();
const envFile = loadLocalEnv(cwd);
const smokeMode = process.argv.includes("--smoke");

let mainWindow: BrowserWindow | undefined;
let smokeHome: string | undefined;
let previousHermsecHome: string | undefined;

registerIpcHandlers();

app.whenReady()
  .then(async () => {
    if (smokeMode) {
      previousHermsecHome = process.env.HERMSEC_HOME;
      smokeHome = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-desktop-smoke-"));
      process.env.HERMSEC_HOME = smokeHome;
    }
    mainWindow = createMainWindow(!smokeMode);
    await waitForRenderer(mainWindow);
    if (smokeMode) {
      await runSmokeTest(mainWindow);
      app.quit();
      return;
    }
    app.on("activate", () => {
      if (BrowserWindow.getAllWindows().length === 0) {
        mainWindow = createMainWindow(true);
      }
    });
  })
  .catch((error) => {
    console.error(error);
    app.exit(1);
  });

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    app.quit();
  }
});

function createMainWindow(show: boolean): BrowserWindow {
  const window = new BrowserWindow({
    width: 1380,
    height: 900,
    minWidth: 980,
    minHeight: 680,
    show,
    backgroundColor: "#08090b",
    title: "Hermsec",
    webPreferences: {
      preload: path.join(__dirname, "preload.cjs"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });

  const devServerUrl = process.env.VITE_DEV_SERVER_URL;
  if (devServerUrl) {
    void window.loadURL(devServerUrl);
  } else {
    void window.loadFile(path.join(__dirname, "../../renderer/index.html"));
  }
  return window;
}

function registerIpcHandlers(): void {
  ipcMain.handle("hermsec:get-state", () => getDesktopState(cwd, envFile));
  ipcMain.handle("hermsec:pick-workspace", async () => {
    const result = await dialog.showOpenDialog({
      title: "Choose a repository or project folder",
      properties: ["openDirectory"],
    });
    const selected = result.filePaths[0];
    return result.canceled || !selected ? undefined : addWorkspaceFromPath(selected);
  });
  ipcMain.handle("hermsec:add-workspace", (_event, rootPath: string) => addWorkspaceFromPath(rootPath));
  ipcMain.handle("hermsec:set-active-workspace", (_event, workspaceId: string) => setActiveWorkspace(workspaceId));
  ipcMain.handle("hermsec:scan-workspace", (_event, input: ScanWorkspaceInput) => scanWorkspace(input));
  ipcMain.handle("hermsec:update-intel", (_event, offline?: boolean) => updateSecurityIntel(cwd, offline === true));
  ipcMain.handle("hermsec:run-doctor", () => runDoctor(cwd));
  ipcMain.handle("hermsec:ask", (_event, input: ChatTurnInput) => chatTurn(cwd, input));
  ipcMain.handle("hermsec:save-settings", (_event, input: SaveSettingsInput) => saveDesktopSettings(cwd, input, envFile));
  ipcMain.handle("hermsec:open-path", async (_event, filePath: string) => {
    const error = await shell.openPath(path.resolve(filePath));
    if (error) {
      throw new Error(error);
    }
  });
  ipcMain.handle("hermsec:show-in-folder", (_event, filePath: string) => {
    shell.showItemInFolder(path.resolve(filePath));
  });
}

async function waitForRenderer(window: BrowserWindow): Promise<void> {
  if (!window.webContents.isLoading()) {
    return;
  }
  await new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error("Renderer load timed out.")), 20_000);
    window.webContents.once("did-finish-load", () => {
      clearTimeout(timeout);
      resolve();
    });
    window.webContents.once("did-fail-load", (_event, _code, description) => {
      clearTimeout(timeout);
      reject(new Error(description));
    });
  });
}

async function runSmokeTest(window: BrowserWindow): Promise<void> {
  try {
    const bridgeVisible = await window.webContents.executeJavaScript("Boolean(window.hermsec)");
    if (bridgeVisible !== true) {
      throw new Error("Hermsec preload bridge is not visible to the renderer.");
    }
    const fixture = path.resolve("tests/fixtures/repos/node-express-vulnerable");
    const workspace = await addWorkspaceFromPath(fixture);
    const scan = await scanWorkspace({ workspaceId: workspace.id, mode: "offline" });
    if (scan.run.summary.total < 1 || !scan.report.documentPath) {
      throw new Error("Desktop smoke scan did not produce findings and a report.");
    }
    const intel = await updateSecurityIntel(cwd, true);
    if (intel.feed.length < 1) {
      throw new Error("Desktop smoke intel feed was empty.");
    }
  } finally {
    if (previousHermsecHome === undefined) {
      delete process.env.HERMSEC_HOME;
    } else {
      process.env.HERMSEC_HOME = previousHermsecHome;
    }
    if (smokeHome) {
      await fs.rm(smokeHome, { recursive: true, force: true });
    }
  }
}
