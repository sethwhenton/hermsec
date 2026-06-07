import { app, BrowserWindow, shell } from "electron";
import { existsSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { loadEnvFile } from "./env";
import { registerIpcHandlers } from "./ipc";
import { dashboardBundle } from "./reportArtifacts";
import { defaultProjectDir, findHermsecRoot, scanProject } from "./scan";

const mainDir = import.meta.dirname;

let mainWindow: BrowserWindow | null = null;

configureAppPaths();

function createWindow(): void {
  mainWindow = new BrowserWindow({
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
      preload: resolve(mainDir, "../preload/index.cjs"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  });

  mainWindow.on("ready-to-show", () => {
    mainWindow?.show();
    if (process.env.HERMSEC_OPEN_DEVTOOLS === "true") {
      mainWindow?.webContents.openDevTools({ mode: "detach" });
    }
  });

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    void shell.openExternal(url);
    return { action: "deny" };
  });

  const rendererUrl = process.env.ELECTRON_RENDERER_URL;
  const loadPromise = rendererUrl
    ? mainWindow.loadURL(rendererUrl)
    : mainWindow.loadFile(join(mainDir, "../renderer/index.html"));

  void loadPromise.catch((error: unknown) => {
    console.error("Failed to load renderer:", error);
  });

  mainWindow.webContents.on("did-fail-load", (_event, errorCode, errorDescription, validatedURL) => {
    console.error("Renderer failed to load:", { errorCode, errorDescription, validatedURL });
  });
}

app.whenReady().then(async () => {
  loadEnvFile();
  if (process.argv.includes("--smoke-dashboard")) {
    try {
      await runDashboardSmoke();
      app.quit();
    } catch (error) {
      console.error(error);
      process.exitCode = 1;
      app.quit();
    }
    return;
  }

  registerIpcHandlers();
  createWindow();

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    app.quit();
  }
});

function appIconPath(): string | undefined {
  const iconName = process.platform === "win32" ? "icon.ico" : "icon.png";
  const candidates = [
    join(process.resourcesPath, iconName),
    join(process.resourcesPath, "resources", iconName),
    join(app.getAppPath(), "resources", iconName),
    resolve(mainDir, "../../resources", iconName),
  ];
  return candidates.find((candidate) => existsSync(candidate));
}

async function runDashboardSmoke(): Promise<void> {
  const root = findHermsecRoot();
  const projectPath = process.env.HERMSEC_SMOKE_PROJECT || defaultProjectDir();
  const reportDir = process.env.HERMSEC_SMOKE_DASHBOARD_OUT || join(root, ".hermsec", "v3-dashboard-smoke");
  const result = await scanProject({
    targetPath: projectPath,
    reportDir,
    mode: "online",
    useModel: process.env.HERMSEC_SMOKE_USE_MODEL !== "false",
  });

  assert(result.ok, `Scan failed: ${result.message}`);
  assert(result.reportDir && existsSync(result.reportDir), "Scan did not return a report directory.");
  assert(result.dashboardHtmlPath && existsSync(result.dashboardHtmlPath), "Dashboard HTML was not generated.");
  assert(result.onepagerHtmlPath && existsSync(result.onepagerHtmlPath), "One-page HTML was not generated.");
  assert(result.onepagerPdfPath && statSync(result.onepagerPdfPath).size > 0, "One-page PDF was not generated.");

  const bundle = dashboardBundle(result.reportDir);
  assert(bundle.ok && bundle.html?.includes("Hermsec"), "Dashboard bundle did not render report HTML.");

  const unchanged = await scanProject({
    targetPath: projectPath,
    reportDir,
    mode: "online",
    useModel: false,
    skipIfUnchanged: true,
    previousProjectState: result.projectState,
  });
  assert(unchanged.ok && unchanged.unchanged, "Unchanged project check did not skip the scan.");

  console.log(
    JSON.stringify(
      {
        ok: true,
        reportDir: result.reportDir,
        dashboardHtmlPath: result.dashboardHtmlPath,
        onepagerPdfPath: result.onepagerPdfPath,
      },
      null,
      2,
    ),
  );
}

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function configureAppPaths(): void {
  const homeDir = process.env.HERMSEC_HOME || argValue("--home-dir");
  if (homeDir) {
    app.setPath("userData", resolve(homeDir));
  }
}

function argValue(name: string): string | undefined {
  const index = process.argv.indexOf(name);
  if (index < 0) return undefined;
  return process.argv[index + 1];
}
