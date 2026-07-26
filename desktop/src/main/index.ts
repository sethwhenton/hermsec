import { app, BrowserWindow, shell } from "electron";
import { existsSync, mkdirSync, readFileSync, renameSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { loadEnvFile } from "./env";
import { registerIpcHandlers } from "./ipc";
import { dashboardBundle } from "./reportArtifacts";
import { defaultProjectDir, findHermsecRoot, scanProject } from "./scan";
import { runDoctor } from "./doctor";
import { configureBundledRuntime } from "./runtimeBundle";
import type { ScanProgressEvent } from "../renderer/src/types/scan";

const mainDir = import.meta.dirname;

let mainWindow: BrowserWindow | null = null;

const dashboardSmokeMode = isDashboardSmokeMode();
const doctorSmokeMode = isDoctorSmokeMode();
const scanModesSmokeMode = isScanModesSmokeMode();
const uiSmokeMode = isUiSmokeMode();

configureGraphicsMode();
configureAppPaths();
configureBundledRuntime();

function createWindow(): BrowserWindow {
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
    if (isSafeExternalUrl(url)) {
      void shell.openExternal(url);
    }
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

  return mainWindow;
}

app.whenReady().then(async () => {
  loadEnvFile();
  if (uiSmokeMode) {
    try {
      registerIpcHandlers();
      await runUiSmoke();
      app.quit();
    } catch (error) {
      console.error(error);
      app.exit(1);
    }
    return;
  }
  if (scanModesSmokeMode) {
    try {
      await runScanModesSmoke();
      app.quit();
    } catch (error) {
      console.error(error);
      app.exit(1);
    }
    return;
  }
  if (dashboardSmokeMode) {
    try {
      await runDashboardSmoke();
      app.quit();
    } catch (error) {
      console.error(error);
      app.exit(1);
    }
    return;
  }
  if (doctorSmokeMode) {
    try {
      await runDoctorSmoke();
      app.quit();
    } catch (error) {
      console.error(error);
      app.exit(1);
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
  if (dashboardSmokeMode || doctorSmokeMode || scanModesSmokeMode || uiSmokeMode) {
    return;
  }
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
  const projectPath = process.env.HERMSEC_SMOKE_PROJECT || defaultProjectDir();
  const reportDir =
    process.env.HERMSEC_SMOKE_DASHBOARD_OUT || join(app.getPath("documents"), "Hermsec", "smoke-reports");
  const result = await scanProject({
    targetPath: projectPath,
    reportDir,
    mode: "online",
    assistMode: "scanner-only",
    useModel: false,
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
    assistMode: "scanner-only",
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

async function runDoctorSmoke(): Promise<void> {
  const progress: unknown[] = [];
  const result = await runDoctor((event) => progress.push(event));
  writeDoctorSmokeResultArtifact({
    schemaVersion: 1,
    kind: "hermsec-doctor-smoke",
    result,
  });
  assert(result.ok, `Doctor failed: ${result.message}`);

  const required = result.groups.find((group) => group.id === "required");
  const scanners = result.groups.find((group) => group.id === "scanners");
  const internet = result.groups.find((group) => group.id === "internet");
  assert(required?.status === "pass", `Required checks are not ready: ${required?.message ?? "missing group"}`);
  assert(scanners?.status === "pass", `Scanner checks are not ready: ${scanners?.message ?? "missing group"}`);
  assert(internet?.status !== "fail", `Internet checks failed: ${internet?.message ?? "missing group"}`);

  console.log(
    JSON.stringify(
      {
        ok: true,
        status: result.status,
        healthScore: result.healthScore,
        checks: result.checks,
        groups: result.groups,
        connectivity: result.connectivity,
        progressEvents: progress.length,
      },
      null,
      2,
    ),
  );
}

function writeDoctorSmokeResultArtifact(payload: unknown): void {
  const configuredPath = process.env.HERMSEC_SMOKE_RESULT_PATH?.trim();
  if (!configuredPath) return;

  const destination = resolve(configuredPath);
  mkdirSync(dirname(destination), { recursive: true });
  const temporary = `${destination}.partial-${process.pid}-${Date.now()}`;
  writeFileSync(temporary, JSON.stringify(payload), "utf8");
  renameSync(temporary, destination);
}

async function runUiSmoke(): Promise<void> {
  const window = createWindow();
  await waitForRenderer(window);
  const result = await window.webContents.executeJavaScript(`
    (async () => {
      const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
      const bodyText = () => document.body?.innerText || "";
      const clickText = (text) => {
        const candidates = Array.from(document.querySelectorAll("button, [role='button']"));
        const target = candidates.find((item) => (item.textContent || "").trim().includes(text));
        if (!target) return false;
        target.click();
        return true;
      };
      const waitForText = async (text) => {
        for (let i = 0; i < 40; i += 1) {
          if (bodyText().includes(text)) return true;
          await delay(100);
        }
        return false;
      };

      const openedSettings = clickText("Settings");
      await waitForText("General");
      await delay(200);
      const general = bodyText();
      const openedAgents = clickText("Agents");
      await waitForText("Low panel");
      await delay(200);
      const agents = bodyText();

      return {
        openedSettings,
        openedAgents,
        generalHasScannerOnly: general.includes("Scanner only"),
        generalHasSingle: general.includes("Single agent"),
        generalHasMoaLow: general.includes("MoA Low"),
        generalHasMoaHigh: general.includes("MoA High"),
        generalHasScannerSingle: general.includes("Scanner + Single"),
        generalHasScannerMoaLow: general.includes("Scanner + MoA Low"),
        generalHasScannerMoaHigh: general.includes("Scanner + MoA High"),
        agentsHasLow: agents.includes("Low panel"),
        agentsHasHigh: agents.includes("High panel"),
        agentsMentionsScannerMoa: agents.includes("Scanner + MoA"),
        bodyLength: bodyText().length,
      };
    })();
  `) as {
    openedSettings?: boolean;
    openedAgents?: boolean;
    generalHasScannerOnly?: boolean;
    generalHasSingle?: boolean;
    generalHasMoaLow?: boolean;
    generalHasMoaHigh?: boolean;
    generalHasScannerSingle?: boolean;
    generalHasScannerMoaLow?: boolean;
    generalHasScannerMoaHigh?: boolean;
    agentsHasLow?: boolean;
    agentsHasHigh?: boolean;
    agentsMentionsScannerMoa?: boolean;
    bodyLength?: number;
  };

  assert(result.openedSettings, "Settings button was not clickable in the rendered UI.");
  assert(result.openedAgents, "Agents settings section was not clickable in the rendered UI.");
  assert(result.generalHasScannerOnly, "General settings did not render Scanner only.");
  assert(result.generalHasSingle, "General settings did not render Single agent.");
  assert(result.generalHasMoaLow, "General settings did not render MoA Low.");
  assert(result.generalHasMoaHigh, "General settings did not render MoA High.");
  assert(result.generalHasScannerSingle, "General settings did not render Scanner + Single.");
  assert(result.generalHasScannerMoaLow, "General settings did not render Scanner + MoA Low.");
  assert(result.generalHasScannerMoaHigh, "General settings did not render Scanner + MoA High.");
  assert(result.agentsHasLow, "Agents settings did not render Low panel.");
  assert(result.agentsHasHigh, "Agents settings did not render High panel.");
  assert(result.agentsMentionsScannerMoa, "Agents settings did not explain Scanner + MoA panel reuse.");

  console.log(JSON.stringify({ ok: true, ...result }, null, 2));
}

async function runScanModesSmoke(): Promise<void> {
  const projectPath = process.env.HERMSEC_SMOKE_PROJECT || resolve(findHermsecRoot(), "tests", "fixtures", "repos", "node-express-clean");
  const reportDir =
    process.env.HERMSEC_SMOKE_SCAN_MODES_OUT || join(app.getPath("documents"), "Hermsec", "scan-mode-smoke");
  const modes = (process.env.HERMSEC_SMOKE_SCAN_MODES || "scanner-only,single-agent,moa-low,moa-high,scanner-single,scanner-moa-low,scanner-moa-high")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean) as Array<"scanner-only" | "single-agent" | "moa-low" | "moa-high" | "scanner-single" | "scanner-moa-low" | "scanner-moa-high">;

  const runs = [];
  for (const assistMode of modes) {
    const progress: ScanProgressEvent[] = [];
    const result = await scanProject({
      targetPath: projectPath,
      reportDir: join(reportDir, assistMode),
      mode: "online",
      assistMode,
      useModel: assistMode !== "scanner-only",
    }, (event) => progress.push(event));

    assert(result.ok, `${assistMode} scan failed: ${result.message}`);
    assert(result.reportDir && existsSync(result.reportDir), `${assistMode} did not write a report directory.`);
    assert(result.dashboardHtmlPath && existsSync(result.dashboardHtmlPath), `${assistMode} did not write a dashboard HTML file.`);
    assert(result.onepagerHtmlPath && existsSync(result.onepagerHtmlPath), `${assistMode} did not write a one-page HTML file.`);
    assert(result.onepagerPdfPath && statSync(result.onepagerPdfPath).size > 0, `${assistMode} did not write a one-page PDF.`);
    assert(result.runId, `${assistMode} did not return a run id.`);
    assert(
      progress.some((event) => event.runId === result.runId && event.assistMode === assistMode),
      `${assistMode} progress did not preserve the selected mode and run id.`,
    );
    assert(
      progress.some((event) => event.id === "scan-terminal" && event.runId === result.runId && event.terminalStatus === result.terminalStatus),
      `${assistMode} did not emit matching terminal progress metadata.`,
    );

    const document = readReportDocument(result.reportDir);
    const agentMode = document.agentMode as { mode?: string; modeLabel?: string; agentsUsed?: unknown[] } | undefined;
    if (assistMode !== "scanner-only") {
      assert(agentMode?.mode === assistMode, `${assistMode} report agent metadata was not preserved.`);
    }
    if (assistMode === "scanner-only") {
      assert(!agentMode || agentMode.mode === "scanner-only", "Scanner-only mode must not substitute a model agent mode.");
    }

    runs.push({
      assistMode,
      reportDir: result.reportDir,
      findings: result.summary?.total ?? 0,
      progressEvents: progress.length,
      agentMode: agentMode?.mode,
      agentModeLabel: agentMode?.modeLabel,
      agentsUsed: agentMode?.agentsUsed?.length ?? 0,
      onepagerPdfPath: result.onepagerPdfPath,
      metrics: scoreSmokeReport(projectPath, document),
    });
  }

  const summary = { ok: true, projectPath, reportDir, metrics: aggregateSmokeMetrics(runs), runs };
  mkdirSync(reportDir, { recursive: true });
  writeFileSync(join(reportDir, "smoke-summary.json"), JSON.stringify(summary, null, 2));
  await writeStdout(`${JSON.stringify(summary, null, 2)}\n`);
}

async function waitForRenderer(window: BrowserWindow): Promise<void> {
  for (let i = 0; i < 80; i += 1) {
    if (!window.webContents.isLoading()) {
      const readyState = await window.webContents.executeJavaScript("document.readyState").catch(() => "");
      if (readyState === "interactive" || readyState === "complete") {
        return;
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error("Renderer did not become ready for UI smoke test.");
}

function readReportDocument(reportDir: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(reportDir, "report-document.json"), "utf8")) as Record<string, unknown>;
}

type SmokeEvalFinding = {
  id?: string;
  category?: string;
  severity?: string;
  cwe?: string[];
  identifiers?: {
    cve?: string[];
    ghsa?: string[];
    osv?: string[];
  };
  location?: {
    file?: string;
    startLine?: number;
  };
  package?: {
    ecosystem?: string;
    name?: string;
  };
  fingerprint?: string;
};

type SmokeEvalMetrics = {
  groundTruthPath?: string;
  totalExpected: number;
  totalActual: number;
  truePositive: number;
  falsePositive: number;
  falseNegative: number;
  precision: number;
  recall: number;
  f1: number;
};

function scoreSmokeReport(projectPath: string, document: Record<string, unknown>): SmokeEvalMetrics | undefined {
  const groundTruthPath = join(projectPath, "groundtruth.json");
  if (!existsSync(groundTruthPath)) {
    return undefined;
  }

  const parsed = JSON.parse(readFileSync(groundTruthPath, "utf8")) as unknown;
  const expected = Array.isArray(parsed)
    ? parsed.map(toSmokeFinding).filter((finding): finding is SmokeEvalFinding => finding !== undefined)
    : [];
  const findings = Array.isArray(document.findings)
    ? document.findings.map(toSmokeFinding).filter((finding): finding is SmokeEvalFinding => finding !== undefined)
    : [];
  const actual = dedupeSmokeFindings(findings);
  const matches = matchSmokeFindings(expected, actual);
  const truePositive = matches.length;
  const falsePositive = Math.max(0, actual.length - truePositive);
  const falseNegative = Math.max(0, expected.length - truePositive);
  const precision = safeSmokeRatio(truePositive, truePositive + falsePositive, 1);
  const recall = safeSmokeRatio(truePositive, truePositive + falseNegative, 1);

  return {
    groundTruthPath,
    totalExpected: expected.length,
    totalActual: actual.length,
    truePositive,
    falsePositive,
    falseNegative,
    precision,
    recall,
    f1: smokeF1(precision, recall),
  };
}

function aggregateSmokeMetrics(runs: Array<{ metrics?: SmokeEvalMetrics }>): SmokeEvalMetrics | undefined {
  const scored = runs.map((run) => run.metrics).filter((metrics): metrics is SmokeEvalMetrics => metrics !== undefined);
  if (scored.length === 0) {
    return undefined;
  }
  const counts = scored.reduce(
    (acc, metrics) => ({
      totalExpected: acc.totalExpected + metrics.totalExpected,
      totalActual: acc.totalActual + metrics.totalActual,
      truePositive: acc.truePositive + metrics.truePositive,
      falsePositive: acc.falsePositive + metrics.falsePositive,
      falseNegative: acc.falseNegative + metrics.falseNegative,
    }),
    { totalExpected: 0, totalActual: 0, truePositive: 0, falsePositive: 0, falseNegative: 0 },
  );
  const precision = safeSmokeRatio(counts.truePositive, counts.truePositive + counts.falsePositive, 1);
  const recall = safeSmokeRatio(counts.truePositive, counts.truePositive + counts.falseNegative, 1);
  return {
    ...counts,
    precision,
    recall,
    f1: smokeF1(precision, recall),
  };
}

function toSmokeFinding(value: unknown): SmokeEvalFinding | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  const record = value as Record<string, unknown>;
  const location = record.location && typeof record.location === "object" && !Array.isArray(record.location)
    ? record.location as Record<string, unknown>
    : undefined;
  const pkg = record.package && typeof record.package === "object" && !Array.isArray(record.package)
    ? record.package as Record<string, unknown>
    : undefined;
  return {
    id: stringValue(record.id),
    category: stringValue(record.category),
    severity: stringValue(record.severity),
    cwe: stringArray(record.cwe),
    identifiers: {
      cve: stringArray((record.identifiers as { cve?: unknown } | undefined)?.cve),
      ghsa: stringArray((record.identifiers as { ghsa?: unknown } | undefined)?.ghsa),
      osv: stringArray((record.identifiers as { osv?: unknown } | undefined)?.osv),
    },
    ...(location
      ? {
          location: {
            file: stringValue(location.file),
            startLine: numberValue(location.startLine),
          },
        }
      : {}),
    ...(pkg
      ? {
          package: {
            ecosystem: stringValue(pkg.ecosystem),
            name: stringValue(pkg.name),
          },
        }
      : {}),
    fingerprint: stringValue(record.fingerprint),
  };
}

function dedupeSmokeFindings(findings: SmokeEvalFinding[]): SmokeEvalFinding[] {
  const seen = new Set<string>();
  const result: SmokeEvalFinding[] = [];
  for (const finding of findings) {
    const key = finding.fingerprint || [
      finding.category,
      finding.severity,
      finding.location?.file,
      finding.location?.startLine,
      finding.package?.ecosystem,
      finding.package?.name,
      finding.cwe?.join(","),
    ].join("|");
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(finding);
  }
  return result;
}

function matchSmokeFindings(expected: SmokeEvalFinding[], actual: SmokeEvalFinding[]): Array<{ expected: number; actual: number }> {
  const candidates: Array<{ expected: number; actual: number; score: number }> = [];
  expected.forEach((truth, expectedIndex) => {
    actual.forEach((finding, actualIndex) => {
      const score = scoreSmokeMatch(truth, finding);
      if (score >= 60) {
        candidates.push({ expected: expectedIndex, actual: actualIndex, score });
      }
    });
  });

  const matches: Array<{ expected: number; actual: number }> = [];
  const usedExpected = new Set<number>();
  const usedActual = new Set<number>();
  for (const candidate of candidates.sort((left, right) => right.score - left.score || left.expected - right.expected || left.actual - right.actual)) {
    if (usedExpected.has(candidate.expected) || usedActual.has(candidate.actual)) {
      continue;
    }
    usedExpected.add(candidate.expected);
    usedActual.add(candidate.actual);
    matches.push({ expected: candidate.expected, actual: candidate.actual });
  }
  return matches;
}

function scoreSmokeMatch(expected: SmokeEvalFinding, actual: SmokeEvalFinding): number {
  let score = 0;
  if (expected.category && expected.category === actual.category) score += 20;
  if (expected.severity && expected.severity === actual.severity) score += 10;
  if (sameSmokeLocation(expected, actual)) score += 30;
  if (sameSmokePackage(expected, actual)) score += 30;
  if (overlapSmokeValues(expected.cwe, actual.cwe)) score += 25;
  if (
    overlapSmokeValues(expected.identifiers?.cve, actual.identifiers?.cve) ||
    overlapSmokeValues(expected.identifiers?.ghsa, actual.identifiers?.ghsa) ||
    overlapSmokeValues(expected.identifiers?.osv, actual.identifiers?.osv)
  ) {
    score += 45;
  }
  return score;
}

function sameSmokeLocation(expected: SmokeEvalFinding, actual: SmokeEvalFinding): boolean {
  if (!expected.location?.file || !actual.location?.file) return false;
  if (normalizeSmokePath(expected.location.file) !== normalizeSmokePath(actual.location.file)) return false;
  if (!expected.location.startLine || !actual.location.startLine) return true;
  return Math.abs(expected.location.startLine - actual.location.startLine) <= 3;
}

function sameSmokePackage(expected: SmokeEvalFinding, actual: SmokeEvalFinding): boolean {
  if (!expected.package?.ecosystem || !expected.package?.name || !actual.package?.ecosystem || !actual.package?.name) {
    return false;
  }
  return (
    expected.package.ecosystem.toLowerCase() === actual.package.ecosystem.toLowerCase() &&
    expected.package.name.toLowerCase() === actual.package.name.toLowerCase()
  );
}

function overlapSmokeValues(left?: string[], right?: string[]): boolean {
  if (!left?.length || !right?.length) return false;
  const normalized = new Set(right.map((item) => item.toUpperCase()));
  return left.some((item) => normalized.has(item.toUpperCase()));
}

function normalizeSmokePath(value: string): string {
  return value.replace(/\\/g, "/").toLowerCase();
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string" && item.length > 0) : [];
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function numberValue(value: unknown): number | undefined {
  const numeric = typeof value === "number" ? value : typeof value === "string" ? Number(value) : NaN;
  return Number.isFinite(numeric) ? numeric : undefined;
}

function safeSmokeRatio(numerator: number, denominator: number, emptyValue: number): number {
  return denominator === 0 ? emptyValue : numerator / denominator;
}

function smokeF1(precision: number, recall: number): number {
  return precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);
}

function writeStdout(message: string): Promise<void> {
  return new Promise((resolve) => {
    process.stdout.write(message, () => resolve());
  });
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

function configureGraphicsMode(): void {
  if (!dashboardSmokeMode && !doctorSmokeMode && !scanModesSmokeMode && !uiSmokeMode && process.env.HERMSEC_DISABLE_GPU !== "true") {
    return;
  }

  app.disableHardwareAcceleration();
  app.commandLine.appendSwitch("disable-gpu");
  app.commandLine.appendSwitch("disable-gpu-compositing");
  app.commandLine.appendSwitch("disable-software-rasterizer");
}

function argValue(name: string): string | undefined {
  const index = process.argv.indexOf(name);
  if (index < 0) return undefined;
  return process.argv[index + 1];
}

function isSafeExternalUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return ["http:", "https:", "mailto:"].includes(url.protocol);
  } catch {
    return false;
  }
}

function isDashboardSmokeMode(): boolean {
  return process.env.HERMSEC_SMOKE_DASHBOARD === "true" || process.argv.includes("--smoke-dashboard");
}

function isDoctorSmokeMode(): boolean {
  return process.env.HERMSEC_SMOKE_DOCTOR === "true" || process.argv.includes("--smoke-doctor");
}

function isScanModesSmokeMode(): boolean {
  return process.env.HERMSEC_SMOKE_SCAN_MODES_RUN === "true" || process.argv.includes("--smoke-scan-modes");
}

function isUiSmokeMode(): boolean {
  return process.env.HERMSEC_SMOKE_UI === "true" || process.argv.includes("--smoke-ui");
}
