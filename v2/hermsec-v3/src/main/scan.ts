import { app, shell } from "electron";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import type {
  HermsecScanAssistMode,
  OpenReportLocationRequest,
  OpenReportLocationResult,
  ScanControlResult,
  ScanProgressEvent,
  ScanProjectRequest,
  ScanProjectResult,
  ScanSummary,
} from "../renderer/src/types/scan";
import { generateReportArtifacts } from "./reportArtifacts";
import { getProjectStateFingerprint, projectStateChanged } from "./projectState";
import { assistModeLabel, writeScanAssistArtifact } from "./scanAssist";
import { findBundledCliRoot } from "./runtimeBundle";
import type { LocalScanMetadata } from "./scanMetadata";

const CLI_RELATIVE_PATH = path.join("dist", "src", "bin", "hermsec.js");
const DEFAULT_SCAN_TIMEOUT_MS = 180_000;
const MAX_OUTPUT_CHARS = 30_000_000;

type CliOutcome = {
  ok?: boolean;
  message?: string;
  data?: {
    scan?: {
      id?: string;
      target?: string;
      durationMs?: number;
      summary?: Partial<ScanSummary>;
    };
    report?: {
      htmlPath?: string;
    };
  };
};

type ScanProgressCallback = (event: ScanProgressEvent) => void;

type ActiveScanControl = {
  child?: ChildProcessWithoutNullStreams;
  canceled: boolean;
};

class ScanCanceledError extends Error {
  constructor() {
    super("Scan stopped.");
    this.name = "ScanCanceledError";
  }
}

let activeScan: ActiveScanControl | null = null;

const PROGRESS_STAGES = [
  { id: "hermsec-heuristics", label: "Hermsec heuristics" },
  { id: "semgrep", label: "Semgrep" },
  { id: "gitleaks", label: "Gitleaks" },
  { id: "bandit", label: "Bandit" },
  { id: "osv", label: "OSV dependency checks" },
  { id: "pip-audit", label: "pip-audit" },
  { id: "pmg", label: "SafeDep PMG npm audit" },
  { id: "vuln-intel", label: "Online vulnerability intelligence" },
  { id: "evidence-merge", label: "Scanner evidence merge" },
  { id: "agent-review", label: "Agent report review" },
  { id: "report-generation", label: "Report generation" },
  { id: "pdf-generation", label: "PDF generation" },
];

export function findHermsecRoot(startDir = process.cwd()): string {
  const bundledRoot = findBundledCliRoot();
  if (bundledRoot) {
    return bundledRoot;
  }

  let current = path.resolve(startDir);
  for (let i = 0; i < 10; i += 1) {
    if (existsSync(path.join(current, CLI_RELATIVE_PATH))) {
      return current;
    }
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }

  const fallback = path.resolve(startDir, "..", "..");
  if (existsSync(path.join(fallback, CLI_RELATIVE_PATH))) {
    return fallback;
  }

  throw new Error("Could not locate the root Hermsec CLI build.");
}

export function defaultProjectDir(): string {
  const root = findHermsecRoot();
  const labProject = path.join(root, "Test projects", "hermsec-node-express-vuln-lab");
  return existsSync(labProject) ? labProject : root;
}

function normalizeScanMode(_mode?: ScanProjectRequest["mode"]): "online" {
  return "online";
}

function defaultReportDir(): string {
  return path.join(app.getPath("documents"), "Hermsec", "reports");
}

function normalizeAssistMode(mode?: ScanProjectRequest["assistMode"]): HermsecScanAssistMode {
  return mode === "deep-assisted" ? "deep-assisted" : "scanner-model-summary";
}

function normalizeSummary(summary?: Partial<ScanSummary>): ScanSummary | undefined {
  if (!summary) return undefined;
  return {
    total: Number(summary.total ?? 0),
    critical: Number(summary.critical ?? 0),
    high: Number(summary.high ?? 0),
    medium: Number(summary.medium ?? 0),
    low: Number(summary.low ?? 0),
    info: Number(summary.info ?? 0),
  };
}

function parseCliJson(stdout: string): CliOutcome {
  const trimmed = stdout.trim();
  if (!trimmed) {
    throw new Error("Hermsec CLI returned no JSON output.");
  }

  try {
    return JSON.parse(trimmed) as CliOutcome;
  } catch {
    const objectStart = trimmed.indexOf("{");
    const objectEnd = trimmed.lastIndexOf("}");
    if (objectStart >= 0 && objectEnd > objectStart) {
      return JSON.parse(trimmed.slice(objectStart, objectEnd + 1)) as CliOutcome;
    }
    throw new Error("Hermsec CLI returned output that was not valid JSON.");
  }
}

function collectOutput(chunk: unknown, current: string): string {
  const next = `${current}${Buffer.isBuffer(chunk) ? chunk.toString("utf8") : String(chunk)}`;
  if (next.length > MAX_OUTPUT_CHARS) {
    return next.slice(next.length - MAX_OUTPUT_CHARS);
  }
  return next;
}

export async function scanProject(
  request: ScanProjectRequest = {},
  onProgress?: ScanProgressCallback,
): Promise<ScanProjectResult> {
  if (activeScan) {
    return {
      ok: false,
      message: "A scan is already running. Stop or restart it before starting another scan.",
      error: "scan-already-running",
    };
  }

  const control: ActiveScanControl = { canceled: false };
  activeScan = control;

  try {
    const root = findHermsecRoot();
    const cliPath = path.join(root, CLI_RELATIVE_PATH);
    const targetPath = path.resolve(root, request.targetPath || defaultProjectDir());
    const reportDir = path.resolve(request.reportDir || defaultReportDir());
    const mode = normalizeScanMode(request.mode);
    const assistMode = normalizeAssistMode(request.assistMode);

    if (!existsSync(targetPath)) {
      return {
        ok: false,
        message: `Project folder was not found: ${targetPath}`,
        targetPath,
        reportDir,
        error: "target-not-found",
      };
    }

    mkdirSync(reportDir, { recursive: true });

    const currentProjectState = getProjectStateFingerprint(targetPath);
    if (request.skipIfUnchanged && !projectStateChanged(request.previousProjectState, currentProjectState)) {
      return {
        ok: true,
        unchanged: true,
        message: "No project changes since the last scan.",
        targetPath,
        reportDir,
        projectState: currentProjectState,
      };
    }

    const scanStartedMs = Date.now();
    const scanStartedAt = new Date(scanStartedMs).toISOString();
    emitInitialProgress(onProgress, assistMode);

    const args = [
      cliPath,
      "scan",
      targetPath,
      "--mode",
      mode,
      "--assist-mode",
      assistMode,
      "--out",
      reportDir,
      "--json",
      "--html",
    ];

    if (request.useModel === false) {
      args.push("--no-model");
    }

    const cli = await runWithStageProgress(root, args, control, onProgress, assistMode);
    throwIfCanceled(control);
    const parsed = parseCliJson(cli.stdout);
    const summary = normalizeSummary(parsed.data?.scan?.summary);
    const htmlPath = parsed.data?.report?.htmlPath;
    const actualReportDir = htmlPath ? path.dirname(htmlPath) : latestReportDir(reportDir) ?? reportDir;
    emitToolProgressFromReport(actualReportDir, onProgress);
    emitProgress(
      onProgress,
      "evidence-merge",
      "Scanner evidence merge",
      "running",
      assistMode === "deep-assisted"
        ? "Merging matching findings across scanners for deep assisted review."
        : "Preparing scanner-confirmed evidence summary.",
    );
    const assistArtifactPath = writeScanAssistArtifact(actualReportDir, assistMode);
    emitProgress(
      onProgress,
      "evidence-merge",
      "Scanner evidence merge",
      assistArtifactPath ? "completed" : "skipped",
      assistArtifactPath
        ? "Scanner evidence map was written for the report."
        : "No scanner evidence map was needed for this report.",
    );
    emitProgress(onProgress, "report-generation", "Report generation", "running", "Writing dashboard and one-page report artifacts.");
    const finishedAt = new Date().toISOString();
    const scanMetadata: LocalScanMetadata = {
      projectPath: parsed.data?.scan?.target ?? targetPath,
      reportDir: actualReportDir,
      scanId: parsed.data?.scan?.id ?? `scan-${scanStartedMs}`,
      mode,
      assistMode,
      assistModeLabel: assistModeLabel(assistMode),
      startedAt: scanStartedAt,
      finishedAt,
      reportGeneratedAt: finishedAt,
      durationMs: Number(parsed.data?.scan?.durationMs ?? Date.now() - scanStartedMs),
      ...(currentProjectState.gitBranch ? { gitBranch: currentProjectState.gitBranch } : {}),
      ...(currentProjectState.gitHead ? { gitCommit: currentProjectState.gitHead } : {}),
      ...(typeof currentProjectState.gitDirty === "boolean" ? { dirtyWorkingTree: currentProjectState.gitDirty } : {}),
      projectStateKind: currentProjectState.kind,
      projectFingerprint: currentProjectState.fingerprint,
    };
    throwIfCanceled(control);
    const artifacts = await generateReportArtifacts(actualReportDir, currentProjectState, scanMetadata);
    throwIfCanceled(control);
    emitProgress(onProgress, "report-generation", "Report generation", "completed", "Dashboard artifacts were written.");
    emitProgress(
      onProgress,
      "pdf-generation",
      "PDF generation",
      artifacts.onepagerPdfPath ? "completed" : "skipped",
      artifacts.onepagerPdfPath ? "One-page PDF was generated." : "PDF generation was skipped by Electron.",
    );

    return {
      ok: parsed.ok !== false && cli.exitCode === 0,
      message: parsed.message ?? "Scan completed.",
      targetPath: parsed.data?.scan?.target ?? targetPath,
      reportDir: actualReportDir,
      ...(htmlPath ? { htmlPath } : {}),
      dashboardHtmlPath: artifacts.dashboardHtmlPath,
      onepagerHtmlPath: artifacts.onepagerHtmlPath,
      ...(artifacts.onepagerPdfPath ? { onepagerPdfPath: artifacts.onepagerPdfPath } : {}),
      ...(parsed.data?.scan?.id ? { scanId: parsed.data.scan.id } : {}),
      assistMode,
      assistModeLabel: assistModeLabel(assistMode),
      ...(assistArtifactPath ? { assistArtifactPath } : {}),
      ...(summary ? { summary } : {}),
      ...(parsed.data?.scan?.durationMs ? { durationMs: parsed.data.scan.durationMs } : {}),
      projectState: currentProjectState,
    };
  } catch (error) {
    if (error instanceof ScanCanceledError) {
      emitCanceledProgress(onProgress);
      return {
        ok: false,
        canceled: true,
        message: "Scan stopped.",
        error: "scan-canceled",
      };
    }
    return {
      ok: false,
      message: error instanceof Error ? error.message : "Hermsec scan failed.",
      error: error instanceof Error ? error.message : String(error),
    };
  } finally {
    if (activeScan === control) {
      activeScan = null;
    }
  }
}

async function runWithStageProgress(
  cwd: string,
  args: string[],
  control: ActiveScanControl,
  onProgress?: ScanProgressCallback,
  assistMode: HermsecScanAssistMode = "scanner-model-summary",
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  let index = 0;
  emitProgress(
    onProgress,
    PROGRESS_STAGES[index].id,
    PROGRESS_STAGES[index].label,
    "running",
    progressRunningMessage(PROGRESS_STAGES[index].id, PROGRESS_STAGES[index].label, assistMode),
  );

  const timer = setInterval(() => {
    const previous = PROGRESS_STAGES[index];
    if (previous && index < PROGRESS_STAGES.length - 3) {
      emitProgress(onProgress, previous.id, previous.label, "completed", `${previous.label} stage finished or moved forward.`);
    }
    index = Math.min(index + 1, PROGRESS_STAGES.length - 3);
    const current = PROGRESS_STAGES[index];
    emitProgress(onProgress, current.id, current.label, "running", progressRunningMessage(current.id, current.label, assistMode));
  }, 3500);

  try {
    return await runNodeCli(cwd, args, control);
  } finally {
    clearInterval(timer);
  }
}

export function cancelActiveScan(): ScanControlResult {
  if (!activeScan) {
    return { ok: false, message: "No scan is currently running." };
  }

  activeScan.canceled = true;
  if (activeScan.child?.pid) {
    killProcessTree(activeScan.child);
  }
  return { ok: true, message: "Scan stop requested." };
}

function throwIfCanceled(control: ActiveScanControl): void {
  if (control.canceled) {
    throw new ScanCanceledError();
  }
}

function emitInitialProgress(onProgress?: ScanProgressCallback, assistMode: HermsecScanAssistMode = "scanner-model-summary"): void {
  for (const stage of PROGRESS_STAGES) {
    emitProgress(onProgress, stage.id, stage.label, "waiting", progressQueuedMessage(stage.id, stage.label, assistMode));
  }
}

function emitProgress(
  onProgress: ScanProgressCallback | undefined,
  id: string,
  label: string,
  status: ScanProgressEvent["status"],
  message?: string,
): void {
  onProgress?.({
    id,
    label,
    status,
    ...(message ? { message } : {}),
    timestamp: Date.now(),
  });
}

function progressQueuedMessage(id: string, label: string, assistMode: HermsecScanAssistMode): string {
  if (id === "evidence-merge") {
    return assistMode === "deep-assisted"
      ? "Deep assisted evidence merge is queued."
      : "Scanner evidence summary is queued.";
  }
  if (id === "agent-review") {
    return assistMode === "deep-assisted"
      ? "Deep model-supported triage is queued after scanner evidence."
      : "Model summary is queued after scanner evidence.";
  }
  return `${label} is queued.`;
}

function progressRunningMessage(id: string, label: string, assistMode: HermsecScanAssistMode): string {
  if (id === "evidence-merge") {
    return assistMode === "deep-assisted"
      ? "Matching scanner findings are being merged."
      : "Scanner-confirmed evidence is being summarized.";
  }
  if (id === "agent-review") {
    return assistMode === "deep-assisted"
      ? "Model is supporting triage over scanner-confirmed groups."
      : "Model is summarizing scanner-backed findings.";
  }
  return `${label} is running.`;
}

function emitCanceledProgress(onProgress?: ScanProgressCallback): void {
  for (const stage of PROGRESS_STAGES) {
    emitProgress(onProgress, stage.id, stage.label, "canceled", "Scan was stopped by the user.");
  }
}

function emitToolProgressFromReport(reportDir: string, onProgress?: ScanProgressCallback): void {
  const documentPath = path.join(reportDir, "report-document.json");
  if (!existsSync(documentPath)) return;

  try {
    const document = JSON.parse(readFileSync(documentPath, "utf8")) as {
      tools?: Array<{ id?: string; label?: string; status?: string; message?: string }>;
    };
    const tools = document.tools ?? [];
    const mappings: Array<[RegExp, string, string]> = [
      [/hermsec/i, "hermsec-heuristics", "Hermsec heuristics"],
      [/semgrep/i, "semgrep", "Semgrep"],
      [/gitleaks/i, "gitleaks", "Gitleaks"],
      [/bandit/i, "bandit", "Bandit"],
      [/osv/i, "osv", "OSV dependency checks"],
      [/pip-audit/i, "pip-audit", "pip-audit"],
      [/pmg|safedep/i, "pmg", "SafeDep PMG npm audit"],
      [/intel|vulnerab/i, "vuln-intel", "Online vulnerability intelligence"],
    ];

    for (const [pattern, id, label] of mappings) {
      const matches = tools.filter((tool) => pattern.test(`${tool.id ?? ""} ${tool.label ?? ""}`));
      if (matches.length === 0) {
        emitProgress(onProgress, id, label, "skipped", `${label} had no matching inputs in this project.`);
        continue;
      }
      const failed = matches.find((tool) => tool.status === "failed");
      const completed = matches.find((tool) => tool.status === "completed" || tool.status === "ready");
      const skipped = matches.every((tool) => tool.status === "skipped");
      const status = failed ? "failed" : completed ? "completed" : skipped ? "skipped" : "completed";
      const message = failed?.message ?? completed?.message ?? matches[0]?.message ?? `${label} status recorded.`;
      emitProgress(onProgress, id, label, status, message);
    }
  } catch {
    // Progress is helpful, but never allowed to fail the scan.
  }
}

function latestReportDir(configuredReportDir: string): string | undefined {
  try {
    const entries = readdirSync(configuredReportDir, { withFileTypes: true })
      .filter((entry: import("node:fs").Dirent) => entry.isDirectory())
      .map((entry: import("node:fs").Dirent) => path.join(configuredReportDir, entry.name))
      .filter((entryPath: string) => existsSync(path.join(entryPath, "report-document.json")) || existsSync(path.join(entryPath, "summary.json")))
      .sort((a: string, b: string) => statSync(b).mtimeMs - statSync(a).mtimeMs);
    return entries[0];
  } catch {
    return undefined;
  }
}

function runNodeCli(
  cwd: string,
  args: string[],
  control: ActiveScanControl,
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  return new Promise((resolve, reject) => {
    const nodeBinary = process.platform === "win32" ? "node.exe" : "node";
    const child = spawn(nodeBinary, args, {
      cwd,
      env: process.env,
      windowsHide: true,
    });
    control.child = child;

    let stdout = "";
    let stderr = "";
    const timer = windowlessTimeout(() => {
      killProcessTree(child);
      reject(new Error(`Hermsec scan timed out after ${DEFAULT_SCAN_TIMEOUT_MS / 1000}s.`));
    }, DEFAULT_SCAN_TIMEOUT_MS);

    child.stdout.on("data", (chunk) => {
      stdout = collectOutput(chunk, stdout);
    });
    child.stderr.on("data", (chunk) => {
      stderr = collectOutput(chunk, stderr);
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on("close", (exitCode) => {
      clearTimeout(timer);
      if (control.child === child) {
        delete control.child;
      }
      if (control.canceled) {
        reject(new ScanCanceledError());
        return;
      }
      if (exitCode && !stdout.trim()) {
        reject(new Error(stderr.trim() || `Hermsec CLI exited with code ${exitCode}.`));
        return;
      }
      resolve({ stdout, stderr, exitCode: exitCode ?? 0 });
    });
  });
}

function killProcessTree(child: ChildProcessWithoutNullStreams): void {
  if (!child.pid) return;
  if (process.platform === "win32") {
    spawn("taskkill.exe", ["/PID", String(child.pid), "/T", "/F"], { windowsHide: true });
    return;
  }
  child.kill("SIGTERM");
}

function windowlessTimeout(callback: () => void, ms: number): NodeJS.Timeout {
  return setTimeout(callback, ms);
}

export async function openReportLocation(
  request: OpenReportLocationRequest,
): Promise<OpenReportLocationResult> {
  try {
    const target = path.resolve(request.path);
    if (!existsSync(target)) {
      return { ok: false, message: `Path not found: ${target}` };
    }

    const stat = statSync(target);
    if (stat.isDirectory()) {
      const error = await shell.openPath(target);
      return error ? { ok: false, message: error } : { ok: true, message: target };
    }

    shell.showItemInFolder(target);
    return { ok: true, message: target };
  } catch (error) {
    return {
      ok: false,
      message: error instanceof Error ? error.message : "Could not open report location.",
    };
  }
}
