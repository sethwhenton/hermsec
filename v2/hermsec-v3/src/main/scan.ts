import { shell } from "electron";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import type {
  OpenReportLocationRequest,
  OpenReportLocationResult,
  ScanProgressEvent,
  ScanProjectRequest,
  ScanProjectResult,
  ScanSummary,
} from "../renderer/src/types/scan";
import { generateReportArtifacts } from "./reportArtifacts";
import { getProjectStateFingerprint, projectStateChanged } from "./projectState";

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

const PROGRESS_STAGES = [
  { id: "hermsec-heuristics", label: "Hermsec heuristics" },
  { id: "semgrep", label: "Semgrep" },
  { id: "gitleaks", label: "Gitleaks" },
  { id: "bandit", label: "Bandit" },
  { id: "osv", label: "OSV dependency checks" },
  { id: "pip-audit", label: "pip-audit" },
  { id: "pmg", label: "SafeDep PMG npm audit" },
  { id: "vuln-intel", label: "Online vulnerability intelligence" },
  { id: "agent-review", label: "Agent report review" },
  { id: "report-generation", label: "Report generation" },
  { id: "pdf-generation", label: "PDF generation" },
];

export function findHermsecRoot(startDir = process.cwd()): string {
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
  try {
    const root = findHermsecRoot();
    const cliPath = path.join(root, CLI_RELATIVE_PATH);
    const targetPath = path.resolve(root, request.targetPath || defaultProjectDir());
    const reportDir = path.resolve(root, request.reportDir || path.join(root, ".hermsec", "v3-reports"));
    const mode = normalizeScanMode(request.mode);

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

    emitInitialProgress(onProgress);

    const args = [
      cliPath,
      "scan",
      targetPath,
      "--mode",
      mode,
      "--out",
      reportDir,
      "--json",
      "--html",
    ];

    if (request.useModel === false) {
      args.push("--no-model");
    }

    const cli = await runWithStageProgress(root, args, onProgress);
    const parsed = parseCliJson(cli.stdout);
    const summary = normalizeSummary(parsed.data?.scan?.summary);
    const htmlPath = parsed.data?.report?.htmlPath;
    const actualReportDir = htmlPath ? path.dirname(htmlPath) : latestReportDir(reportDir) ?? reportDir;
    emitToolProgressFromReport(actualReportDir, onProgress);
    emitProgress(onProgress, "report-generation", "Report generation", "running", "Writing dashboard and one-page report artifacts.");
    const artifacts = await generateReportArtifacts(actualReportDir, currentProjectState);
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
      ...(summary ? { summary } : {}),
      ...(parsed.data?.scan?.durationMs ? { durationMs: parsed.data.scan.durationMs } : {}),
      projectState: currentProjectState,
    };
  } catch (error) {
    return {
      ok: false,
      message: error instanceof Error ? error.message : "Hermsec scan failed.",
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

async function runWithStageProgress(
  cwd: string,
  args: string[],
  onProgress?: ScanProgressCallback,
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  let index = 0;
  emitProgress(
    onProgress,
    PROGRESS_STAGES[index].id,
    PROGRESS_STAGES[index].label,
    "running",
    `${PROGRESS_STAGES[index].label} is running.`,
  );

  const timer = setInterval(() => {
    const previous = PROGRESS_STAGES[index];
    if (previous && index < PROGRESS_STAGES.length - 3) {
      emitProgress(onProgress, previous.id, previous.label, "completed", `${previous.label} stage finished or moved forward.`);
    }
    index = Math.min(index + 1, PROGRESS_STAGES.length - 3);
    const current = PROGRESS_STAGES[index];
    emitProgress(onProgress, current.id, current.label, "running", `${current.label} is running.`);
  }, 3500);

  try {
    return await runNodeCli(cwd, args);
  } finally {
    clearInterval(timer);
  }
}

function emitInitialProgress(onProgress?: ScanProgressCallback): void {
  for (const stage of PROGRESS_STAGES) {
    emitProgress(onProgress, stage.id, stage.label, "waiting", `${stage.label} is queued.`);
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

function runNodeCli(cwd: string, args: string[]): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  return new Promise((resolve, reject) => {
    const nodeBinary = process.platform === "win32" ? "node.exe" : "node";
    const child = spawn(nodeBinary, args, {
      cwd,
      env: process.env,
      windowsHide: true,
    });

    let stdout = "";
    let stderr = "";
    const timer = windowlessTimeout(() => {
      child.kill("SIGKILL");
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
      if (exitCode && !stdout.trim()) {
        reject(new Error(stderr.trim() || `Hermsec CLI exited with code ${exitCode}.`));
        return;
      }
      resolve({ stdout, stderr, exitCode: exitCode ?? 0 });
    });
  });
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
