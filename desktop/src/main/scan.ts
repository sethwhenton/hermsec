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
import { prepareScannersForProject, scannerEnvForCli, scannerStatuses } from "./scanners";
import type { ScannerStatusItem } from "../renderer/src/types/scanners";

const CLI_RELATIVE_PATH = path.join("dist", "src", "bin", "hermsec.js");
const DEFAULT_SCAN_TIMEOUT_MS = 180_000;
const MAX_OUTPUT_CHARS = 30_000_000;
const HERMSEC_PROGRESS_PREFIX = "HERMSEC_PROGRESS ";

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

type RootScanProgressEvent = {
  schemaVersion?: string;
  id?: string;
  stage?: "repository" | "scanner" | "model" | "report";
  scannerId?: string;
  label?: string;
  status?: string;
  message?: string;
  details?: Array<{ id?: string; label?: string; status?: string; message?: string; value?: string }>;
  findingCount?: number;
  durationMs?: number;
  assistMode?: HermsecScanAssistMode;
  timestamp?: string;
};

type ActiveScanControl = {
  child?: ChildProcessWithoutNullStreams;
  canceled: boolean;
};

type ProjectProfile = {
  fileCount: number;
  truncated: boolean;
  languages: string[];
  frameworks: string[];
  manifests: string[];
  lockfiles: string[];
  iac: string[];
};

type ScannerPlanItem = {
  id: string;
  label: string;
  reason: string;
  status: ScanProgressEvent["status"];
  message: string;
  adapter: "current" | "planned";
  command?: string;
};

class ScanCanceledError extends Error {
  constructor() {
    super("Scan stopped.");
    this.name = "ScanCanceledError";
  }
}

let activeScan: ActiveScanControl | null = null;

const MAIN_PROGRESS_STAGES = [
  { id: "inspect-project", label: "Inspecting project" },
  { id: "choose-tools", label: "Choosing scanner tools" },
  { id: "prepare-tools", label: "Preparing tools" },
  { id: "running-scans", label: "Running scans" },
  { id: "model-summary", label: "Model summary" },
  { id: "report-ready", label: "Report ready" },
] as const;

const MIN_VISIBLE_STAGE_MS = 2_000;

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
  const trimmed = stripProgressLines(stdout).trim();
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

function stripProgressLines(value: string): string {
  return value
    .split(/\r?\n/)
    .filter((line) => !line.startsWith(HERMSEC_PROGRESS_PREFIX))
    .join("\n");
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

    const profile = await timedStage(
      onProgress,
      "inspect-project",
      "Inspecting project",
      "Scanning to see which tools this project needs...",
      async () => inspectProject(targetPath),
      (inspected) => ({
        message: profileSummary(inspected),
        details: profileDetails(inspected),
        chips: profileChips(inspected),
      }),
    );

    let scannerPlan = await timedStage(
      onProgress,
      "choose-tools",
      "Choosing scanner tools",
      "Choosing scanners for the detected project shape...",
      async () => buildScannerPlan(profile, targetPath),
      (plan) => ({
        message: `${plan.filter((item) => item.adapter === "current").length} runnable scanner tool${plan.filter((item) => item.adapter === "current").length === 1 ? "" : "s"} selected.`,
        details: plan.map(planDetail),
        chips: profileChips(profile),
      }),
    );

    await timedStage(
      onProgress,
      "prepare-tools",
      "Preparing tools",
      "Preparing scanner tools for this project...",
      async () => {
        scannerPlan = scannerPlanFromStatuses(await prepareScannersForProject(targetPath));
        return scannerPlan;
      },
      (plan) => ({
        message: preparationSummary(plan),
        details: plan.map(planDetail),
        chips: toolChips(plan),
      }),
    );

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

    const cli = await runWithStageProgress(root, args, control, onProgress, assistMode, scannerPlan, targetPath);
    throwIfCanceled(control);
    const parsed = parseCliJson(cli.stdout);
    const summary = normalizeSummary(parsed.data?.scan?.summary);
    const htmlPath = parsed.data?.report?.htmlPath;
    const actualReportDir = htmlPath ? path.dirname(htmlPath) : latestReportDir(reportDir) ?? reportDir;
    emitToolProgressFromReport(actualReportDir, onProgress);
    const modelStageLabel = progressStageLabel("model-summary", "Model summary", assistMode);
    emitProgress(
      onProgress,
      "model-summary",
      modelStageLabel,
      "running",
      assistMode === "deep-assisted"
        ? "Reviewing model-supported scanner evidence."
        : "Summarizing scanner-backed evidence.",
      { assistMode, assistModeLabel: assistModeLabel(assistMode) },
    );
    const assistArtifactPath = writeScanAssistArtifact(actualReportDir, assistMode);
    emitProgress(
      onProgress,
      "model-summary",
      modelStageLabel,
      assistArtifactPath ? "completed" : "skipped",
      assistArtifactPath
        ? "Scanner evidence map was written for the report."
        : "No model summary artifact was needed for this report.",
      {
        assistMode,
        assistModeLabel: assistModeLabel(assistMode),
        details: [
          {
            label: assistModeLabel(assistMode),
            status: assistArtifactPath ? "completed" : "skipped",
            message: assistMode === "deep-assisted"
              ? "Scanner-matched evidence is ready for deeper triage."
              : "Scanner-backed summary is ready.",
          },
        ],
      },
    );
    emitProgress(onProgress, "report-ready", "Report ready", "running", "Writing dashboard and one-page report artifacts.");
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
    emitProgress(onProgress, "report-ready", "Report ready", "completed", "Dashboard artifacts were written.", {
      details: [
        { label: "Dashboard", status: "completed", message: "Interactive report bundle was written." },
        {
          label: "One-page PDF",
          status: artifacts.onepagerPdfPath ? "completed" : "skipped",
          message: artifacts.onepagerPdfPath ? "PDF was generated." : "PDF generation was skipped by Electron.",
        },
      ],
    });
    emitProgress(
      onProgress,
      "report-pdf",
      "PDF generation",
      artifacts.onepagerPdfPath ? "completed" : "skipped",
      artifacts.onepagerPdfPath ? "One-page PDF was generated." : "PDF generation was skipped by Electron.",
      { parentId: "report-ready" },
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
  scannerPlan: ScannerPlanItem[] = [],
  targetPath?: string,
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  const runnablePlan = scannerPlan.filter((item) => item.adapter === "current" && item.status === "completed");
  emitProgress(
    onProgress,
    "running-scans",
    "Running scans",
    "running",
    "Running selected scanner tools...",
    {
      details: runnablePlan.length > 0
        ? [
            {
              id: "scanner-engine",
              label: "HermSec scanner engine",
              status: "running" as const,
              message: "Running the selected scanner command. Per-tool results update when each scanner writes its status.",
            },
            ...runnablePlan.map((item) => ({
              id: item.id,
              label: item.label,
              status: "waiting" as const,
              message: "Selected for this project. Waiting for the scanner status report.",
            })),
          ]
        : [{ id: "scanner-engine", label: "HermSec scanner engine", status: "running" as const, message: "Running built-in deterministic checks." }],
    },
  );

  const timer = setInterval(() => {
    emitProgress(
      onProgress,
      "running-scans",
      "Running scans",
      "running",
      "Scanner process is still running; exact tool statuses will appear from the report.",
      {
        details: runnablePlan.length > 0
          ? [
              {
                id: "scanner-engine",
                label: "HermSec scanner engine",
                status: "running" as const,
                message: "HermSec is waiting for the scanner process to finish.",
              },
              ...runnablePlan.map((item) => ({
                id: item.id,
                label: item.label,
                status: "waiting" as const,
                message: "Selected for this project.",
              })),
            ]
          : [{ id: "scanner-engine", label: "HermSec scanner engine", status: "running" as const, message: "Built-in deterministic checks are running." }],
      },
    );
  }, 5000);

  try {
    const result = await runNodeCli(
      cwd,
      args,
      control,
      targetPath ? scannerEnvForCli(targetPath) : undefined,
      onProgress,
      assistMode,
    );
    emitProgress(
      onProgress,
      "running-scans",
      "Running scans",
      "completed",
      "Scanner execution completed. Reading scanner status report.",
      {
        details: runnablePlan.length > 0
          ? [
              {
                id: "scanner-engine",
                label: "HermSec scanner engine",
                status: "completed" as const,
                message: "Scanner process finished.",
              },
              ...runnablePlan.map((item) => ({
                id: item.id,
                label: item.label,
                status: "waiting" as const,
                message: "Waiting for recorded scanner status.",
              })),
            ]
          : [{ id: "scanner-engine", label: "HermSec scanner engine", status: "completed" as const, message: "Built-in deterministic checks completed." }],
      },
    );
    return result;
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
  emitProgress(
    onProgress,
    "scan-assist-mode",
    assistModeLabel(assistMode),
    "completed",
    `${assistModeLabel(assistMode)} selected for this run.`,
    { assistMode, assistModeLabel: assistModeLabel(assistMode) },
  );
  for (const stage of MAIN_PROGRESS_STAGES) {
    const label = progressStageLabel(stage.id, stage.label, assistMode);
    emitProgress(onProgress, stage.id, label, "waiting", progressQueuedMessage(stage.id, label, assistMode), {
      assistMode,
      assistModeLabel: assistModeLabel(assistMode),
    });
  }
}

function emitProgress(
  onProgress: ScanProgressCallback | undefined,
  id: string,
  label: string,
  status: ScanProgressEvent["status"],
  message?: string,
  options: {
    parentId?: string;
    details?: ScanProgressEvent["details"];
    chips?: string[];
    assistMode?: HermsecScanAssistMode;
    assistModeLabel?: string;
  } = {},
): void {
  onProgress?.({
    id,
    label,
    status,
    ...(message ? { message } : {}),
    ...(options.parentId ? { parentId: options.parentId } : {}),
    ...(options.details ? { details: options.details } : {}),
    ...(options.chips ? { chips: options.chips } : {}),
    ...(options.assistMode ? { assistMode: options.assistMode } : {}),
    ...(options.assistModeLabel ? { assistModeLabel: options.assistModeLabel } : {}),
    timestamp: Date.now(),
  });
}

function progressStageLabel(id: string, fallback: string, assistMode: HermsecScanAssistMode): string {
  if (id === "model-summary" && assistMode === "deep-assisted") {
    return "Deep model triage";
  }
  return fallback;
}

function progressQueuedMessage(id: string, label: string, assistMode: HermsecScanAssistMode): string {
  if (id === "model-summary") {
    return assistMode === "deep-assisted"
      ? "Deep model-supported triage is queued after scanner evidence."
      : "Model summary is queued after scanner evidence.";
  }
  return `${label} is queued.`;
}

function progressRunningMessage(id: string, label: string, assistMode: HermsecScanAssistMode): string {
  if (id === "model-summary") {
    return assistMode === "deep-assisted"
      ? "Model is supporting triage over scanner-confirmed groups."
      : "Model is summarizing scanner-backed findings.";
  }
  return `${label} is running.`;
}

async function timedStage<T>(
  onProgress: ScanProgressCallback | undefined,
  id: string,
  label: string,
  runningMessage: string,
  task: () => Promise<T> | T,
  completed: (value: T) => {
    message?: string;
    details?: ScanProgressEvent["details"];
    chips?: string[];
  },
): Promise<T> {
  const started = Date.now();
  emitProgress(onProgress, id, label, "running", runningMessage);
  const value = await task();
  const remaining = MIN_VISIBLE_STAGE_MS - (Date.now() - started);
  if (remaining > 0) {
    await delay(remaining);
  }
  const payload = completed(value);
  emitProgress(onProgress, id, label, "completed", payload.message, {
    details: payload.details,
    chips: payload.chips,
  });
  return value;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function inspectProject(targetPath: string): ProjectProfile {
  const files: string[] = [];
  const maxFiles = 4_000;
  const ignored = new Set([
    ".git",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "coverage",
    ".next",
    ".nuxt",
    ".cache",
    ".hermsec",
    "__pycache__",
  ]);
  const pending = [targetPath];
  let truncated = false;

  while (pending.length > 0 && files.length < maxFiles) {
    const directory = pending.pop();
    if (!directory) continue;
    let entries;
    try {
      entries = readdirSync(directory, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      const absolutePath = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        if (!ignored.has(entry.name)) {
          pending.push(absolutePath);
        }
        continue;
      }
      if (!entry.isFile()) continue;
      files.push(path.relative(targetPath, absolutePath).replace(/\\/g, "/"));
      if (files.length >= maxFiles) {
        truncated = true;
        break;
      }
    }
  }

  const names = new Set(files.map((file) => path.basename(file)));
  const lowerNames = new Set(files.map((file) => file.toLowerCase()));
  const languages = new Set<string>();
  const frameworks = new Set<string>();
  const manifests = new Set<string>();
  const lockfiles = new Set<string>();
  const iac = new Set<string>();

  for (const file of files) {
    const base = path.basename(file);
    const ext = path.extname(file).toLowerCase();
    const lower = file.toLowerCase();
    const language = languageForExtension(ext, base);
    if (language) languages.add(language);
    if (isManifest(base)) manifests.add(base);
    if (isLockfile(base)) lockfiles.add(base);
    if (isIacFile(lower, base, ext)) iac.add(iacLabel(lower, base, ext));
  }

  if (names.has("package.json")) {
    const packageJson = readJsonFile(path.join(targetPath, "package.json"));
    const deps = {
      ...(recordValue(packageJson?.dependencies)),
      ...(recordValue(packageJson?.devDependencies)),
    };
    if (deps.react) frameworks.add("React");
    if (deps.next) frameworks.add("Next.js");
    if (deps.vue) frameworks.add("Vue");
    if (deps.svelte) frameworks.add("Svelte");
    if (deps.vite || names.has("vite.config.ts") || names.has("vite.config.js")) frameworks.add("Vite");
  }

  if (names.has("pom.xml")) frameworks.add("Maven");
  if ([...lowerNames].some((file) => file.endsWith("build.gradle") || file.endsWith("build.gradle.kts"))) {
    frameworks.add("Gradle");
  }
  if (names.has("Cargo.toml")) frameworks.add("Cargo");
  if (names.has("composer.json")) frameworks.add("Composer");

  return {
    fileCount: files.length,
    truncated,
    languages: sorted(languages),
    frameworks: sorted(frameworks),
    manifests: sorted(manifests),
    lockfiles: sorted(lockfiles),
    iac: sorted(iac),
  };
}

function buildScannerPlan(_profile: ProjectProfile, targetPath: string): ScannerPlanItem[] {
  return scannerPlanFromStatuses(scannerStatuses({ projectPath: targetPath }));
}

function scannerPlanFromStatuses(statuses: ScannerStatusItem[]): ScannerPlanItem[] {
  return statuses
    .filter((scanner) => scanner.enabled && scanner.usedByCurrentProject !== false)
    .map((scanner) => {
      const ready = scanner.status === "installed" || scanner.status === "built-in";
      const failed = scanner.status === "failed";
      return {
        id: scanner.id,
        label: scanner.label,
        reason: scanner.riskNotes,
        status: ready ? "completed" : failed ? "failed" : "skipped",
        message: ready ? scanner.message : failed ? scanner.message : `${scanner.label} is not installed; HermSec will continue with ready scanners.`,
        adapter: "current",
        ...(scanner.command ? { command: scanner.command } : {}),
      };
    });
}

function currentScanner(id: string, label: string, reason: string, command: string | undefined): ScannerPlanItem {
  if (!command) {
    return {
      id,
      label,
      reason,
      status: "completed",
      message: "Built into Hermsec.",
      adapter: "current",
    };
  }
  const ready = commandReady(command);
  return {
    id,
    label,
    reason,
    status: ready ? "completed" : "skipped",
    message: ready ? "Tool ready." : "Tool missing; scan will continue with remaining coverage.",
    adapter: "current",
    command,
  };
}

function plannedScanner(id: string, label: string, message: string): ScannerPlanItem {
  return {
    id,
    label,
    reason: message,
    status: "skipped",
    message,
    adapter: "planned",
  };
}

function planDetail(item: ScannerPlanItem): NonNullable<ScanProgressEvent["details"]>[number] {
  return {
    id: item.id,
    label: item.label,
    status: item.status,
    message: item.message,
    value: item.adapter === "planned" ? "planned" : item.status === "completed" ? "ready" : item.status === "failed" ? "failed" : "skipped",
  };
}

function profileDetails(profile: ProjectProfile): NonNullable<ScanProgressEvent["details"]> {
  return [
    {
      label: "Files inspected",
      status: "completed",
      value: profile.truncated ? `${profile.fileCount}+` : String(profile.fileCount),
      message: profile.truncated ? "Inspection hit the preview limit." : "Repository profile completed.",
    },
    {
      label: "Languages",
      status: profile.languages.length > 0 ? "completed" : "skipped",
      value: profile.languages.slice(0, 5).join(", ") || "none",
    },
    {
      label: "Frameworks",
      status: profile.frameworks.length > 0 ? "completed" : "skipped",
      value: profile.frameworks.slice(0, 5).join(", ") || "none",
    },
    {
      label: "Lockfiles",
      status: profile.lockfiles.length > 0 ? "completed" : "skipped",
      value: profile.lockfiles.slice(0, 4).join(", ") || "none",
    },
  ];
}

function profileSummary(profile: ProjectProfile): string {
  const languageText = profile.languages.slice(0, 3).join(", ") || "source files";
  const frameworkText = profile.frameworks.length > 0 ? ` with ${profile.frameworks.slice(0, 2).join(", ")}` : "";
  return `Detected ${languageText}${frameworkText}.`;
}

function preparationSummary(plan: ScannerPlanItem[]): string {
  const ready = plan.filter((item) => item.adapter === "current" && item.status === "completed").length;
  const skipped = plan.filter((item) => item.status === "skipped").length;
  const failed = plan.filter((item) => item.status === "failed").length;
  return `${ready} tool${ready === 1 ? "" : "s"} ready${failed ? `, ${failed} need attention` : ""}${skipped ? `, ${skipped} skipped/planned` : ""}.`;
}

function profileChips(profile: ProjectProfile): string[] {
  return [...profile.frameworks, ...profile.languages, ...profile.lockfiles].slice(0, 8);
}

function toolChips(plan: ScannerPlanItem[]): string[] {
  return plan.slice(0, 8).map((item) => item.label);
}

function languageForExtension(extension: string, baseName: string): string | undefined {
  if (baseName.endsWith(".gradle.kts")) return "Gradle";
  switch (extension) {
    case ".js":
    case ".jsx":
    case ".mjs":
    case ".cjs":
      return "JavaScript";
    case ".ts":
    case ".tsx":
    case ".mts":
    case ".cts":
      return "TypeScript";
    case ".py":
      return "Python";
    case ".java":
      return "Java";
    case ".jsp":
      return "JSP";
    case ".php":
      return "PHP";
    case ".rs":
      return "Rust";
    case ".go":
      return "Go";
    case ".rb":
      return "Ruby";
    case ".cs":
      return "C#";
    case ".kt":
    case ".kts":
      return "Kotlin";
    case ".swift":
      return "Swift";
    case ".dart":
      return "Dart";
    case ".html":
    case ".htm":
      return "HTML";
    case ".vue":
      return "Vue";
    case ".svelte":
      return "Svelte";
    default:
      return undefined;
  }
}

function isManifest(baseName: string): boolean {
  return [
    "package.json",
    "pyproject.toml",
    "requirements.txt",
    "requirements-dev.txt",
    "Pipfile",
    "go.mod",
    "Cargo.toml",
    "composer.json",
    "Gemfile",
    "pom.xml",
    "build.gradle",
    "settings.gradle",
    "build.gradle.kts",
    "settings.gradle.kts",
  ].includes(baseName);
}

function isLockfile(baseName: string): boolean {
  return [
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lock",
    "bun.lockb",
    "poetry.lock",
    "uv.lock",
    "Pipfile.lock",
    "go.sum",
    "Cargo.lock",
    "composer.lock",
    "Gemfile.lock",
    "gradle.lockfile",
    "packages.lock.json",
  ].includes(baseName);
}

function isIacFile(lowerPath: string, baseName: string, extension: string): boolean {
  return (
    extension === ".tf" ||
    extension === ".tfvars" ||
    baseName === "Dockerfile" ||
    lowerPath.includes(".github/workflows/") ||
    lowerPath.includes("k8s/") ||
    lowerPath.includes("kubernetes/") ||
    lowerPath.endsWith("docker-compose.yml") ||
    lowerPath.endsWith("docker-compose.yaml")
  );
}

function iacLabel(lowerPath: string, baseName: string, extension: string): string {
  if (extension === ".tf" || extension === ".tfvars") return "Terraform";
  if (baseName === "Dockerfile" || lowerPath.includes("docker-compose")) return "Docker";
  if (lowerPath.includes(".github/workflows/")) return "GitHub Actions";
  if (lowerPath.includes("k8s/") || lowerPath.includes("kubernetes/")) return "Kubernetes";
  return "IaC";
}

function commandReady(command: string): boolean {
  const override = process.env[`HERMSEC_${command.replace(/[^a-zA-Z0-9]/g, "_").toUpperCase()}_BIN`];
  if (override && existsSync(override)) return true;
  return executableOnPath(command);
}

function executableOnPath(command: string): boolean {
  const suffixes = process.platform === "win32" ? ["", ".exe", ".cmd", ".bat", ".com"] : [""];
  const entries = (process.env.PATH ?? "").split(path.delimiter).filter(Boolean);
  return entries.some((entry) => suffixes.some((suffix) => existsSync(path.join(entry, `${command}${suffix}`))));
}

function readJsonFile(filePath: string): Record<string, unknown> | undefined {
  try {
    return JSON.parse(readFileSync(filePath, "utf8")) as Record<string, unknown>;
  } catch {
    return undefined;
  }
}

function recordValue(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function sorted(values: Set<string>): string[] {
  return Array.from(values).sort((left, right) => left.localeCompare(right));
}

function hasAny(values: Set<string>, expected: string[]): boolean {
  return expected.some((value) => values.has(value));
}

function dedupePlan(plan: ScannerPlanItem[]): ScannerPlanItem[] {
  const seen = new Set<string>();
  return plan.filter((item) => {
    if (seen.has(item.id)) return false;
    seen.add(item.id);
    return true;
  });
}

function emitCanceledProgress(onProgress?: ScanProgressCallback): void {
  for (const stage of MAIN_PROGRESS_STAGES) {
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
      [/hermsec/i, "hermsec-heuristics", "HermSec heuristics"],
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
        continue;
      }
      const failed = matches.find((tool) => tool.status === "failed");
      const completed = matches.find((tool) => tool.status === "completed" || tool.status === "ready");
      const skipped = matches.every((tool) => tool.status === "skipped");
      const status = failed ? "failed" : completed ? "completed" : skipped ? "skipped" : "completed";
      const message = failed?.message ?? completed?.message ?? matches[0]?.message ?? `${label} status recorded.`;
      emitProgress(onProgress, id, label, status, message, { parentId: "running-scans" });
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
  extraEnv?: Record<string, string>,
  onProgress?: ScanProgressCallback,
  assistMode: HermsecScanAssistMode = "scanner-model-summary",
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  return new Promise((resolve, reject) => {
    const nodeBinary = process.platform === "win32" ? "node.exe" : "node";
    const child = spawn(nodeBinary, args, {
      cwd,
      env: { ...process.env, ...extraEnv },
      windowsHide: true,
    });
    control.child = child;

    let stdout = "";
    let stderr = "";
    let stdoutLineBuffer = "";
    let stderrLineBuffer = "";
    const timer = windowlessTimeout(() => {
      killProcessTree(child);
      reject(new Error(`Hermsec scan timed out after ${DEFAULT_SCAN_TIMEOUT_MS / 1000}s.`));
    }, DEFAULT_SCAN_TIMEOUT_MS);

    const handleChunk = (chunk: unknown, stream: "stdout" | "stderr") => {
      const text = Buffer.isBuffer(chunk) ? chunk.toString("utf8") : String(chunk);
      const combined = stream === "stdout" ? `${stdoutLineBuffer}${text}` : `${stderrLineBuffer}${text}`;
      const lines = combined.split(/\r?\n/);
      const remainder = lines.pop() ?? "";
      if (stream === "stdout") {
        stdoutLineBuffer = remainder;
      } else {
        stderrLineBuffer = remainder;
      }

      for (const line of lines) {
        if (consumeProgressLine(line, onProgress, assistMode)) {
          continue;
        }
        if (stream === "stdout") {
          stdout = collectOutput(`${line}\n`, stdout);
        } else {
          stderr = collectOutput(`${line}\n`, stderr);
        }
      }
    };

    const flushBufferedLines = () => {
      if (stdoutLineBuffer) {
        if (!consumeProgressLine(stdoutLineBuffer, onProgress, assistMode)) {
          stdout = collectOutput(stdoutLineBuffer, stdout);
        }
        stdoutLineBuffer = "";
      }
      if (stderrLineBuffer) {
        if (!consumeProgressLine(stderrLineBuffer, onProgress, assistMode)) {
          stderr = collectOutput(stderrLineBuffer, stderr);
        }
        stderrLineBuffer = "";
      }
    };

    child.stdout.on("data", (chunk) => {
      handleChunk(chunk, "stdout");
    });
    child.stderr.on("data", (chunk) => {
      handleChunk(chunk, "stderr");
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on("close", (exitCode) => {
      clearTimeout(timer);
      flushBufferedLines();
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

function consumeProgressLine(
  line: string,
  onProgress: ScanProgressCallback | undefined,
  fallbackAssistMode: HermsecScanAssistMode,
): boolean {
  if (!line.startsWith(HERMSEC_PROGRESS_PREFIX)) {
    return false;
  }
  try {
    const parsed = JSON.parse(line.slice(HERMSEC_PROGRESS_PREFIX.length)) as RootScanProgressEvent;
    const event = rootProgressToDesktopEvent(parsed, fallbackAssistMode);
    if (event) {
      if (event.parentId === "running-scans") {
        emitProgress(
          onProgress,
          "running-scans",
          "Running scans",
          event.status === "failed" ? "failed" : event.status === "completed" || event.status === "skipped" ? "running" : event.status,
          scannerParentMessage(event),
          {
            assistMode: event.assistMode,
            assistModeLabel: event.assistModeLabel,
          },
        );
      }
      onProgress?.(event);
    }
  } catch {
    // Progress is advisory; malformed lines must not break the scan.
  }
  return true;
}

function rootProgressToDesktopEvent(
  event: RootScanProgressEvent,
  fallbackAssistMode: HermsecScanAssistMode,
): ScanProgressEvent | undefined {
  const status = normalizeProgressStatus(event.status);
  if (!status) {
    return undefined;
  }
  const assistMode = event.assistMode === "deep-assisted" ? "deep-assisted" : fallbackAssistMode;
  const timestamp = event.timestamp ? Date.parse(event.timestamp) : Date.now();
  const details = rootProgressDetails(event, status);
  const base = {
    status,
    assistMode,
    assistModeLabel: assistModeLabel(assistMode),
    timestamp: Number.isFinite(timestamp) ? timestamp : Date.now(),
    ...(event.message ? { message: event.message } : {}),
    ...(details ? { details } : {}),
  };

  if (event.stage === "repository") {
    return {
      id: "inspect-project",
      label: "Inspecting project",
      ...base,
    };
  }

  if (event.stage === "scanner") {
    return {
      id: event.scannerId ?? event.id ?? "scanner",
      label: event.label ?? event.scannerId ?? "Scanner",
      parentId: "running-scans",
      ...base,
    };
  }

  if (event.stage === "model") {
    return {
      id: "model-summary",
      label: progressStageLabel("model-summary", event.label ?? "Model summary", assistMode),
      ...base,
    };
  }

  if (event.stage === "report") {
    return {
      id: "report-ready",
      label: "Report ready",
      ...base,
    };
  }

  if (!event.id || !event.label) {
    return undefined;
  }
  return {
    id: event.id,
    label: event.label,
    ...base,
  };
}

function normalizeProgressStatus(value: string | undefined): ScanProgressEvent["status"] | undefined {
  switch (value) {
    case "waiting":
    case "running":
    case "completed":
    case "skipped":
    case "failed":
    case "canceled":
      return value;
    case "ready":
      return "completed";
    case "missing":
      return "skipped";
    default:
      return undefined;
  }
}

function rootProgressDetails(
  event: RootScanProgressEvent,
  fallbackStatus: ScanProgressEvent["status"],
): ScanProgressEvent["details"] {
  const details = (event.details ?? []).flatMap((detail) => {
    if (!detail.label) {
      return [];
    }
    return [{
      label: detail.label,
      status: normalizeProgressStatus(detail.status) ?? fallbackStatus,
      ...(detail.id ? { id: detail.id } : {}),
      ...(detail.message ? { message: detail.message } : {}),
      ...(detail.value ? { value: detail.value } : {}),
    }];
  });
  if (event.findingCount !== undefined) {
    details.push({
      label: "Findings",
      status: fallbackStatus,
      value: String(event.findingCount),
    });
  }
  if (event.durationMs !== undefined) {
    details.push({
      label: "Duration",
      status: fallbackStatus,
      value: formatDuration(event.durationMs),
    });
  }
  return details.length > 0 ? details : undefined;
}

function scannerParentMessage(event: ScanProgressEvent): string {
  if (event.status === "running") {
    return event.message ?? `${event.label} is running.`;
  }
  if (event.status === "failed") {
    return `${event.label} reported a scanner issue; the harness will continue where possible.`;
  }
  return `Updated scanner status: ${event.label}.`;
}

function formatDuration(durationMs: number): string {
  if (durationMs < 1000) {
    return `${durationMs}ms`;
  }
  return `${(durationMs / 1000).toFixed(1)}s`;
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
