import { app, shell } from "electron";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, realpathSync, statSync } from "node:fs";
import path from "node:path";
import type {
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
import { assistModeLabel, writeScanAssistArtifact, type RuntimeScanAssistMode } from "./scanAssist";
import { createCliProcessSpec, failedScanResultFromCli } from "./cliProcess";
import {
  createVerifiedBundledRuntimeExecutionLease,
  findBundledCliRoot,
} from "./runtimeBundle";
import type { LocalScanMetadata } from "./scanMetadata";
import { modelEnvironmentVariableNames, prepareScannersForProject, scannerEnvForCli, scannerStatuses } from "./scanners";
import { runIdsMatch } from "../shared/scanRunIsolation";
import type { ScannerStatusItem } from "../renderer/src/types/scanners";

const CLI_RELATIVE_PATH = path.join("dist", "src", "bin", "hermsec.js");
const DEFAULT_SCAN_TIMEOUT_MS = 300_000;
const SCAN_TIMEOUT_MS_BY_ASSIST_MODE: Record<RuntimeScanAssistMode, number> = {
  "scanner-only": 300_000,
  "single-agent": 420_000,
  "moa-low": 600_000,
  "moa-high": 780_000,
  "scanner-single": 720_000,
  "scanner-moa-low": 900_000,
  "scanner-moa-high": 1_080_000,
};
const MAX_OUTPUT_CHARS = 30_000_000;
const HERMSEC_PROGRESS_PREFIX = "HERMSEC_PROGRESS ";

type CliOutcome = {
  ok?: boolean;
  message?: string;
  errorCode?: string;
  remediation?: string;
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
    orchestration?: {
      runId?: string;
      mode?: RuntimeScanAssistMode;
      terminalStatus?: ScanProjectResult["terminalStatus"];
      degradationReasons?: string[];
    };
  };
};

type CliScanData = NonNullable<NonNullable<CliOutcome["data"]>["scan"]>;
type CliOrchestrationData = NonNullable<NonNullable<CliOutcome["data"]>["orchestration"]>;

type ValidatedCliSuccessEnvelope =
  | {
      ok: true;
      scan: CliScanData & {
        id: string;
        target: string;
        summary: NonNullable<CliScanData["summary"]>;
      };
      orchestration: CliOrchestrationData & {
        runId: string;
        mode: RuntimeScanAssistMode;
        terminalStatus: Exclude<
          NonNullable<CliOrchestrationData["terminalStatus"]>,
          "canceled" | "failed" | "unchanged"
        >;
      };
      htmlPath: string;
      reportDir: string;
    }
  | {
      ok: false;
      reason: string;
    };

type RuntimeScanProgressEvent = Omit<ScanProgressEvent, "assistMode"> & {
  assistMode?: RuntimeScanAssistMode;
};

type RuntimeScanProjectResult = Omit<ScanProjectResult, "assistMode"> & {
  assistMode?: RuntimeScanAssistMode;
};

type ScanProgressCallback = (event: RuntimeScanProgressEvent) => void;

type RootScanProgressEvent = {
  schemaVersion?: string;
  runId?: string;
  id?: string;
  stage?: "repository" | "scanner" | "model" | "report" | "candidate" | "task" | "revalidation" | "checkpoint" | "profile" | "agent" | "tool" | "judge" | "aggregator" | "fusion" | "evaluation";
  scannerId?: string;
  label?: string;
  status?: string;
  message?: string;
  details?: Array<{ id?: string; label?: string; status?: string; message?: string; value?: string }>;
  findingCount?: number;
  durationMs?: number;
  assistMode?: RuntimeScanAssistMode;
  terminalStatus?: ScanProjectResult["terminalStatus"];
  degradationReasons?: string[];
  timestamp?: string;
};

type ActiveScanControl = {
  runId: string;
  child?: ChildProcessWithoutNullStreams;
  canceled: boolean;
  terminal: boolean;
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
  const labProject = path.join(root, "Test projects", "primary_tests", "nodejs-express-app");
  return existsSync(labProject) ? labProject : root;
}

function normalizeScanMode(_mode?: ScanProjectRequest["mode"]): "online" {
  return "online";
}

function defaultReportDir(): string {
  return path.join(app.getPath("documents"), "Hermsec", "reports");
}

function normalizeAssistMode(mode?: ScanProjectRequest["assistMode"]): RuntimeScanAssistMode {
  switch (mode) {
    case "scanner-only":
    case "single-agent":
    case "moa-low":
    case "moa-high":
    case "scanner-single":
    case "scanner-moa-low":
    case "scanner-moa-high":
      return mode;
    default:
      return "scanner-only";
  }
}

function modeRequiresModel(mode: RuntimeScanAssistMode): boolean {
  return mode !== "scanner-only";
}

function modeUsesScanners(mode: RuntimeScanAssistMode): boolean {
  return mode === "scanner-only" || mode === "scanner-single" || mode === "scanner-moa-low" || mode === "scanner-moa-high";
}

function uniqueRunId(requested?: string): string {
  const candidate = requested?.trim();
  return candidate && /^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$/.test(candidate)
    ? candidate
    : `desktop-${randomUUID()}`;
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

// test-contract:start current-cli-success-envelope
export function validateCurrentCliSuccessEnvelope(input: {
  outcome: CliOutcome;
  expectedRunId: string;
  expectedAssistMode: RuntimeScanAssistMode;
  expectedTargetPath: string;
  configuredReportDir: string;
  scanStartedMs: number;
}): ValidatedCliSuccessEnvelope {
  const fail = (reason: string): ValidatedCliSuccessEnvelope => ({ ok: false, reason });
  const nonEmpty = (value: unknown): value is string => typeof value === "string" && value.trim().length > 0;
  const comparablePath = (value: string): string => {
    const resolved = path.resolve(value);
    return process.platform === "win32" ? resolved.toLowerCase() : resolved;
  };
  const readJsonObject = (filePath: string): Record<string, unknown> | undefined => {
    try {
      const value = JSON.parse(readFileSync(filePath, "utf8")) as unknown;
      return value && typeof value === "object" && !Array.isArray(value)
        ? value as Record<string, unknown>
        : undefined;
    } catch {
      return undefined;
    }
  };
  const isFreshFile = (filePath: string): boolean => {
    try {
      const stats = statSync(filePath);
      return stats.isFile() && stats.mtimeMs + 2_000 >= input.scanStartedMs;
    } catch {
      return false;
    }
  };

  if (input.outcome.ok !== true) {
    return fail("The CLI did not return an explicit successful outcome.");
  }

  const scan = input.outcome.data?.scan;
  if (!scan || !nonEmpty(scan.id) || !nonEmpty(scan.target) || !scan.summary) {
    return fail("The CLI success payload is missing current scan identity or summary data.");
  }
  if (comparablePath(scan.target) !== comparablePath(input.expectedTargetPath)) {
    return fail("The CLI success payload belongs to a different project target.");
  }
  const summaryKeys = ["total", "critical", "high", "medium", "low", "info"] as const;
  if (summaryKeys.some((key) => typeof scan.summary?.[key] !== "number" || !Number.isFinite(scan.summary[key]))) {
    return fail("The CLI success payload contains an incomplete scan summary.");
  }

  const orchestration = input.outcome.data?.orchestration;
  if (!orchestration || orchestration.runId !== input.expectedRunId) {
    return fail("The CLI success payload does not match the active scan run.");
  }
  if (orchestration.mode !== input.expectedAssistMode) {
    return fail("The CLI success payload does not match the requested scan mode.");
  }
  if (
    orchestration.terminalStatus !== "success"
    && orchestration.terminalStatus !== "partial"
    && orchestration.terminalStatus !== "degraded"
  ) {
    return fail("The CLI success payload has no valid successful terminal status.");
  }

  const reportedHtmlPath = input.outcome.data?.report?.htmlPath;
  if (!nonEmpty(reportedHtmlPath) || !path.isAbsolute(reportedHtmlPath)) {
    return fail("The CLI success payload is missing an absolute HTML report path.");
  }

  let configuredRoot: string;
  let htmlPath: string;
  try {
    configuredRoot = realpathSync(input.configuredReportDir);
    htmlPath = realpathSync(reportedHtmlPath);
  } catch {
    return fail("The CLI HTML report artifact does not exist.");
  }

  const relativeHtmlPath = path.relative(configuredRoot, htmlPath);
  if (
    relativeHtmlPath === ""
    || relativeHtmlPath.startsWith("..")
    || path.isAbsolute(relativeHtmlPath)
    || path.basename(htmlPath).toLowerCase() !== "report.html"
  ) {
    return fail("The CLI HTML report artifact is outside the configured report directory.");
  }
  if (!isFreshFile(htmlPath)) {
    return fail("The CLI HTML report artifact was not written by the current scan.");
  }

  const reportDir = path.dirname(htmlPath);
  const evidencePath = path.join(reportDir, "detector-evidence.json");
  const documentPath = path.join(reportDir, "report-document.json");
  let canonicalEvidencePath: string;
  let canonicalDocumentPath: string;
  try {
    canonicalEvidencePath = realpathSync(evidencePath);
    canonicalDocumentPath = realpathSync(documentPath);
  } catch {
    return fail("The current report is missing invocation metadata.");
  }
  if (
    comparablePath(path.dirname(canonicalEvidencePath)) !== comparablePath(reportDir)
    || comparablePath(path.dirname(canonicalDocumentPath)) !== comparablePath(reportDir)
    || !isFreshFile(canonicalEvidencePath)
    || !isFreshFile(canonicalDocumentPath)
  ) {
    return fail("The report metadata does not belong to the current scan artifact.");
  }

  const evidence = readJsonObject(canonicalEvidencePath);
  if (evidence?.runId !== input.expectedRunId || evidence.mode !== input.expectedAssistMode) {
    return fail("The report evidence does not match the active scan run.");
  }

  const document = readJsonObject(canonicalDocumentPath);
  const documentRun = document?.run;
  if (
    document?.scanId !== scan.id
    || !documentRun
    || typeof documentRun !== "object"
    || Array.isArray(documentRun)
    || (documentRun as Record<string, unknown>).id !== scan.id
    || (documentRun as Record<string, unknown>).assistMode !== input.expectedAssistMode
  ) {
    return fail("The report document does not match the current scan identity.");
  }

  return {
    ok: true,
    scan: {
      ...scan,
      id: scan.id,
      target: scan.target,
      summary: scan.summary,
    },
    orchestration: {
      ...orchestration,
      runId: orchestration.runId,
      mode: orchestration.mode,
      terminalStatus: orchestration.terminalStatus,
    },
    htmlPath,
    reportDir,
  };
}
// test-contract:end current-cli-success-envelope

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
): Promise<RuntimeScanProjectResult> {
  if (activeScan) {
    return {
      ok: false,
      message: "A scan is already running. Stop or restart it before starting another scan.",
      error: "scan-already-running",
    };
  }

  const runId = uniqueRunId(request.runId);
  const control: ActiveScanControl = { runId, canceled: false, terminal: false };
  activeScan = control;
  const scopedProgress: ScanProgressCallback = (event) => {
    if (activeScan !== control || control.terminal || (control.canceled && event.status !== "canceled")) return;
    onProgress?.({ ...event, runId });
  };

  try {
    const root = findHermsecRoot();
    const cliPath = path.join(root, CLI_RELATIVE_PATH);
    const targetInput = request.targetPath?.trim();
    if (!targetInput) {
      return {
        ok: false,
        message: "Choose a project folder before starting a scan.",
        reportDir: path.resolve(request.reportDir || defaultReportDir()),
        error: "target-required",
        runId,
        terminalStatus: "failed",
      };
    }
    const targetPath = path.resolve(root, targetInput);
    const reportDir = path.resolve(request.reportDir || defaultReportDir());
    const mode = normalizeScanMode(request.mode);
    const assistMode = normalizeAssistMode(request.assistMode);
    const useModel = modeRequiresModel(assistMode);
    const agentOnlyMode = isAgentOnlyMode(assistMode);

    if (!existsSync(targetPath)) {
      return {
        ok: false,
        message: `Project folder was not found: ${targetPath}`,
        targetPath,
        reportDir,
        error: "target-not-found",
        runId,
        terminalStatus: "failed",
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
        runId,
        terminalStatus: "unchanged",
      };
    }

    const scanStartedMs = Date.now();
    const scanStartedAt = new Date(scanStartedMs).toISOString();
    emitInitialProgress(scopedProgress, assistMode);

    const profile = await timedStage(
      scopedProgress,
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

    let scannerPlan: ScannerPlanItem[] = [];
    if (agentOnlyMode) {
      await timedStage(
        scopedProgress,
        "choose-tools",
        progressStageLabel("choose-tools", "Choosing scanner tools", assistMode),
        "Selecting the agent-only inspection workflow...",
        async () => agentModePlan(assistMode),
        (plan) => ({
          message: "Agent-only mode selected. Scanner tools will not run for this scan.",
          details: plan,
          chips: profileChips(profile),
        }),
      );

      await timedStage(
        scopedProgress,
        "prepare-tools",
        progressStageLabel("prepare-tools", "Preparing tools", assistMode),
        "Preparing bounded repository context for read-only agent inspection...",
        async () => agentModePlan(assistMode),
        (plan) => ({
          message: "Bounded file, search, and snippet context will be prepared inside the agent runtime.",
          details: plan,
          chips: [assistModeLabel(assistMode)],
        }),
      );
    } else {
      scannerPlan = await timedStage(
        scopedProgress,
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
        scopedProgress,
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
    }

    const args = [
      cliPath,
      "scan",
      targetPath,
      "--mode",
      mode,
      "--assist-mode",
      assistMode,
      "--run-id",
      runId,
      "--out",
      reportDir,
      "--json",
      "--html",
    ];

    if (!useModel) {
      args.push("--no-model");
    }

    const cli = await runWithStageProgress(
      root,
      args,
      control,
      scopedProgress,
      assistMode,
      scannerPlan,
      targetPath,
      useModel,
    );
    throwIfCanceled(control);
    const parsed = parseCliJson(cli.stdout);
    const cliFailure = failedScanResultFromCli({
      exitCode: cli.exitCode,
      outcome: parsed,
      runId,
      assistMode,
      assistModeLabel: assistModeLabel(assistMode),
      targetPath,
      reportDir,
    });
    if (cliFailure) {
      emitProgress(
        scopedProgress,
        "scan-terminal",
        "Scan failed",
        "failed",
        cliFailure.message,
        {
          terminalStatus: "failed",
          degradationReasons: cliFailure.degradationReasons,
          assistMode,
          assistModeLabel: assistModeLabel(assistMode),
        },
      );
      control.terminal = true;
      return cliFailure;
    }
    const cliSuccess = validateCurrentCliSuccessEnvelope({
      outcome: parsed,
      expectedRunId: runId,
      expectedAssistMode: assistMode,
      expectedTargetPath: targetPath,
      configuredReportDir: reportDir,
      scanStartedMs,
    });
    if (!cliSuccess.ok) {
      const message = `Hermsec CLI returned an incomplete or stale scan result. ${cliSuccess.reason}`;
      const invalidSuccessResult: RuntimeScanProjectResult = {
        ok: false,
        message,
        error: "invalid-cli-success",
        runId,
        targetPath,
        reportDir,
        assistMode,
        assistModeLabel: assistModeLabel(assistMode),
        terminalStatus: "failed",
        degradationReasons: [message],
      };
      emitProgress(
        scopedProgress,
        "scan-terminal",
        "Scan failed",
        "failed",
        message,
        {
          terminalStatus: "failed",
          degradationReasons: invalidSuccessResult.degradationReasons,
          assistMode,
          assistModeLabel: assistModeLabel(assistMode),
        },
      );
      control.terminal = true;
      return invalidSuccessResult;
    }
    const summary = normalizeSummary(cliSuccess.scan.summary);
    const htmlPath = cliSuccess.htmlPath;
    const actualReportDir = cliSuccess.reportDir;
    if (!agentOnlyMode) {
      emitToolProgressFromReport(actualReportDir, scopedProgress);
    }
    emitAgentProgressFromReport(actualReportDir, scopedProgress, assistMode);
    const modelStageLabel = progressStageLabel("model-summary", "Model summary", assistMode);
    emitProgress(
      scopedProgress,
      "model-summary",
      modelStageLabel,
      "running",
      modelPhaseRunningMessage(assistMode),
      { assistMode, assistModeLabel: assistModeLabel(assistMode) },
    );
    const assistArtifactPath = agentOnlyMode ? null : writeScanAssistArtifact(actualReportDir, assistMode);
    emitProgress(
      scopedProgress,
      "model-summary",
      modelStageLabel,
      assistArtifactPath ? "completed" : "skipped",
      assistArtifactPath
        ? "Scanner evidence map was written for the report."
        : agentOnlyMode
          ? "Agent-only mode does not write a scanner evidence map."
          : "No model summary artifact was needed for this report.",
      {
        assistMode,
        assistModeLabel: assistModeLabel(assistMode),
        details: [
          {
            label: assistModeLabel(assistMode),
            status: assistArtifactPath ? "completed" : "skipped",
            message: modelPhaseCompletedMessage(assistMode),
          },
        ],
      },
    );
    emitProgress(scopedProgress, "report-ready", "Report ready", "running", "Writing dashboard and one-page report artifacts.");
    const finishedAt = new Date().toISOString();
    const terminalStatus = cliSuccess.orchestration.terminalStatus;
    const degradationReasons = cliSuccess.orchestration.degradationReasons ?? [];
    const scanMetadata: LocalScanMetadata = {
      projectPath: cliSuccess.scan.target,
      reportDir: actualReportDir,
      scanId: cliSuccess.scan.id,
      runId: cliSuccess.orchestration.runId,
      mode,
      assistMode: assistMode as LocalScanMetadata["assistMode"],
      assistModeLabel: assistModeLabel(assistMode),
      terminalStatus,
      ...(degradationReasons.length > 0 ? { degradationReasons } : {}),
      startedAt: scanStartedAt,
      finishedAt,
      reportGeneratedAt: finishedAt,
      durationMs: Number(cliSuccess.scan.durationMs ?? Date.now() - scanStartedMs),
      ...(currentProjectState.gitBranch ? { gitBranch: currentProjectState.gitBranch } : {}),
      ...(currentProjectState.gitHead ? { gitCommit: currentProjectState.gitHead } : {}),
      ...(typeof currentProjectState.gitDirty === "boolean" ? { dirtyWorkingTree: currentProjectState.gitDirty } : {}),
      projectStateKind: currentProjectState.kind,
      projectFingerprint: currentProjectState.fingerprint,
    };
    throwIfCanceled(control);
    const artifacts = await generateReportArtifacts(actualReportDir, currentProjectState, scanMetadata);
    throwIfCanceled(control);
    emitProgress(scopedProgress, "report-ready", "Report ready", "completed", "Dashboard artifacts were written.", {
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
      scopedProgress,
      "report-pdf",
      "PDF generation",
      artifacts.onepagerPdfPath ? "completed" : "skipped",
      artifacts.onepagerPdfPath ? "One-page PDF was generated." : "PDF generation was skipped by Electron.",
      { parentId: "report-ready" },
    );
    emitProgress(
      scopedProgress,
      "scan-terminal",
      "Scan complete",
      progressStatusForTerminal(terminalStatus),
      terminalStatus === "success" ? "Scan completed." : `Scan completed with status: ${terminalStatus}.`,
      {
        terminalStatus,
        ...(degradationReasons.length > 0 ? { degradationReasons } : {}),
      },
    );

    const result: RuntimeScanProjectResult = {
      ok: true,
      message: parsed.message ?? "Scan completed.",
      targetPath: cliSuccess.scan.target,
      reportDir: actualReportDir,
      htmlPath,
      dashboardHtmlPath: artifacts.dashboardHtmlPath,
      onepagerHtmlPath: artifacts.onepagerHtmlPath,
      ...(artifacts.onepagerPdfPath ? { onepagerPdfPath: artifacts.onepagerPdfPath } : {}),
      scanId: cliSuccess.scan.id,
      runId: cliSuccess.orchestration.runId,
      assistMode,
      assistModeLabel: assistModeLabel(assistMode),
      ...(assistArtifactPath ? { assistArtifactPath } : {}),
      ...(summary ? { summary } : {}),
      ...(cliSuccess.scan.durationMs ? { durationMs: cliSuccess.scan.durationMs } : {}),
      projectState: currentProjectState,
      terminalStatus,
      ...(degradationReasons.length > 0 ? { degradationReasons } : {}),
    };
    control.terminal = true;
    return result;
  } catch (error) {
    if (error instanceof ScanCanceledError) {
      emitCanceledProgress(scopedProgress);
      control.terminal = true;
      return {
        ok: false,
        canceled: true,
        message: "Scan stopped.",
        error: "scan-canceled",
        runId,
        terminalStatus: "canceled",
        degradationReasons: ["Scan stopped by the user."],
      };
    }
    control.terminal = true;
    return {
      ok: false,
      message: error instanceof Error ? error.message : "Hermsec scan failed.",
      error: error instanceof Error ? error.message : String(error),
      runId,
      terminalStatus: "failed",
      degradationReasons: [error instanceof Error ? error.message : String(error)],
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
  assistMode: RuntimeScanAssistMode = "scanner-only",
  scannerPlan: ScannerPlanItem[] = [],
  targetPath?: string,
  includeModel = false,
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  const runnablePlan = scannerPlan.filter((item) => item.adapter === "current" && item.status === "completed");
  const agentOnlyMode = isAgentOnlyMode(assistMode);
  const runningLabel = progressStageLabel("running-scans", "Running scans", assistMode);
  emitProgress(
    onProgress,
    "running-scans",
    runningLabel,
    "running",
    agentOnlyMode ? modelPhaseRunningMessage(assistMode) : "Running selected scanner tools...",
    {
      details: agentOnlyMode
        ? agentInspectionDetails(assistMode, "running")
        : runnablePlan.length > 0
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
      runningLabel,
      "running",
      agentOnlyMode
        ? "Agent-only inspection is still running; model progress will update as stages complete."
        : "Scanner process is still running; exact tool statuses will appear from the report.",
      {
        details: agentOnlyMode
          ? agentInspectionDetails(assistMode, "running")
          : runnablePlan.length > 0
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
      targetPath ? scannerEnvForCli(targetPath, { includeModel }) : undefined,
      onProgress,
      assistMode,
      includeModel,
    );
    emitProgress(
      onProgress,
      "running-scans",
      runningLabel,
      "completed",
      agentOnlyMode
        ? "Agent-only inspection completed. Reading report metadata."
        : "Scanner execution completed. Reading scanner status report.",
      {
        details: agentOnlyMode
          ? agentInspectionDetails(assistMode, "completed")
          : runnablePlan.length > 0
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

export function cancelActiveScan(runId: string | undefined): ScanControlResult {
  if (!activeScan) {
    return { ok: false, message: "No scan is currently running." };
  }

  if (!runIdsMatch(activeScan.runId, runId)) {
    return { ok: false, message: "The requested scan is no longer active.", runId };
  }

  activeScan.canceled = true;
  if (activeScan.child?.pid) {
    killProcessTree(activeScan.child);
  }
  return { ok: true, message: "Scan stop requested.", runId: activeScan.runId };
}

function progressStatusForTerminal(status: NonNullable<ScanProjectResult["terminalStatus"]>): ScanProgressEvent["status"] {
  if (status === "canceled") return "canceled";
  if (status === "failed") return "failed";
  if (status === "partial" || status === "degraded") return "degraded";
  return "completed";
}

function throwIfCanceled(control: ActiveScanControl): void {
  if (control.canceled) {
    throw new ScanCanceledError();
  }
}

function emitInitialProgress(onProgress?: ScanProgressCallback, assistMode: RuntimeScanAssistMode = "scanner-only"): void {
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
    assistMode?: RuntimeScanAssistMode;
    assistModeLabel?: string;
    terminalStatus?: ScanProjectResult["terminalStatus"];
    degradationReasons?: string[];
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
    ...(options.terminalStatus ? { terminalStatus: options.terminalStatus } : {}),
    ...(options.degradationReasons?.length ? { degradationReasons: options.degradationReasons } : {}),
    timestamp: Date.now(),
  });
}

function progressStageLabel(id: string, fallback: string, assistMode: RuntimeScanAssistMode): string {
  if (isAgentOnlyMode(assistMode)) {
    if (id === "choose-tools") return assistMode === "moa-low" || assistMode === "moa-high" ? "Choosing agent panel" : "Choosing agent";
    if (id === "prepare-tools") return "Preparing code context";
    if (id === "running-scans") return assistMode === "moa-low" || assistMode === "moa-high" ? "Running agent panel" : "Running agent inspection";
  }
  if (id === "model-summary") {
    if (assistMode === "single-agent") return "Single-agent inspection";
    if (assistMode === "moa-low") return "MoA Low inspection";
    if (assistMode === "moa-high") return "MoA High inspection";
    if (assistMode === "scanner-single") return "Scanner + Single fusion";
    if (assistMode === "scanner-moa-low") return "Scanner + MoA Low fusion";
    if (assistMode === "scanner-moa-high") return "Scanner + MoA High fusion";
    return "Scanner evidence map";
  }
  return fallback;
}

function progressQueuedMessage(id: string, label: string, assistMode: RuntimeScanAssistMode): string {
  if (isAgentOnlyMode(assistMode)) {
    if (id === "choose-tools") return `${label} is queued; scanner tools will not run.`;
    if (id === "prepare-tools") return "Bounded code context preparation is queued.";
    if (id === "running-scans") return `${label} is queued.`;
  }
  if (id === "model-summary") {
    if (assistMode === "single-agent") return "Single-agent repository inspection is queued.";
    if (assistMode === "moa-low") return "MoA Low specialist, judge, and aggregator inspection is queued.";
    if (assistMode === "moa-high") return "MoA High specialist, judge, and aggregator inspection is queued.";
    if (assistMode === "scanner-single") return "Scanner + Single fusion is queued after scanner execution.";
    if (assistMode === "scanner-moa-low") return "Scanner + MoA Low judging and aggregation is queued after scanner execution.";
    if (assistMode === "scanner-moa-high") return "Scanner + MoA High judging and aggregation is queued after scanner execution.";
    return "Scanner evidence mapping is queued after scanner execution.";
  }
  return `${label} is queued.`;
}

function progressRunningMessage(id: string, label: string, assistMode: RuntimeScanAssistMode): string {
  if (id === "model-summary") {
    return modelPhaseRunningMessage(assistMode);
  }
  return `${label} is running.`;
}

function modelPhaseRunningMessage(assistMode: RuntimeScanAssistMode): string {
  if (assistMode === "single-agent") {
    return "Inspecting bounded repository snippets for product findings.";
  }
  if (assistMode === "moa-low") {
    return "Running three specialists, a false-positive judge, and an aggregator.";
  }
  if (assistMode === "moa-high") {
    return "Running five specialists, a false-positive judge, and an aggregator.";
  }
  if (assistMode === "scanner-single") {
    return "Fusing independent scanner and single-agent evidence.";
  }
  if (assistMode === "scanner-moa-low") {
    return "Judging and aggregating scanner findings with three specialist agents.";
  }
  if (assistMode === "scanner-moa-high") {
    return "Judging and aggregating scanner findings with five specialist agents.";
  }
  return "Writing a deterministic scanner evidence map without model review.";
}

function modelPhaseCompletedMessage(assistMode: RuntimeScanAssistMode): string {
  if (assistMode === "single-agent") {
    return "Single-agent inspection evidence is ready for the report.";
  }
  if (assistMode === "moa-low") {
    return "MoA Low inspection evidence is ready for the report.";
  }
  if (assistMode === "moa-high") {
    return "MoA High inspection evidence is ready for the report.";
  }
  if (assistMode === "scanner-single") return "Scanner and single-agent evidence is fused and ready for the report.";
  if (assistMode === "scanner-moa-low") return "Scanner and MoA Low evidence is judged, merged, and ready for the report.";
  if (assistMode === "scanner-moa-high") return "Scanner and MoA High evidence is judged, merged, and ready for the report.";
  return "Scanner evidence map is ready for the report.";
}

function isAgentOnlyMode(assistMode: RuntimeScanAssistMode): boolean {
  return !modeUsesScanners(assistMode);
}

function agentModePlan(assistMode: RuntimeScanAssistMode): NonNullable<ScanProgressEvent["details"]> {
  if (assistMode === "moa-low" || assistMode === "moa-high") {
    return [
      {
        id: "moa-specialists",
        label: "Specialist agents",
        status: "completed",
        message: "Specialist agents will inspect bounded repository snippets.",
      },
      {
        id: "moa-judge",
        label: "False-positive judge",
        status: "completed",
        message: "The judge will reject weak or unsupported agent candidates.",
      },
      {
        id: "moa-aggregator",
        label: "Aggregator",
        status: "completed",
        message: "The aggregator will merge accepted agent findings.",
      },
    ];
  }

  return [
    {
      id: "single-agent-inspector",
      label: "Single agent inspector",
      status: "completed",
      message: "One configured agent will inspect bounded repository snippets.",
    },
  ];
}

function agentInspectionDetails(
  assistMode: RuntimeScanAssistMode,
  status: Extract<ScanProgressEvent["status"], "running" | "completed">,
): NonNullable<ScanProgressEvent["details"]> {
  if (assistMode === "moa-low" || assistMode === "moa-high") {
    return [
      {
        id: "moa-agent-runtime",
        label: "MoA runtime",
        status,
        message: status === "running"
          ? "Specialists, judge, and aggregator are inspecting code without scanner tools."
          : "Specialists, judge, and aggregator completed their agent-only inspection.",
      },
    ];
  }

  return [
    {
      id: "single-agent-runtime",
      label: "Single agent runtime",
      status,
      message: status === "running"
        ? "The configured agent is inspecting code without scanner tools."
        : "The configured agent completed its agent-only inspection.",
    },
  ];
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

function numberFromUnknown(...values: unknown[]): number | undefined {
  for (const value of values) {
    const numeric = typeof value === "number" ? value : typeof value === "string" ? Number(value) : NaN;
    if (Number.isFinite(numeric)) {
      return numeric;
    }
  }
  return undefined;
}

function stringFromUnknown(...values: unknown[]): string | undefined {
  for (const value of values) {
    if (typeof value === "string" && value.trim()) {
      return value.trim();
    }
  }
  return undefined;
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

function emitAgentProgressFromReport(
  reportDir: string,
  onProgress: ScanProgressCallback | undefined,
  assistMode: RuntimeScanAssistMode,
): void {
  const documentPath = path.join(reportDir, "report-document.json");
  if (!existsSync(documentPath)) return;

  try {
    const document = JSON.parse(readFileSync(documentPath, "utf8")) as {
      agentMode?: Record<string, unknown>;
      findings?: unknown[];
    };
    const agentMode = recordValue(document.agentMode);
    if (Object.keys(agentMode).length === 0) {
      return;
    }

    const candidateCount = numberFromUnknown(agentMode.candidateFindingCount, agentMode.candidateCount);
    const acceptedCount = numberFromUnknown(agentMode.acceptedFindingCount, agentMode.acceptedCount);
    const rejectedCount = numberFromUnknown(agentMode.rejectedFindingCount, agentMode.rejectedCount);
    const needsReviewCount = numberFromUnknown(agentMode.needsHumanReviewCount, agentMode.needsReviewCount);
    const finalFindingCount = Array.isArray(document.findings)
      ? document.findings.length
      : numberFromUnknown(agentMode.finalFindingCount);
    const agents = Array.isArray(agentMode.agents) ? agentMode.agents.map(recordValue) : [];
    const aggregator = recordValue(agentMode.aggregator);
    const aggregatorModel = stringFromUnknown(agentMode.aggregatorModel, aggregator.model);
    const totalRuntimeMs = numberFromUnknown(agentMode.totalAgentRuntimeMs, agentMode.totalRuntimeMs, agentMode.runtimeMs);

    if (candidateCount !== undefined) {
      emitProgress(
        onProgress,
        "agent-candidate-discovery",
        "Candidate discovery",
        "completed",
        modeUsesScanners(assistMode)
          ? `Collected ${candidateCount} scanner and agent candidate finding${candidateCount === 1 ? "" : "s"} for judging.`
          : `Collected ${candidateCount} agent candidate finding${candidateCount === 1 ? "" : "s"} for judging.`,
        {
          parentId: "model-summary",
          assistMode,
          assistModeLabel: assistModeLabel(assistMode),
          details: [
            {
              id: "candidate-findings",
              label: "Candidate findings",
              status: "completed",
              value: String(candidateCount),
            },
          ],
        },
      );
    }

    if (agents.length > 0) {
      const specialistCount = agents.filter((agent) => `${agent.role ?? ""}`.toLowerCase().includes("specialist")).length;
      emitProgress(
        onProgress,
        "agent-focused-tasks",
        "Focused tasks",
        agents.some((agent) => agent.status === "failed") ? "failed" : "completed",
        specialistCount > 0
          ? `${specialistCount} focused specialist task${specialistCount === 1 ? "" : "s"} reported status.`
          : `${agents.length} agent task${agents.length === 1 ? "" : "s"} reported status.`,
        {
          parentId: "model-summary",
          assistMode,
          assistModeLabel: assistModeLabel(assistMode),
          details: [
            {
              id: "agent-tasks",
              label: "Agent tasks",
              status: "completed",
              value: String(agents.length),
            },
            ...(totalRuntimeMs !== undefined
              ? [{
                  id: "agent-runtime",
                  label: "Runtime",
                  status: "completed" as const,
                  value: formatDuration(totalRuntimeMs),
                }]
              : []),
          ],
        },
      );
    }

    if (finalFindingCount !== undefined) {
      emitProgress(
        onProgress,
        "agent-evidence-revalidation",
        "Evidence revalidation",
        "completed",
        `Revalidated ${finalFindingCount} final finding${finalFindingCount === 1 ? "" : "s"} against report evidence.`,
        {
          parentId: "model-summary",
          assistMode,
          assistModeLabel: assistModeLabel(assistMode),
          details: [
            {
              id: "final-findings",
              label: "Final findings",
              status: "completed",
              value: String(finalFindingCount),
            },
          ],
        },
      );
    }

    if (acceptedCount !== undefined || rejectedCount !== undefined || needsReviewCount !== undefined) {
      emitProgress(
        onProgress,
        "moa-false-positive-judge",
        "False-positive judge",
        "completed",
        "Candidate judgments were preserved in the report metadata.",
        {
          parentId: "model-summary",
          assistMode,
          assistModeLabel: assistModeLabel(assistMode),
          details: [
            ...(acceptedCount !== undefined ? [{ id: "accepted", label: "Accepted", status: "completed" as const, value: String(acceptedCount) }] : []),
            ...(rejectedCount !== undefined ? [{ id: "rejected", label: "Rejected", status: "completed" as const, value: String(rejectedCount) }] : []),
            ...(needsReviewCount !== undefined ? [{ id: "needs-review", label: "Needs review", status: "completed" as const, value: String(needsReviewCount) }] : []),
          ],
        },
      );
    }

    if (aggregatorModel || finalFindingCount !== undefined) {
      emitProgress(
        onProgress,
        "moa-aggregator",
        "Aggregator counts",
        "completed",
        aggregatorModel ? `Aggregator completed with ${aggregatorModel}.` : "Aggregator completed.",
        {
          parentId: "model-summary",
          assistMode,
          assistModeLabel: assistModeLabel(assistMode),
          details: [
            ...(candidateCount !== undefined ? [{ id: "candidates", label: "Candidates", status: "completed" as const, value: String(candidateCount) }] : []),
            ...(finalFindingCount !== undefined ? [{ id: "final-findings", label: "Final findings", status: "completed" as const, value: String(finalFindingCount) }] : []),
          ],
        },
      );
    }
  } catch {
    // Agent progress is display-only and must never fail the scan.
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

function runNodeCli(
  cwd: string,
  args: string[],
  control: ActiveScanControl,
  extraEnv?: Record<string, string>,
  onProgress?: ScanProgressCallback,
  assistMode: RuntimeScanAssistMode = "scanner-only",
  includeModel = false,
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  const runtimeLease = app.isPackaged ? createVerifiedBundledRuntimeExecutionLease() : undefined;
  const effectiveArgs = runtimeLease
    ? [runtimeLease.cliEntryPath, ...args.slice(1)]
    : args;
  const effectiveCwd = runtimeLease?.cliRoot ?? cwd;
  return new Promise((resolve, reject) => {
    const settleAfterRuntimeRelease = (
      complete: () => void,
    ): void => {
      void (async () => {
        try {
          await runtimeLease?.release();
          complete();
        } catch (error) {
          reject(error);
        }
      })();
    };
    let child: ChildProcessWithoutNullStreams;
    try {
      const processSpec = createCliProcessSpec({
        isPackaged: app.isPackaged,
        electronExecutable: process.execPath,
        platform: process.platform,
        args: effectiveArgs,
        inheritedEnv: process.env,
        ...(extraEnv ? { extraEnv } : {}),
        ...(runtimeLease
          ? {
              trustedRuntime: {
                values: runtimeLease.trustedEnvironment,
                controlledNames: runtimeLease.controlledEnvironmentNames,
              },
            }
          : {}),
        includeModel,
        modelEnvironmentNames: modelEnvironmentVariableNames(),
      });
      // The child can execute only from the lease. This is deliberately adjacent
      // to spawn so a tampered snapshot fails before any scanner/CLI bytes run.
      runtimeLease?.assertIntact();
      child = spawn(processSpec.executable, processSpec.args, {
        cwd: effectiveCwd,
        env: processSpec.env,
        windowsHide: true,
      });
    } catch (error) {
      settleAfterRuntimeRelease(() => reject(error));
      return;
    }
    control.child = child;

    let stdout = "";
    let stderr = "";
    let stdoutLineBuffer = "";
    let stderrLineBuffer = "";
    const timeoutMs = scanTimeoutMs(assistMode);
    const timer = windowlessTimeout(() => {
      killProcessTree(child);
      reject(new Error(`Hermsec ${assistModeLabel(assistMode)} timed out after ${formatTimeoutDuration(timeoutMs)}.`));
    }, timeoutMs);

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
      settleAfterRuntimeRelease(() => reject(error));
    });
    child.on("close", (exitCode) => {
      clearTimeout(timer);
      flushBufferedLines();
      if (control.child === child) {
        delete control.child;
      }
      settleAfterRuntimeRelease(() => {
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
  });
}

function scanTimeoutMs(assistMode: RuntimeScanAssistMode): number {
  const modeKey = assistMode.replace(/[^a-z0-9]/giu, "_").toUpperCase();
  const modeOverride = Number(process.env[`HERMSEC_DESKTOP_SCAN_TIMEOUT_${modeKey}_MS`]);
  if (Number.isFinite(modeOverride) && modeOverride >= 30_000) {
    return Math.trunc(modeOverride);
  }
  const override = Number(process.env.HERMSEC_DESKTOP_SCAN_TIMEOUT_MS);
  if (Number.isFinite(override) && override >= 30_000) {
    return Math.trunc(override);
  }
  return SCAN_TIMEOUT_MS_BY_ASSIST_MODE[assistMode] ?? DEFAULT_SCAN_TIMEOUT_MS;
}

function formatTimeoutDuration(ms: number): string {
  const seconds = Math.round(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = seconds % 60;
  return remainingSeconds === 0 ? `${minutes}m` : `${minutes}m ${remainingSeconds}s`;
}

function consumeProgressLine(
  line: string,
  onProgress: ScanProgressCallback | undefined,
  fallbackAssistMode: RuntimeScanAssistMode,
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
  fallbackAssistMode: RuntimeScanAssistMode,
): RuntimeScanProgressEvent | undefined {
  const status = normalizeProgressStatus(event.status);
  if (!status) {
    return undefined;
  }
  const assistMode = normalizeAssistMode(event.assistMode ?? fallbackAssistMode);
  const timestamp = event.timestamp ? Date.parse(event.timestamp) : Date.now();
  const details = rootProgressDetails(event, status);
  const base = {
    status,
    assistMode,
    assistModeLabel: assistModeLabel(assistMode),
    timestamp: Number.isFinite(timestamp) ? timestamp : Date.now(),
    ...(event.message ? { message: event.message } : {}),
    ...(details ? { details } : {}),
    ...(event.terminalStatus ? { terminalStatus: event.terminalStatus } : {}),
    ...(event.degradationReasons?.length ? { degradationReasons: event.degradationReasons } : {}),
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

  if (event.stage === "model" || event.stage === "agent" || event.stage === "tool" || event.stage === "judge" || event.stage === "aggregator" || event.stage === "fusion" || event.stage === "evaluation") {
    const childId = event.id && event.id !== "model-summary" ? event.id : undefined;
    if (childId) {
      return {
        id: childId,
        label: event.label ?? childId,
        parentId: "model-summary",
        ...base,
      };
    }
    return {
      id: "model-summary",
      label: progressStageLabel("model-summary", event.label ?? "Model summary", assistMode),
      ...base,
    };
  }

  if (event.stage === "candidate" || event.stage === "task" || event.stage === "revalidation" || event.stage === "checkpoint") {
    return {
      id: event.id ?? `product-agent-${event.stage}`,
      label: event.label ?? productAgentStageLabel(event.stage),
      parentId: "model-summary",
      ...base,
    };
  }

  if (event.stage === "report") {
    const childId = event.id && event.id !== "report-ready" ? event.id : undefined;
    if (childId) {
      return {
        id: childId,
        label: event.label ?? childId,
        parentId: "report-ready",
        ...base,
      };
    }
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

function productAgentStageLabel(stage: "candidate" | "task" | "revalidation" | "checkpoint"): string {
  if (stage === "candidate") return "Candidate discovery";
  if (stage === "task") return "Focused tasks";
  if (stage === "revalidation") return "Evidence revalidation";
  return "Checkpoint";
}

function normalizeProgressStatus(value: string | undefined): ScanProgressEvent["status"] | undefined {
  switch (value) {
    case "waiting":
    case "running":
    case "completed":
    case "skipped":
    case "failed":
    case "canceled":
    case "degraded":
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

function scannerParentMessage(event: RuntimeScanProgressEvent): string {
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
