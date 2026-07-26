import path from "node:path";
import {
  runCanonicalAgentDetector,
  type CanonicalAgentDetectorInput,
  type CanonicalAgentDetectorMode,
  type CanonicalAgentDetectorResult,
  type CanonicalModelResolver,
  type CanonicalAgentProgressEvent,
} from "../agent/canonicalHarness.js";
import {
  fuseFindings,
  type FindingFusionResult,
} from "../agent/findingFusion.js";
import { sanitizeErrorMessage } from "../agent/redaction.js";
import { stableId } from "../shared/text.js";
import type {
  CanonicalScanAssistMode,
  Finding,
  ScanMode,
  ScanProgressEvent,
  ScanProgressStage,
  ScanProgressStatus,
  ScanRun,
  ScanTerminalStatus,
  ScannerStatus,
} from "../shared/types.js";
import {
  resolveScanAssistMode,
  scanAssistModeSpec,
  type CanonicalScanAssistMode as CoreCanonicalScanAssistMode,
} from "./scanAssistModes.js";
import {
  runScan as runLocalScan,
  summarize,
  type ScanOptions,
} from "./scan.js";
import type { ScanProgressCallback } from "./progress.js";

export type CanonicalScannerRunner = (
  options: ScanOptions,
) => Promise<ScanRun>;

export type CanonicalAgentDetectorRunner = (
  input: CanonicalAgentDetectorInput,
) => Promise<Readonly<CanonicalAgentDetectorResult>>;

export type CanonicalScanOrchestratorInput = {
  target: string;
  assistMode: CanonicalScanAssistMode;
  scanMode?: ScanMode;
  runId?: string;
  signal?: AbortSignal;
  resolveModel?: CanonicalModelResolver;
  onProgress?: ScanProgressCallback;
  scannerRunner?: CanonicalScannerRunner;
  agentDetectorRunner?: CanonicalAgentDetectorRunner;
  now?: () => Date;
};

export type CanonicalScanOrchestrationResult = {
  schemaVersion: "1.0";
  runId: string;
  mode: CoreCanonicalScanAssistMode;
  terminalStatus: ScanTerminalStatus;
  startedAt: string;
  finishedAt: string;
  durationMs: number;
  scan: ScanRun;
  scannerFindings: Finding[];
  agentFindings: Finding[];
  findings: Finding[];
  agentResult?: Readonly<CanonicalAgentDetectorResult>;
  fusion?: FindingFusionResult;
  degradationReasons: string[];
};

/**
 * Runs one canonical product mode. Scanner and agent detectors remain
 * independent until deterministic fusion, so model output cannot erase raw
 * scanner evidence or silently substitute a different experiment mode.
 */
export async function runCanonicalScanOrchestration(
  input: CanonicalScanOrchestratorInput,
): Promise<Readonly<CanonicalScanOrchestrationResult>> {
  const mode = resolveScanAssistMode(input.assistMode);
  const spec = scanAssistModeSpec(mode);
  const now = input.now ?? (() => new Date());
  const startedAt = now().toISOString();
  const startedMs = Date.parse(startedAt);
  const runId =
    input.runId ??
    stableId(`${path.resolve(input.target)}\u0000${mode}\u0000${startedAt}`, "scan-run");
  const scannerRunner = input.scannerRunner ?? runLocalScan;
  const detectorRunner =
    input.agentDetectorRunner ?? runCanonicalAgentDetector;
  let terminal = false;
  const emit = createRunScopedProgressEmitter({
    runId,
    mode,
    ...(input.onProgress ? { callback: input.onProgress } : {}),
    isTerminal: () => terminal,
  });

  if (input.signal?.aborted) {
    const finishedAt = now().toISOString();
    terminal = true;
    return freezeResult({
      schemaVersion: "1.0",
      runId,
      mode,
      terminalStatus: "canceled",
      startedAt,
      finishedAt,
      durationMs: elapsedMs(startedMs, finishedAt),
      scan: emptyScanRun({
        target: input.target,
        scanMode: input.scanMode ?? "online",
        assistMode: mode,
        runId,
        startedAt,
        finishedAt,
        terminalStatus: "canceled",
        degradationReasons: ["Run canceled before detector dispatch."],
      }),
      scannerFindings: [],
      agentFindings: [],
      findings: [],
      degradationReasons: ["Run canceled before detector dispatch."],
    });
  }

  const scannerPromise = scannerRunner({
    target: input.target,
    mode: input.scanMode ?? "online",
    assistMode: mode,
    scannerMode: spec.runsScanners ? "full" : "none",
    runId,
    ...(input.signal ? { signal: input.signal } : {}),
    onProgress: (event) => emitScannerProgress(emit, event),
  });
  const agentPromise =
    spec.agentPath === "none"
      ? undefined
      : runAgentDetector({
          input,
          mode,
          detectorMode: detectorModeFor(mode),
          runId,
          detectorRunner,
          emit,
        });

  const [scannerSettled, agentSettled] = await Promise.all([
    settle(scannerPromise),
    agentPromise ? settle(agentPromise) : Promise.resolve(undefined),
  ]);

  const degradationReasons: string[] = [];
  const scannerRun = scannerSettled.ok
    ? scannerSettled.value
    : emptyScanRun({
        target: input.target,
        scanMode: input.scanMode ?? "online",
        assistMode: mode,
        runId,
        startedAt,
        finishedAt: now().toISOString(),
        terminalStatus: "failed",
        degradationReasons: [
          `Scanner path failed: ${sanitizeErrorMessage(
            scannerSettled.error,
            "Scanner path failed.",
          )}`,
        ],
      });
  if (!scannerSettled.ok) {
    degradationReasons.push(...(scannerRun.degradationReasons ?? []));
  }

  let agentResult: Readonly<CanonicalAgentDetectorResult> | undefined;
  if (agentSettled) {
    if (agentSettled.ok) {
      agentResult = agentSettled.value;
      degradationReasons.push(...agentResult.limitations);
    } else {
      degradationReasons.push(
        `Agent path failed: ${sanitizeErrorMessage(
          agentSettled.error,
          "Agent path failed.",
        )}`,
      );
    }
  }

  const scannerFindings = spec.runsScanners
    ? scannerRun.findings.map(cloneFinding)
    : [];
  const agentFindings = agentResult?.findings.map(cloneFinding) ?? [];
  let findings =
    spec.agentPath === "none"
      ? scannerFindings.map(cloneFinding)
      : spec.runsScanners
        ? [...scannerFindings, ...agentFindings].map(cloneFinding)
        : agentFindings.map(cloneFinding);
  let fusion: FindingFusionResult | undefined;
  let fusionFailed = false;

  if (spec.runsScanners && spec.agentPath !== "none") {
    if (scannerFindings.length === 0 || agentFindings.length === 0) {
      findings = [...scannerFindings, ...agentFindings].map(cloneFinding);
      emit({
        id: "deterministic-fusion",
        stage: "fusion",
        label: "Deterministic evidence fusion",
        status: "skipped",
        message:
          "Fusion was not needed because one detector path produced no eligible findings.",
        findingCount: findings.length,
      });
    } else {
      emit({
        id: "deterministic-fusion",
        stage: "fusion",
        label: "Deterministic evidence fusion",
        status: "running",
        message: "Reconciling independent scanner and agent evidence.",
        findingCount: findings.length,
      });
      try {
        fusion = fuseFindings(
          [
            ...scannerFindings.map((finding) => ({
              finding,
              sourceId: `scanner:${finding.id}`,
              sourceLabel: finding.tool,
              sourceKind: "scanner" as const,
            })),
            ...agentFindings.map((finding) => ({
              finding,
              sourceId: `agent:${finding.id}`,
              sourceLabel: finding.agent?.role ?? finding.tool,
              sourceKind: "agent" as const,
            })),
          ],
          { repoRoot: scannerRun.target },
        );
        findings = fusion.canonicalFindings.map(cloneFinding);
        emit({
          id: "deterministic-fusion",
          stage: "fusion",
          label: "Deterministic evidence fusion",
          status: "completed",
          message:
            "Scanner and agent evidence were fused without removing raw sources.",
          findingCount: findings.length,
        });
      } catch (error) {
        fusionFailed = true;
        degradationReasons.push(
          `Deterministic fusion was skipped: ${sanitizeErrorMessage(
            error,
            "Finding fusion failed.",
          )}`,
        );
        findings = stableFindingOrder(findings);
        emit({
          id: "deterministic-fusion",
          stage: "fusion",
          label: "Deterministic evidence fusion",
          status: "degraded",
          message: "Fusion could not complete; all raw findings were preserved.",
          findingCount: findings.length,
        });
      }
    }
  }

  if (input.signal?.aborted) {
    degradationReasons.push("Run canceled before orchestration completed.");
  }
  const scannerDegraded = scannerRun.scannerStatuses.some(
    (status) => status.status === "failed",
  );
  if (scannerDegraded) {
    degradationReasons.push("One or more scanner stages failed.");
  }

  const terminalStatus = deriveTerminalStatus({
    mode,
    ...(input.signal ? { signal: input.signal } : {}),
    scannerFailed: !scannerSettled.ok,
    scannerDegraded,
    ...(agentResult?.status ? { agentStatus: agentResult.status } : {}),
    agentFailedUnexpectedly: agentSettled?.ok === false,
    fusionDegraded: fusionFailed,
  });
  const uniqueReasons = uniqueSorted(degradationReasons);
  const finishedAt = now().toISOString();
  const finalScan: ScanRun = {
    ...scannerRun,
    id: runId,
    assistMode: mode,
    terminalStatus,
    ...(uniqueReasons.length > 0
      ? { degradationReasons: [...uniqueReasons] }
      : {}),
    startedAt,
    finishedAt,
    durationMs: elapsedMs(startedMs, finishedAt),
    findings: findings.map(cloneFinding),
    summary: summarize(findings),
  };
  terminal = true;

  return freezeResult({
    schemaVersion: "1.0",
    runId,
    mode,
    terminalStatus,
    startedAt,
    finishedAt,
    durationMs: elapsedMs(startedMs, finishedAt),
    scan: finalScan,
    scannerFindings,
    agentFindings,
    findings,
    ...(agentResult ? { agentResult } : {}),
    ...(fusion ? { fusion } : {}),
    degradationReasons: uniqueReasons,
  });
}

function runAgentDetector(input: {
  input: CanonicalScanOrchestratorInput;
  mode: CoreCanonicalScanAssistMode;
  detectorMode: CanonicalAgentDetectorMode;
  runId: string;
  detectorRunner: CanonicalAgentDetectorRunner;
  emit: RunScopedEmitter;
}): Promise<Readonly<CanonicalAgentDetectorResult>> {
  const resolveModel: CanonicalModelResolver =
    input.input.resolveModel ?? (() => undefined);
  return input.detectorRunner({
    repoRoot: input.input.target,
    mode: input.detectorMode,
    resolveModel,
    runId: input.runId,
    ...(input.input.signal ? { signal: input.input.signal } : {}),
    onProgress: (event) => emitAgentProgress(input.emit, event),
  });
}

function detectorModeFor(
  mode: CoreCanonicalScanAssistMode,
): CanonicalAgentDetectorMode {
  switch (mode) {
    case "single-agent":
    case "scanner-single":
      return "single";
    case "moa-low":
    case "scanner-moa-low":
      return "moa-low";
    case "moa-high":
    case "scanner-moa-high":
      return "moa-high";
    case "scanner-only":
      throw new Error("Scanner-only mode has no agent detector.");
  }
}

function deriveTerminalStatus(input: {
  mode: CoreCanonicalScanAssistMode;
  signal?: AbortSignal;
  scannerFailed: boolean;
  scannerDegraded: boolean;
  agentStatus?: CanonicalAgentDetectorResult["status"];
  agentFailedUnexpectedly: boolean;
  fusionDegraded: boolean;
}): ScanTerminalStatus {
  if (input.signal?.aborted || input.agentStatus === "canceled") {
    return "canceled";
  }
  const spec = scanAssistModeSpec(input.mode);
  if (spec.agentPath === "none") {
    return input.scannerFailed
      ? "failed"
      : input.scannerDegraded
        ? "partial"
        : "success";
  }
  if (!spec.runsScanners) {
    if (input.agentFailedUnexpectedly || input.agentStatus === "failed") {
      return "failed";
    }
    if (input.agentStatus === "partial") {
      return "partial";
    }
    if (input.agentStatus === "degraded" || !input.agentStatus) {
      return "degraded";
    }
    return "success";
  }
  if (
    input.scannerFailed ||
    input.agentFailedUnexpectedly ||
    input.agentStatus === "failed" ||
    input.agentStatus === "partial"
  ) {
    return "partial";
  }
  if (
    input.scannerDegraded ||
    input.agentStatus === "degraded" ||
    !input.agentStatus ||
    input.fusionDegraded
  ) {
    return "degraded";
  }
  return "success";
}

type Settled<T> =
  | { ok: true; value: T }
  | { ok: false; error: unknown };

async function settle<T>(promise: Promise<T>): Promise<Settled<T>> {
  try {
    return { ok: true, value: await promise };
  } catch (error) {
    return { ok: false, error };
  }
}

type RunScopedEmitter = (
  event: Omit<ScanProgressEvent, "schemaVersion" | "timestamp" | "message"> & {
    message?: string;
  },
) => void;

function createRunScopedProgressEmitter(input: {
  runId: string;
  mode: CoreCanonicalScanAssistMode;
  callback?: ScanProgressCallback;
  isTerminal: () => boolean;
}): RunScopedEmitter {
  return (event) => {
    if (!input.callback || input.isTerminal()) {
      return;
    }
    input.callback({
      ...event,
      schemaVersion: "1.0",
      runId: input.runId,
      assistMode: input.mode,
      message: event.message ?? event.label,
      timestamp: new Date().toISOString(),
    });
  };
}

function emitScannerProgress(
  emit: RunScopedEmitter,
  event: ScanProgressEvent,
): void {
  const {
    schemaVersion: _schemaVersion,
    timestamp: _timestamp,
    runId: _runId,
    assistMode: _assistMode,
    message,
    ...progress
  } = event;
  emit({
    ...progress,
    message,
  });
}

function emitAgentProgress(
  emit: RunScopedEmitter,
  event: Readonly<CanonicalAgentProgressEvent>,
): void {
  emit({
    id: [
      "agent",
      event.phase,
      event.role,
      event.round,
      event.toolName,
    ]
      .filter((value) => value !== undefined)
      .join(":"),
    stage: agentProgressStage(event.phase),
    label: agentProgressLabel(event),
    status: agentProgressStatus(event.status),
    message: event.message,
    ...(event.role
      ? { componentId: event.role, roleId: event.role }
      : {}),
    ...(event.round !== undefined ? { round: event.round } : {}),
    ...(event.toolName ? { toolName: event.toolName } : {}),
  });
}

function agentProgressStage(
  phase: CanonicalAgentProgressEvent["phase"],
): ScanProgressStage {
  switch (phase) {
    case "profile":
      return "profile";
    case "tool":
      return "tool";
    case "judge":
      return "judge";
    case "aggregator":
      return "aggregator";
    case "coverage":
      return "agent";
    case "inspection":
    case "complete":
      return "agent";
  }
}

function agentProgressStatus(
  status: CanonicalAgentProgressEvent["status"],
): ScanProgressStatus {
  switch (status) {
    case "started":
      return "running";
    case "partial":
      return "degraded";
    case "completed":
    case "degraded":
    case "failed":
    case "canceled":
    case "skipped":
      return status;
  }
}

function agentProgressLabel(
  event: Readonly<CanonicalAgentProgressEvent>,
): string {
  if (event.role) {
    return event.role
      .split("-")
      .map((word) => `${word.slice(0, 1).toUpperCase()}${word.slice(1)}`)
      .join(" ");
  }
  return event.phase
    .split("-")
    .map((word) => `${word.slice(0, 1).toUpperCase()}${word.slice(1)}`)
    .join(" ");
}

function emptyScanRun(input: {
  target: string;
  scanMode: ScanMode;
  assistMode: CoreCanonicalScanAssistMode;
  runId: string;
  startedAt: string;
  finishedAt: string;
  terminalStatus: ScanTerminalStatus;
  degradationReasons: string[];
}): ScanRun {
  const scannerStatus: ScannerStatus = {
    id: "scanner-path",
    label: "Scanner path",
    status:
      input.terminalStatus === "canceled" ? "skipped" : "failed",
    message: input.degradationReasons[0] ?? "Scanner path did not complete.",
  };
  return {
    schemaVersion: "1.0",
    id: input.runId,
    assistMode: input.assistMode,
    terminalStatus: input.terminalStatus,
    degradationReasons: [...input.degradationReasons],
    target: path.resolve(input.target),
    mode: input.scanMode,
    startedAt: input.startedAt,
    finishedAt: input.finishedAt,
    durationMs: elapsedMs(Date.parse(input.startedAt), input.finishedAt),
    scannerStatuses: [scannerStatus],
    findings: [],
    summary: summarize([]),
  };
}

function stableFindingOrder(findings: readonly Finding[]): Finding[] {
  return findings
    .map(cloneFinding)
    .sort(
      (left, right) =>
        left.fingerprint.localeCompare(right.fingerprint) ||
        left.id.localeCompare(right.id),
    );
}

function cloneFinding(finding: Finding): Finding {
  return structuredClone(finding);
}

function uniqueSorted(values: readonly string[]): string[] {
  return [...new Set(values.filter(Boolean))].sort();
}

function elapsedMs(startedMs: number, finishedAt: string): number {
  const finishedMs = Date.parse(finishedAt);
  return Number.isFinite(startedMs) && Number.isFinite(finishedMs)
    ? Math.max(0, finishedMs - startedMs)
    : 0;
}

function freezeResult(
  result: CanonicalScanOrchestrationResult,
): Readonly<CanonicalScanOrchestrationResult> {
  return deepFreeze(structuredClone(result));
}

function deepFreeze<T>(value: T): T {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const nested of Object.values(value as Record<string, unknown>)) {
      deepFreeze(nested);
    }
  }
  return value;
}
