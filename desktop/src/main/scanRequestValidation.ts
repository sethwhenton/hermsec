import type {
  HermsecProductScanAssistMode,
  ProjectStateFingerprint,
  ScanProgressEvent,
  ScanProjectRequest,
  ScanProjectResult,
} from "../renderer/src/types/scan";

const CANONICAL_ASSIST_MODES = new Set<HermsecProductScanAssistMode>([
  "scanner-only",
  "single-agent",
  "moa-low",
  "moa-high",
  "scanner-single",
  "scanner-moa-low",
  "scanner-moa-high",
]);
const REQUEST_KEYS = new Set([
  "runId",
  "targetPath",
  "reportDir",
  "mode",
  "assistMode",
  "useModel",
  "skipIfUnchanged",
  "previousProjectState",
]);
const PROJECT_STATE_KEYS = new Set([
  "kind",
  "fingerprint",
  "gitHead",
  "gitBranch",
  "gitDirty",
  "gitStatusHash",
  "fileStateHash",
  "capturedAt",
]);
const RUN_ID_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$/;
const HASH_PATTERN = /^[a-fA-F0-9]{64}$/;
const MAX_PATH_LENGTH = 32_767;

export type ScanRequestValidation =
  | { ok: true; request: ScanProjectRequest }
  | { ok: false; result: ScanProjectResult };

export type ScanRequestExecutor = (
  request: ScanProjectRequest,
  onProgress?: (event: ScanProgressEvent) => void,
) => Promise<ScanProjectResult>;

export function validateScanProjectRequest(value: unknown): ScanRequestValidation {
  try {
    if (!isPlainRecord(value)) {
      return invalidRequest("Scan request must be an object.");
    }

    const unknownKey = Object.keys(value).find((key) => !REQUEST_KEYS.has(key));
    if (unknownKey) {
      return invalidRequest(`Scan request contains an unsupported field: ${unknownKey}.`);
    }

    const runId = optionalRunId(value.runId);
    if (!runId.ok) return invalidRequest(runId.message);

    const targetPath = optionalPath(value.targetPath, "targetPath");
    if (!targetPath.ok) return invalidRequest(targetPath.message, runId.value);

    const reportDir = optionalPath(value.reportDir, "reportDir");
    if (!reportDir.ok) return invalidRequest(reportDir.message, runId.value);

    if (value.mode !== undefined && value.mode !== "online") {
      return invalidRequest("Scan mode must be online.", runId.value);
    }

    const assistMode = value.assistMode === undefined ? "scanner-only" : value.assistMode;
    if (!isCanonicalAssistMode(assistMode)) {
      return invalidRequest("Scan assist mode is not one of the seven canonical modes.", runId.value);
    }

    if (value.useModel !== undefined && typeof value.useModel !== "boolean") {
      return invalidRequest("useModel must be a boolean.", runId.value, assistMode);
    }
    if (value.skipIfUnchanged !== undefined && typeof value.skipIfUnchanged !== "boolean") {
      return invalidRequest("skipIfUnchanged must be a boolean.", runId.value, assistMode);
    }

    const previousProjectState = validateProjectState(value.previousProjectState);
    if (!previousProjectState.ok) {
      return invalidRequest(previousProjectState.message, runId.value, assistMode);
    }

    const request: ScanProjectRequest = {
      mode: "online",
      assistMode,
      useModel: assistMode !== "scanner-only",
    };
    if (runId.value) request.runId = runId.value;
    if (targetPath.value) request.targetPath = targetPath.value;
    if (reportDir.value) request.reportDir = reportDir.value;
    if (value.skipIfUnchanged !== undefined) request.skipIfUnchanged = value.skipIfUnchanged;
    if (previousProjectState.value) request.previousProjectState = previousProjectState.value;
    return { ok: true, request };
  } catch {
    return invalidRequest("Scan request could not be validated safely.");
  }
}

export async function executeScanProjectRequest(
  value: unknown,
  execute: ScanRequestExecutor,
  onProgress?: (event: ScanProgressEvent) => void,
): Promise<ScanProjectResult> {
  const validation = validateScanProjectRequest(value);
  if (!validation.ok) return validation.result;

  try {
    return await execute(validation.request, onProgress);
  } catch {
    return {
      ok: false,
      message: "The desktop scan handler could not process this request.",
      error: "scan-handler-failed",
      runId: validation.request.runId,
      assistMode: validation.request.assistMode ?? "scanner-only",
      terminalStatus: "failed",
      degradationReasons: ["The desktop scan handler failed before a scan result was available."],
    };
  }
}

function invalidRequest(
  message: string,
  runId?: string,
  assistMode: HermsecProductScanAssistMode = "scanner-only",
): ScanRequestValidation {
  return {
    ok: false,
    result: {
      ok: false,
      message,
      error: "invalid-scan-request",
      ...(runId ? { runId } : {}),
      assistMode,
      terminalStatus: "failed",
      degradationReasons: ["The desktop rejected malformed scan input."],
    },
  };
}

function optionalRunId(
  value: unknown,
): { ok: true; value?: string } | { ok: false; message: string } {
  if (value === undefined) return { ok: true };
  if (typeof value !== "string") return { ok: false, message: "runId must be a string." };
  const trimmed = value.trim();
  if (!RUN_ID_PATTERN.test(trimmed)) {
    return { ok: false, message: "runId contains unsupported characters or is too long." };
  }
  return { ok: true, value: trimmed };
}

function optionalPath(
  value: unknown,
  field: "targetPath" | "reportDir",
): { ok: true; value?: string } | { ok: false; message: string } {
  if (value === undefined) return { ok: true };
  if (typeof value !== "string") return { ok: false, message: `${field} must be a string.` };
  const trimmed = value.trim();
  if (!trimmed) return { ok: false, message: `${field} cannot be empty.` };
  if (trimmed.length > MAX_PATH_LENGTH || /[\u0000-\u001f]/u.test(trimmed)) {
    return { ok: false, message: `${field} contains unsupported characters or is too long.` };
  }
  return { ok: true, value: trimmed };
}

function validateProjectState(
  value: unknown,
): { ok: true; value?: ProjectStateFingerprint } | { ok: false; message: string } {
  if (value === undefined) return { ok: true };
  if (!isPlainRecord(value)) {
    return { ok: false, message: "previousProjectState must be an object." };
  }
  const unknownKey = Object.keys(value).find((key) => !PROJECT_STATE_KEYS.has(key));
  if (unknownKey) {
    return { ok: false, message: `previousProjectState contains an unsupported field: ${unknownKey}.` };
  }
  if (value.kind !== "git" && value.kind !== "filesystem") {
    return { ok: false, message: "previousProjectState.kind must be git or filesystem." };
  }
  if (typeof value.fingerprint !== "string" || !HASH_PATTERN.test(value.fingerprint)) {
    return { ok: false, message: "previousProjectState.fingerprint must be a SHA-256 hash." };
  }
  if (typeof value.capturedAt !== "string" || !isIsoDate(value.capturedAt)) {
    return { ok: false, message: "previousProjectState.capturedAt must be an ISO timestamp." };
  }
  for (const field of ["gitHead", "gitBranch"] as const) {
    const candidate = value[field];
    if (candidate !== undefined && (typeof candidate !== "string" || !candidate.trim() || candidate.length > 512)) {
      return { ok: false, message: `previousProjectState.${field} must be a non-empty string.` };
    }
  }
  for (const field of ["gitStatusHash", "fileStateHash"] as const) {
    const candidate = value[field];
    if (candidate !== undefined && (typeof candidate !== "string" || !HASH_PATTERN.test(candidate))) {
      return { ok: false, message: `previousProjectState.${field} must be a SHA-256 hash.` };
    }
  }
  if (value.gitDirty !== undefined && typeof value.gitDirty !== "boolean") {
    return { ok: false, message: "previousProjectState.gitDirty must be a boolean." };
  }

  const state: ProjectStateFingerprint = {
    kind: value.kind,
    fingerprint: value.fingerprint.toLowerCase(),
    capturedAt: new Date(value.capturedAt).toISOString(),
  };
  if (typeof value.gitHead === "string") state.gitHead = value.gitHead.trim();
  if (typeof value.gitBranch === "string") state.gitBranch = value.gitBranch.trim();
  if (typeof value.gitDirty === "boolean") state.gitDirty = value.gitDirty;
  if (typeof value.gitStatusHash === "string") state.gitStatusHash = value.gitStatusHash.toLowerCase();
  if (typeof value.fileStateHash === "string") state.fileStateHash = value.fileStateHash.toLowerCase();
  return { ok: true, value: state };
}

function isCanonicalAssistMode(value: unknown): value is HermsecProductScanAssistMode {
  return typeof value === "string" && CANONICAL_ASSIST_MODES.has(value as HermsecProductScanAssistMode);
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function isIsoDate(value: string): boolean {
  if (value.length > 64) return false;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) && new Date(timestamp).toISOString() === value;
}
