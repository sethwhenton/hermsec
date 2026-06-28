import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import type { ProductAgentScanMode } from "./productScan.js";

export const PRODUCT_AGENT_CHECKPOINT_SCHEMA_VERSION = "1.0" as const;
export const PRODUCT_AGENT_CHECKPOINT_KIND = "product-agent-scan" as const;
export const PRODUCT_AGENT_CHECKPOINT_DIRECTORY = ".checkpoints" as const;

export type ProductAgentCheckpointPhase = "candidate" | "task" | "revalidation" | "checkpoint";
export type ProductAgentCheckpointStatus = "waiting" | "running" | "completed" | "skipped" | "failed";
export type ProductAgentCheckpointCandidateDecision = "pending" | "accepted" | "rejected" | "needs-review";
export type ProductAgentCheckpointCandidateSource =
  | "scanner-backed"
  | "single-agent"
  | "moa-specialist"
  | "moa-aggregator";

export type ProductAgentCheckpointTask = {
  id: string;
  label: string;
  phase: ProductAgentCheckpointPhase;
  status: ProductAgentCheckpointStatus;
  updatedAt: string;
  startedAt?: string;
  finishedAt?: string;
  durationMs?: number;
  roleId?: string;
  message?: string;
  candidateIds?: string[];
};

export type ProductAgentCheckpointCandidate = {
  id: string;
  source: ProductAgentCheckpointCandidateSource;
  status: ProductAgentCheckpointCandidateDecision;
  updatedAt: string;
  title?: string;
  roleId?: string;
  findingId?: string;
  fingerprint?: string;
  message?: string;
};

export type ProductAgentScanCheckpoint = {
  schemaVersion: typeof PRODUCT_AGENT_CHECKPOINT_SCHEMA_VERSION;
  kind: typeof PRODUCT_AGENT_CHECKPOINT_KIND;
  target: string;
  targetHash: string;
  assistMode: ProductAgentScanMode;
  createdAt: string;
  updatedAt: string;
  currentPhase?: ProductAgentCheckpointPhase;
  tasks: ProductAgentCheckpointTask[];
  candidates: ProductAgentCheckpointCandidate[];
  finalFindingIds?: string[];
  metadata?: Record<string, unknown>;
};

export type ProductAgentCheckpointLocation = {
  reportOutputDirectory: string;
  checkpointDir: string;
  checkpointPath: string;
  fileName: string;
  target: string;
  targetHash: string;
  assistMode: ProductAgentScanMode;
};

export type ProductAgentCheckpointResumeReason =
  | "missing"
  | "invalid-json"
  | "schema-mismatch"
  | "target-mismatch"
  | "assist-mode-mismatch";

export type ProductAgentCheckpointResumeMetadata = {
  available: boolean;
  checkpointPath: string;
  target: string;
  targetHash: string;
  assistMode: ProductAgentScanMode;
  completedTaskIds: string[];
  runningTaskIds: string[];
  candidateCount: number;
  acceptedCandidateCount: number;
  rejectedCandidateCount: number;
  needsReviewCandidateCount: number;
  finalFindingCount: number;
  reason?: ProductAgentCheckpointResumeReason;
  lastUpdatedAt?: string;
  lastPhase?: ProductAgentCheckpointPhase;
  resumedAt?: string;
};

export type ProductAgentCheckpointReadResult = {
  location: ProductAgentCheckpointLocation;
  resume: ProductAgentCheckpointResumeMetadata;
  checkpoint?: ProductAgentScanCheckpoint;
};

export type ProductAgentCheckpointWriteResult = {
  location: ProductAgentCheckpointLocation;
  resume: ProductAgentCheckpointResumeMetadata;
  checkpoint: ProductAgentScanCheckpoint;
};

export type ProductAgentCheckpointStoreInput = {
  reportOutputDirectory: string;
  target: string;
  assistMode: ProductAgentScanMode;
  now?: () => Date;
};

export type ProductAgentCheckpointStore = {
  location: ProductAgentCheckpointLocation;
  read: () => Promise<ProductAgentCheckpointReadResult>;
  resumeMetadata: () => Promise<ProductAgentCheckpointResumeMetadata>;
  write: (checkpoint: ProductAgentScanCheckpoint) => Promise<ProductAgentCheckpointWriteResult>;
  clear: () => Promise<void>;
};

export type ProductAgentCheckpointTaskUpdate = Omit<ProductAgentCheckpointTask, "updatedAt"> & {
  updatedAt?: string;
};

export type ProductAgentCheckpointCandidateUpdate = Omit<ProductAgentCheckpointCandidate, "updatedAt"> & {
  updatedAt?: string;
};

const productAgentModes = new Set<string>(["single-agent", "moa-assisted", "scanner-moa-assisted"]);
const checkpointPhases = new Set<string>(["candidate", "task", "revalidation", "checkpoint"]);
const checkpointStatuses = new Set<string>(["waiting", "running", "completed", "skipped", "failed"]);
const candidateDecisions = new Set<string>(["pending", "accepted", "rejected", "needs-review"]);
const candidateSources = new Set<string>(["scanner-backed", "single-agent", "moa-specialist", "moa-aggregator"]);

export function createProductAgentCheckpointStore(input: ProductAgentCheckpointStoreInput): ProductAgentCheckpointStore {
  const location = resolveProductAgentCheckpointLocation(input);
  return {
    location,
    read: () => readProductAgentCheckpoint(input),
    resumeMetadata: async () => (await readProductAgentCheckpoint(input)).resume,
    write: (checkpoint) => writeProductAgentCheckpoint({ ...input, checkpoint }),
    clear: async () => {
      await fs.rm(location.checkpointPath, { force: true });
    },
  };
}

export function resolveProductAgentCheckpointLocation(input: {
  reportOutputDirectory: string;
  target: string;
  assistMode: ProductAgentScanMode;
}): ProductAgentCheckpointLocation {
  const assistMode = productAgentModeFrom(input.assistMode);
  const reportOutputDirectory = path.resolve(input.reportOutputDirectory);
  const target = canonicalTarget(input.target);
  const targetHash = productAgentTargetHash(target);
  const checkpointDir = path.join(reportOutputDirectory, PRODUCT_AGENT_CHECKPOINT_DIRECTORY);
  const fileName = `${targetHash}-${assistMode}.json`;
  const checkpointPath = assertInsideRoot(reportOutputDirectory, path.join(checkpointDir, fileName));
  return {
    reportOutputDirectory,
    checkpointDir,
    checkpointPath,
    fileName,
    target,
    targetHash,
    assistMode,
  };
}

export function productAgentTargetHash(target: string): string {
  return crypto.createHash("sha256").update(canonicalTarget(target)).digest("hex").slice(0, 16);
}

export function createProductAgentScanCheckpoint(input: {
  reportOutputDirectory: string;
  target: string;
  assistMode: ProductAgentScanMode;
  now?: () => Date;
  currentPhase?: ProductAgentCheckpointPhase;
  tasks?: ProductAgentCheckpointTask[];
  candidates?: ProductAgentCheckpointCandidate[];
  finalFindingIds?: string[];
  metadata?: Record<string, unknown>;
}): ProductAgentScanCheckpoint {
  const location = resolveProductAgentCheckpointLocation(input);
  const now = isoNow(input.now);
  return {
    schemaVersion: PRODUCT_AGENT_CHECKPOINT_SCHEMA_VERSION,
    kind: PRODUCT_AGENT_CHECKPOINT_KIND,
    target: location.target,
    targetHash: location.targetHash,
    assistMode: location.assistMode,
    createdAt: now,
    updatedAt: now,
    ...(input.currentPhase ? { currentPhase: input.currentPhase } : {}),
    tasks: [...(input.tasks ?? [])],
    candidates: [...(input.candidates ?? [])],
    ...(input.finalFindingIds ? { finalFindingIds: [...input.finalFindingIds] } : {}),
    ...(input.metadata ? { metadata: input.metadata } : {}),
  };
}

export function upsertProductAgentCheckpointTask(
  checkpoint: ProductAgentScanCheckpoint,
  task: ProductAgentCheckpointTaskUpdate,
  now?: () => Date,
): ProductAgentScanCheckpoint {
  const updatedAt = task.updatedAt ?? isoNow(now);
  const nextTask: ProductAgentCheckpointTask = {
    ...task,
    updatedAt,
    ...(task.candidateIds ? { candidateIds: [...task.candidateIds] } : {}),
  };
  const tasks = replaceById(checkpoint.tasks, nextTask);
  return {
    ...checkpoint,
    currentPhase: nextTask.phase,
    updatedAt,
    tasks,
  };
}

export function upsertProductAgentCheckpointCandidate(
  checkpoint: ProductAgentScanCheckpoint,
  candidate: ProductAgentCheckpointCandidateUpdate,
  now?: () => Date,
): ProductAgentScanCheckpoint {
  const updatedAt = candidate.updatedAt ?? isoNow(now);
  const nextCandidate: ProductAgentCheckpointCandidate = {
    ...candidate,
    updatedAt,
  };
  const candidates = replaceById(checkpoint.candidates, nextCandidate);
  return {
    ...checkpoint,
    currentPhase: "candidate",
    updatedAt,
    candidates,
  };
}

export async function readProductAgentCheckpoint(input: {
  reportOutputDirectory: string;
  target: string;
  assistMode: ProductAgentScanMode;
  now?: () => Date;
}): Promise<ProductAgentCheckpointReadResult> {
  const location = resolveProductAgentCheckpointLocation(input);
  let raw: string;
  try {
    raw = await fs.readFile(location.checkpointPath, "utf8");
  } catch (error) {
    if (isErrnoException(error) && error.code === "ENOENT") {
      return {
        location,
        resume: emptyResumeMetadata(location, "missing"),
      };
    }
    throw error;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch {
    return {
      location,
      resume: emptyResumeMetadata(location, "invalid-json"),
    };
  }

  const checkpoint = checkpointFromUnknown(parsed);
  if (!checkpoint) {
    return {
      location,
      resume: emptyResumeMetadata(location, "schema-mismatch"),
    };
  }
  if (checkpoint.targetHash !== location.targetHash) {
    return {
      location,
      resume: emptyResumeMetadata(location, "target-mismatch"),
    };
  }
  if (checkpoint.assistMode !== location.assistMode) {
    return {
      location,
      resume: emptyResumeMetadata(location, "assist-mode-mismatch"),
    };
  }

  return {
    location,
    checkpoint,
    resume: buildProductAgentResumeMetadata(checkpoint, location, input.now),
  };
}

export async function writeProductAgentCheckpoint(input: {
  reportOutputDirectory: string;
  checkpoint: ProductAgentScanCheckpoint;
  now?: () => Date;
}): Promise<ProductAgentCheckpointWriteResult> {
  const location = resolveProductAgentCheckpointLocation({
    reportOutputDirectory: input.reportOutputDirectory,
    target: input.checkpoint.target,
    assistMode: input.checkpoint.assistMode,
  });
  if (input.checkpoint.targetHash !== location.targetHash) {
    throw new Error(`Product agent checkpoint target hash mismatch: expected ${location.targetHash}, got ${input.checkpoint.targetHash}`);
  }

  const checkpoint: ProductAgentScanCheckpoint = {
    ...input.checkpoint,
    target: location.target,
    targetHash: location.targetHash,
    assistMode: location.assistMode,
    updatedAt: isoNow(input.now),
    tasks: input.checkpoint.tasks.map((task) => ({
      ...task,
      ...(task.candidateIds ? { candidateIds: [...task.candidateIds] } : {}),
    })),
    candidates: input.checkpoint.candidates.map((candidate) => ({ ...candidate })),
    ...(input.checkpoint.finalFindingIds ? { finalFindingIds: [...input.checkpoint.finalFindingIds] } : {}),
  };
  await fs.mkdir(location.checkpointDir, { recursive: true });
  const tempPath = `${location.checkpointPath}.${process.pid}.${Date.now()}.tmp`;
  try {
    await fs.writeFile(tempPath, `${JSON.stringify(checkpoint, null, 2)}\n`, "utf8");
    await fs.rename(tempPath, location.checkpointPath);
  } catch (error) {
    await fs.rm(tempPath, { force: true }).catch(() => undefined);
    throw error;
  }
  return {
    location,
    checkpoint,
    resume: buildProductAgentResumeMetadata(checkpoint, location, input.now),
  };
}

export function buildProductAgentResumeMetadata(
  checkpoint: ProductAgentScanCheckpoint,
  location: ProductAgentCheckpointLocation,
  now?: () => Date,
): ProductAgentCheckpointResumeMetadata {
  const completedTaskIds = checkpoint.tasks
    .filter((task) => task.status === "completed")
    .map((task) => task.id);
  const runningTaskIds = checkpoint.tasks
    .filter((task) => task.status === "running")
    .map((task) => task.id);
  const acceptedCandidateCount = checkpoint.candidates.filter((candidate) => candidate.status === "accepted").length;
  const rejectedCandidateCount = checkpoint.candidates.filter((candidate) => candidate.status === "rejected").length;
  const needsReviewCandidateCount = checkpoint.candidates.filter((candidate) => candidate.status === "needs-review").length;
  const lastPhase = checkpoint.currentPhase ?? checkpoint.tasks.at(-1)?.phase;
  return {
    available: true,
    checkpointPath: location.checkpointPath,
    target: location.target,
    targetHash: location.targetHash,
    assistMode: location.assistMode,
    completedTaskIds,
    runningTaskIds,
    candidateCount: checkpoint.candidates.length,
    acceptedCandidateCount,
    rejectedCandidateCount,
    needsReviewCandidateCount,
    finalFindingCount: checkpoint.finalFindingIds?.length ?? 0,
    lastUpdatedAt: checkpoint.updatedAt,
    ...(lastPhase ? { lastPhase } : {}),
    resumedAt: isoNow(now),
  };
}

function emptyResumeMetadata(
  location: ProductAgentCheckpointLocation,
  reason: ProductAgentCheckpointResumeReason,
): ProductAgentCheckpointResumeMetadata {
  return {
    available: false,
    reason,
    checkpointPath: location.checkpointPath,
    target: location.target,
    targetHash: location.targetHash,
    assistMode: location.assistMode,
    completedTaskIds: [],
    runningTaskIds: [],
    candidateCount: 0,
    acceptedCandidateCount: 0,
    rejectedCandidateCount: 0,
    needsReviewCandidateCount: 0,
    finalFindingCount: 0,
  };
}

function checkpointFromUnknown(value: unknown): ProductAgentScanCheckpoint | undefined {
  if (!isRecord(value)) {
    return undefined;
  }
  if (value.schemaVersion !== PRODUCT_AGENT_CHECKPOINT_SCHEMA_VERSION || value.kind !== PRODUCT_AGENT_CHECKPOINT_KIND) {
    return undefined;
  }
  const target = stringValue(value.target);
  const targetHash = stringValue(value.targetHash);
  const assistMode = productAgentModeOrUndefined(value.assistMode);
  const createdAt = stringValue(value.createdAt);
  const updatedAt = stringValue(value.updatedAt);
  if (!target || !targetHash || !assistMode || !createdAt || !updatedAt) {
    return undefined;
  }
  const currentPhase = checkpointPhaseOrUndefined(value.currentPhase);
  const tasks = Array.isArray(value.tasks) ? value.tasks.flatMap(taskFromUnknown) : [];
  const candidates = Array.isArray(value.candidates) ? value.candidates.flatMap(candidateFromUnknown) : [];
  const finalFindingIds = stringArray(value.finalFindingIds);
  const metadata = isRecord(value.metadata) ? value.metadata : undefined;
  return {
    schemaVersion: PRODUCT_AGENT_CHECKPOINT_SCHEMA_VERSION,
    kind: PRODUCT_AGENT_CHECKPOINT_KIND,
    target,
    targetHash,
    assistMode,
    createdAt,
    updatedAt,
    ...(currentPhase ? { currentPhase } : {}),
    tasks,
    candidates,
    ...(finalFindingIds.length > 0 ? { finalFindingIds } : {}),
    ...(metadata ? { metadata } : {}),
  };
}

function taskFromUnknown(value: unknown): ProductAgentCheckpointTask[] {
  if (!isRecord(value)) {
    return [];
  }
  const id = stringValue(value.id);
  const label = stringValue(value.label);
  const phase = checkpointPhaseOrUndefined(value.phase);
  const status = checkpointStatusOrUndefined(value.status);
  const updatedAt = stringValue(value.updatedAt);
  if (!id || !label || !phase || !status || !updatedAt) {
    return [];
  }
  const startedAt = stringValue(value.startedAt);
  const finishedAt = stringValue(value.finishedAt);
  const durationMs = finiteNonNegativeNumber(value.durationMs);
  const roleId = stringValue(value.roleId);
  const message = stringValue(value.message);
  const candidateIds = stringArray(value.candidateIds);
  return [{
    id,
    label,
    phase,
    status,
    updatedAt,
    ...(startedAt ? { startedAt } : {}),
    ...(finishedAt ? { finishedAt } : {}),
    ...(durationMs !== undefined ? { durationMs } : {}),
    ...(roleId ? { roleId } : {}),
    ...(message ? { message } : {}),
    ...(candidateIds.length > 0 ? { candidateIds } : {}),
  }];
}

function candidateFromUnknown(value: unknown): ProductAgentCheckpointCandidate[] {
  if (!isRecord(value)) {
    return [];
  }
  const id = stringValue(value.id);
  const source = candidateSourceOrUndefined(value.source);
  const status = candidateDecisionOrUndefined(value.status);
  const updatedAt = stringValue(value.updatedAt);
  if (!id || !source || !status || !updatedAt) {
    return [];
  }
  const title = stringValue(value.title);
  const roleId = stringValue(value.roleId);
  const findingId = stringValue(value.findingId);
  const fingerprint = stringValue(value.fingerprint);
  const message = stringValue(value.message);
  return [{
    id,
    source,
    status,
    updatedAt,
    ...(title ? { title } : {}),
    ...(roleId ? { roleId } : {}),
    ...(findingId ? { findingId } : {}),
    ...(fingerprint ? { fingerprint } : {}),
    ...(message ? { message } : {}),
  }];
}

function productAgentModeFrom(value: ProductAgentScanMode): ProductAgentScanMode {
  if (productAgentModes.has(value)) {
    return value;
  }
  throw new Error(`Product agent checkpoints only support product agent assist modes: ${String(value)}`);
}

function productAgentModeOrUndefined(value: unknown): ProductAgentScanMode | undefined {
  return typeof value === "string" && productAgentModes.has(value) ? value as ProductAgentScanMode : undefined;
}

function checkpointPhaseOrUndefined(value: unknown): ProductAgentCheckpointPhase | undefined {
  return typeof value === "string" && checkpointPhases.has(value) ? value as ProductAgentCheckpointPhase : undefined;
}

function checkpointStatusOrUndefined(value: unknown): ProductAgentCheckpointStatus | undefined {
  return typeof value === "string" && checkpointStatuses.has(value) ? value as ProductAgentCheckpointStatus : undefined;
}

function candidateDecisionOrUndefined(value: unknown): ProductAgentCheckpointCandidateDecision | undefined {
  return typeof value === "string" && candidateDecisions.has(value) ? value as ProductAgentCheckpointCandidateDecision : undefined;
}

function candidateSourceOrUndefined(value: unknown): ProductAgentCheckpointCandidateSource | undefined {
  return typeof value === "string" && candidateSources.has(value) ? value as ProductAgentCheckpointCandidateSource : undefined;
}

function canonicalTarget(target: string): string {
  const resolved = path.resolve(target).replace(/\\/g, "/");
  return process.platform === "win32" ? resolved.toLowerCase() : resolved;
}

function assertInsideRoot(rootDir: string, candidatePath: string): string {
  const resolvedRoot = path.resolve(rootDir);
  const resolvedCandidate = path.resolve(candidatePath);
  const relative = path.relative(resolvedRoot, resolvedCandidate);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error(`Checkpoint path escapes configured report output directory: ${resolvedCandidate}`);
  }
  return resolvedCandidate;
}

function isoNow(now?: () => Date): string {
  return (now?.() ?? new Date()).toISOString();
}

function replaceById<T extends { id: string }>(items: readonly T[], next: T): T[] {
  const result = items.filter((item) => item.id !== next.id);
  result.push(next);
  return result;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value : undefined;
}

function stringArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.filter((item): item is string => typeof item === "string" && item.trim().length > 0);
}

function finiteNonNegativeNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isErrnoException(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}
