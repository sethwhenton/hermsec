import fs from "node:fs/promises";
import path from "node:path";
import type { CommandResult } from "../shared/types.js";
import type { SimpleEvalMetrics } from "./metrics.js";

export type CapabilityBudget = {
  modelClass: string;
  maxRoundsPerAgent: number;
  maxToolCallsPerAgent: number;
  maxInputTokensPerAgent: number;
  maxOutputTokensPerAgent: number;
};

export type ModeEvaluationObservation = {
  runId: string;
  mode: string;
  precision: number;
  recall: number;
  f1: number;
  costUsd: number;
  totalTokens: number;
  agentCount: number;
  capability: CapabilityBudget;
};

export type NormalizedComparison<T> = {
  normalization: "capability" | "cost";
  rows: T[];
  excluded: Array<{
    runId?: string;
    mode: string;
    reason: string;
  }>;
};

export type CapabilityNormalizedRow = ModeEvaluationObservation & {
  capabilitySignature: string;
};

export type CostNormalizedRow = ModeEvaluationObservation & {
  targetCostUsd: number;
  absoluteCostDeltaUsd: number;
};

export async function compareEvaluations(options: {
  cwd: string;
  scannerOnly: string;
  agentAssisted: string;
  outputPath?: string;
}): Promise<CommandResult> {
  const scannerOnly = await readMetrics(options.scannerOnly);
  const agentAssisted = await readMetrics(options.agentAssisted);
  const comparison = {
    deltaPrecision: agentAssisted.precision - scannerOnly.precision,
    deltaRecall: agentAssisted.recall - scannerOnly.recall,
    deltaF1: agentAssisted.f1 - scannerOnly.f1,
    scannerOnly,
    agentAssisted,
  };
  if (options.outputPath) {
    const out = path.resolve(options.cwd, options.outputPath);
    await fs.mkdir(path.dirname(out), { recursive: true });
    await fs.writeFile(out, `${JSON.stringify(comparison, null, 2)}\n`, "utf8");
  }
  return {
    ok: true,
    message: `Evaluation comparison completed. Delta F1: ${comparison.deltaF1.toFixed(2)}.`,
    data: comparison,
  };
}

/**
 * Capability normalization keeps the per-agent ceilings fixed. Agent count is
 * intentionally not part of the signature: MoA is allowed more agents, and
 * its resulting extra cost remains visible in each row.
 */
export function buildCapabilityNormalizedComparison(
  observations: readonly ModeEvaluationObservation[],
  reference?: CapabilityBudget,
): NormalizedComparison<CapabilityNormalizedRow> {
  validateObservations(observations);
  const ordered = [...observations].sort(compareObservations);
  const referenceCapability =
    reference ?? selectModalCapability(ordered.map((row) => row.capability));
  if (!referenceCapability) {
    return { normalization: "capability", rows: [], excluded: [] };
  }

  const signature = capabilitySignature(referenceCapability);
  const rows: CapabilityNormalizedRow[] = [];
  const excluded: NormalizedComparison<CapabilityNormalizedRow>["excluded"] =
    [];
  for (const observation of ordered) {
    const observationSignature = capabilitySignature(observation.capability);
    if (observationSignature !== signature) {
      excluded.push({
        runId: observation.runId,
        mode: observation.mode,
        reason: `per-agent capability differs from ${signature}`,
      });
      continue;
    }
    rows.push({ ...observation, capabilitySignature: signature });
  }

  return { normalization: "capability", rows, excluded };
}

/**
 * Cost normalization selects the run nearest to the target for each mode.
 * Selection never uses precision, recall, or F1, avoiding winner selection
 * after results are known.
 */
export function buildCostNormalizedComparison(
  observations: readonly ModeEvaluationObservation[],
  options: {
    targetCostUsd: number;
    toleranceUsd: number;
    requiredModes?: readonly string[];
  },
): NormalizedComparison<CostNormalizedRow> {
  validateObservations(observations);
  if (!Number.isFinite(options.targetCostUsd) || options.targetCostUsd < 0) {
    throw new Error("targetCostUsd must be a non-negative finite number");
  }
  if (!Number.isFinite(options.toleranceUsd) || options.toleranceUsd < 0) {
    throw new Error("toleranceUsd must be a non-negative finite number");
  }

  const byMode = new Map<string, ModeEvaluationObservation[]>();
  for (const observation of observations) {
    const modeRows = byMode.get(observation.mode) ?? [];
    modeRows.push(observation);
    byMode.set(observation.mode, modeRows);
  }

  const modes = [
    ...new Set(options.requiredModes ?? [...byMode.keys()]),
  ].sort();
  const rows: CostNormalizedRow[] = [];
  const excluded: NormalizedComparison<CostNormalizedRow>["excluded"] = [];
  for (const mode of modes) {
    const candidates = [...(byMode.get(mode) ?? [])].sort((left, right) => {
      const leftDelta = Math.abs(left.costUsd - options.targetCostUsd);
      const rightDelta = Math.abs(right.costUsd - options.targetCostUsd);
      return (
        leftDelta - rightDelta ||
        left.costUsd - right.costUsd ||
        left.runId.localeCompare(right.runId)
      );
    });
    const selected = candidates[0];
    if (!selected) {
      excluded.push({ mode, reason: "no observation available" });
      continue;
    }
    const absoluteCostDeltaUsd = Math.abs(
      selected.costUsd - options.targetCostUsd,
    );
    if (absoluteCostDeltaUsd > options.toleranceUsd) {
      excluded.push({
        runId: selected.runId,
        mode,
        reason: `nearest cost differs by ${absoluteCostDeltaUsd.toFixed(6)} USD`,
      });
      continue;
    }

    rows.push({
      ...selected,
      targetCostUsd: options.targetCostUsd,
      absoluteCostDeltaUsd,
    });
  }

  return { normalization: "cost", rows, excluded };
}

async function readMetrics(file: string): Promise<SimpleEvalMetrics> {
  const parsed = JSON.parse(await fs.readFile(file, "utf8")) as { metrics?: SimpleEvalMetrics } | SimpleEvalMetrics;
  if (isWrappedMetrics(parsed)) {
    return parsed.metrics;
  }
  return parsed as SimpleEvalMetrics;
}

function isWrappedMetrics(value: { metrics?: SimpleEvalMetrics } | SimpleEvalMetrics): value is { metrics: SimpleEvalMetrics } {
  return "metrics" in value && value.metrics !== undefined;
}

function capabilitySignature(capability: CapabilityBudget): string {
  validateCapability(capability);
  return [
    capability.modelClass.trim().toLowerCase(),
    `rounds=${capability.maxRoundsPerAgent}`,
    `tools=${capability.maxToolCallsPerAgent}`,
    `in=${capability.maxInputTokensPerAgent}`,
    `out=${capability.maxOutputTokensPerAgent}`,
  ].join("|");
}

function selectModalCapability(
  capabilities: readonly CapabilityBudget[],
): CapabilityBudget | undefined {
  const bySignature = new Map<
    string,
    { capability: CapabilityBudget; count: number }
  >();
  for (const capability of capabilities) {
    const signature = capabilitySignature(capability);
    const current = bySignature.get(signature);
    bySignature.set(signature, {
      capability,
      count: (current?.count ?? 0) + 1,
    });
  }

  return [...bySignature.entries()]
    .sort(
      ([leftSignature, left], [rightSignature, right]) =>
        right.count - left.count ||
        leftSignature.localeCompare(rightSignature),
    )[0]?.[1].capability;
}

function validateObservations(
  observations: readonly ModeEvaluationObservation[],
): void {
  const runIds = new Set<string>();
  for (const observation of observations) {
    if (!observation.runId.trim() || !observation.mode.trim()) {
      throw new Error("comparison observations require runId and mode");
    }
    if (runIds.has(observation.runId)) {
      throw new Error(`comparison runId must be unique: ${observation.runId}`);
    }
    runIds.add(observation.runId);
    for (const [name, value] of Object.entries({
      precision: observation.precision,
      recall: observation.recall,
      f1: observation.f1,
    })) {
      if (!Number.isFinite(value) || value < 0 || value > 1) {
        throw new Error(`${name} must be between zero and one`);
      }
    }
    if (!Number.isFinite(observation.costUsd) || observation.costUsd < 0) {
      throw new Error("costUsd must be a non-negative finite number");
    }
    if (
      !Number.isSafeInteger(observation.totalTokens) ||
      observation.totalTokens < 0 ||
      !Number.isSafeInteger(observation.agentCount) ||
      observation.agentCount < 0
    ) {
      throw new Error("token and agent counts must be non-negative integers");
    }
    validateCapability(observation.capability);
  }
}

function validateCapability(capability: CapabilityBudget): void {
  if (!capability.modelClass.trim()) {
    throw new Error("capability modelClass is required");
  }
  for (const [name, value] of Object.entries({
    maxRoundsPerAgent: capability.maxRoundsPerAgent,
    maxToolCallsPerAgent: capability.maxToolCallsPerAgent,
    maxInputTokensPerAgent: capability.maxInputTokensPerAgent,
    maxOutputTokensPerAgent: capability.maxOutputTokensPerAgent,
  })) {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error(`${name} must be a non-negative integer`);
    }
  }
}

function compareObservations(
  left: ModeEvaluationObservation,
  right: ModeEvaluationObservation,
): number {
  return (
    left.mode.localeCompare(right.mode) || left.runId.localeCompare(right.runId)
  );
}
