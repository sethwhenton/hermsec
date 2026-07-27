import { usdToNanoUsd } from "../agent/costTracker.js";

export type ResearchExecutionMode = "mock" | "replay" | "live";

export const MAX_RESEARCH_GLOBAL_BUDGET_USD = 3.25;

export const MAX_RESEARCH_MODE_BUDGET_USD = Object.freeze({
  "scanner-only": 0,
  "single-agent": 0.015,
  "moa-low": 0.06,
  "moa-high": 0.12,
  "scanner-single": 0.015,
  "scanner-moa-low": 0.06,
  "scanner-moa-high": 0.12,
} as const);

export type CanonicalResearchMode = keyof typeof MAX_RESEARCH_MODE_BUDGET_USD;

export type ResearchExecutionPolicy = {
  execution: ResearchExecutionMode;
  scored: boolean;
  allowSpend: boolean;
  noModelFallback: true;
  exactModelAllowlist: readonly string[];
  globalBudgetUsd: number;
  modeBudgetUsd: number;
};

export function snapshotExecutionPolicy(
  policy: ResearchExecutionPolicy,
): Readonly<ResearchExecutionPolicy> {
  const snapshot: ResearchExecutionPolicy = {
    execution: policy.execution,
    scored: policy.scored,
    allowSpend: policy.allowSpend,
    noModelFallback: policy.noModelFallback,
    exactModelAllowlist: Object.freeze([...policy.exactModelAllowlist]),
    globalBudgetUsd: policy.globalBudgetUsd,
    modeBudgetUsd: policy.modeBudgetUsd,
  };
  validateExecutionPolicy(snapshot);
  return Object.freeze(snapshot);
}

export function validateExecutionPolicy(policy: ResearchExecutionPolicy): void {
  if (policy.noModelFallback !== true) {
    throw new Error("Research runs require noModelFallback=true.");
  }
  if (policy.exactModelAllowlist.length === 0) {
    throw new Error("Research runs require a non-empty exact model allowlist.");
  }
  if (new Set(policy.exactModelAllowlist).size !== policy.exactModelAllowlist.length) {
    throw new Error("The exact model allowlist contains duplicate model IDs.");
  }
  for (const model of policy.exactModelAllowlist) {
    if (!model.trim()) {
      throw new Error("The exact model allowlist contains an empty model ID.");
    }
  }
  assertBudget(policy.globalBudgetUsd, "global");
  assertBudget(policy.modeBudgetUsd, "mode");
  if (
    usdToNanoUsd(policy.globalBudgetUsd) >
    usdToNanoUsd(MAX_RESEARCH_GLOBAL_BUDGET_USD)
  ) {
    throw new Error(
      `The global research budget cannot exceed USD ${MAX_RESEARCH_GLOBAL_BUDGET_USD}.`,
    );
  }

  if (policy.execution === "live" && !policy.allowSpend) {
    throw new Error("Live research execution requires explicit allowSpend=true.");
  }
  if (policy.execution !== "live" && policy.allowSpend) {
    throw new Error("Mock and replay execution must not enable spending.");
  }
}

export function validateModeBudget(mode: string, modeBudgetUsd: number): CanonicalResearchMode {
  if (!(mode in MAX_RESEARCH_MODE_BUDGET_USD)) {
    throw new Error(`Unknown canonical research mode: ${mode}`);
  }
  const canonicalMode = mode as CanonicalResearchMode;
  const maximum = MAX_RESEARCH_MODE_BUDGET_USD[canonicalMode];
  if (usdToNanoUsd(modeBudgetUsd) > usdToNanoUsd(maximum)) {
    throw new Error(
      `The ${canonicalMode} budget cannot exceed USD ${maximum.toFixed(3)} per run.`,
    );
  }
  return canonicalMode;
}

export function requireExactAllowedModel(
  requestedModel: string | undefined,
  policy: ResearchExecutionPolicy,
): string {
  if (!requestedModel?.trim()) {
    throw new Error("Research model requests require an exact model ID.");
  }
  if (!policy.exactModelAllowlist.includes(requestedModel)) {
    throw new Error(`Model is outside the exact research allowlist: ${requestedModel}`);
  }
  return requestedModel;
}

function assertBudget(value: number, label: string): void {
  if (!Number.isFinite(value) || value < 0) {
    throw new Error(`The ${label} research budget must be a non-negative finite USD amount.`);
  }
}
