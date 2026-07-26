import assert from "node:assert/strict";
import test from "node:test";
import {
  buildCapabilityNormalizedComparison,
  buildCostNormalizedComparison,
  type ModeEvaluationObservation,
} from "../../../src/eval/modeComparison.js";

test("capability normalization keeps equal per-agent budgets despite different agent counts", () => {
  const single = observation("single", "single-agent", 1, 0.01);
  const moa = observation("moa", "moa-low", 3, 0.04);
  const different = {
    ...observation("different", "moa-high", 5, 0.08),
    capability: {
      ...single.capability,
      maxRoundsPerAgent: 8,
    },
  };

  const comparison = buildCapabilityNormalizedComparison([
    single,
    moa,
    different,
  ]);

  assert.deepEqual(
    comparison.rows.map((row) => row.runId),
    ["moa", "single"],
  );
  assert.equal(comparison.excluded.length, 1);
  assert.equal(comparison.excluded[0]?.runId, "different");
});

test("cost normalization selects nearest cost without consulting F1", () => {
  const comparison = buildCostNormalizedComparison(
    [
      { ...observation("near-low-f1", "single-agent", 1, 0.051), f1: 0.2 },
      { ...observation("far-high-f1", "single-agent", 1, 0.06), f1: 0.99 },
      observation("moa", "moa-low", 3, 0.049),
    ],
    {
      targetCostUsd: 0.05,
      toleranceUsd: 0.002,
      requiredModes: ["single-agent", "moa-low", "scanner-only"],
    },
  );

  assert.equal(
    comparison.rows.find((row) => row.mode === "single-agent")?.runId,
    "near-low-f1",
  );
  assert.equal(comparison.rows.length, 2);
  assert.equal(
    comparison.excluded.find((row) => row.mode === "scanner-only")?.reason,
    "no observation available",
  );
});

function observation(
  runId: string,
  mode: string,
  agentCount: number,
  costUsd: number,
): ModeEvaluationObservation {
  return {
    runId,
    mode,
    precision: 0.8,
    recall: 0.7,
    f1: 0.746,
    costUsd,
    totalTokens: 1_000,
    agentCount,
    capability: {
      modelClass: "cheap-tool-model",
      maxRoundsPerAgent: 5,
      maxToolCallsPerAgent: 12,
      maxInputTokensPerAgent: 8_000,
      maxOutputTokensPerAgent: 2_000,
    },
  };
}
