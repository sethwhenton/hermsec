import { computeMetricsFromCounts } from "./metrics.js";
import type { DetectionCounts, EvalFindingCategory, EvalMetrics, MatchResult } from "./schema.js";

export const EVAL_CATEGORIES: readonly EvalFindingCategory[] = [
  "code",
  "dependency",
  "secret",
  "supply-chain",
  "config",
];

export function computeCategoryMetrics(matchResult: MatchResult): Record<EvalFindingCategory, EvalMetrics> {
  const counts = Object.fromEntries(
    EVAL_CATEGORIES.map((category) => [
      category,
      { truePositive: 0, falsePositive: 0, falseNegative: 0, trueNegative: 0 } satisfies DetectionCounts,
    ]),
  ) as Record<EvalFindingCategory, DetectionCounts>;

  for (const match of matchResult.matches) {
    counts[match.expectedCategory].truePositive += 1;
  }

  for (const finding of matchResult.falsePositives) {
    counts[finding.category].falsePositive += 1;
  }

  for (const finding of matchResult.falseNegatives) {
    counts[finding.category].falseNegative += 1;
  }

  if (matchResult.trueNegative) {
    for (const category of EVAL_CATEGORIES) {
      counts[category].trueNegative += 1;
    }
  }

  return Object.fromEntries(
    EVAL_CATEGORIES.map((category) => [category, computeMetricsFromCounts(counts[category])]),
  ) as Record<EvalFindingCategory, EvalMetrics>;
}

export function applyMacroAndWeightedF1(
  overall: EvalMetrics,
  byCategory: Record<EvalFindingCategory, EvalMetrics>,
): EvalMetrics {
  const macroF1 =
    EVAL_CATEGORIES.reduce((total, category) => total + byCategory[category].f1, 0) / EVAL_CATEGORIES.length;
  const totalWeight = EVAL_CATEGORIES.reduce(
    (total, category) => total + Math.max(1, byCategory[category].totalExpected),
    0,
  );
  const weightedF1 = EVAL_CATEGORIES.reduce(
    (total, category) => total + byCategory[category].f1 * Math.max(1, byCategory[category].totalExpected),
    0,
  ) / totalWeight;

  return {
    ...overall,
    macroF1,
    weightedF1,
  };
}
