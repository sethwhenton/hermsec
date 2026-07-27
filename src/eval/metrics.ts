import type { Finding, FindingCategory, Severity } from "../shared/types.js";
import { dedupeActualFindings, projectFinding, projectFindings } from "./findingProjection.js";
import { normalizeGroundTruthFinding } from "./groundTruthSchema.js";
import { matchFindings, scoreCandidate } from "./matcher.js";
import {
  DEFAULT_MATCH_THRESHOLDS,
  type DetectionCounts,
  type EvalMetrics,
  type ExecutionCompleteness,
  type ExecutionCompletenessInput,
  type GroundTruthFinding,
  type MatchResult,
  type SelectiveEvaluationCounts,
  type SelectiveMetrics,
  type WilsonInterval,
} from "./schema.js";

export type { EvalMetrics, GroundTruthFinding } from "./schema.js";

export type SimpleGroundTruthFinding = {
  id: string;
  category: FindingCategory;
  severity: Severity;
  cwe?: string[];
  identifiers?: {
    cve?: string[];
    ghsa?: string[];
    osv?: string[];
  };
  location?: {
    file: string;
    startLine?: number;
    endLine?: number;
  };
  package?: {
    ecosystem: string;
    name: string;
    installedVersion?: string;
  };
};

export type SimpleMatchResult = {
  expectedId: string;
  findingId: string;
  score: number;
};

export type SimpleIgnoredActual = {
  findingId: string;
  reason: "duplicate";
  duplicateOfId: string;
};

export type SimpleEvalMetrics = {
  totalExpected: number;
  totalActual: number;
  truePositive: number;
  falsePositive: number;
  falseNegative: number;
  precision: number;
  recall: number;
  f1: number;
  matches: SimpleMatchResult[];
  unmatchedExpected: string[];
  unmatchedActual: string[];
  ignoredActual: SimpleIgnoredActual[];
};

export type MetricComputationOptions = {
  duplicateCount?: number;
  cleanCaseCount?: number;
  cleanTrueNegativeCases?: number;
  cleanFalsePositiveCases?: number;
  sourceLines?: number;
  categorySupport?: number;
  supportedCategoryCount?: number;
};

export function computeMetricsFromCounts(
  counts: DetectionCounts,
  totalExpected = counts.truePositive + counts.falseNegative,
  totalActual = counts.truePositive + counts.falsePositive,
  options: MetricComputationOptions = {},
): EvalMetrics {
  const precisionDenominator = counts.truePositive + counts.falsePositive;
  const recallDenominator = counts.truePositive + counts.falseNegative;
  const precisionDefined = precisionDenominator > 0;
  const recallDefined = recallDenominator > 0;
  const precision = precisionDefined
    ? counts.truePositive / precisionDenominator
    : 0;
  const recall = recallDefined ? counts.truePositive / recallDenominator : 0;
  const f1Defined = precisionDefined && recallDefined;
  const f1 = f1Defined ? fScore(precision, recall) : 0;

  const cleanCaseCount = options.cleanCaseCount ?? counts.trueNegative;
  const cleanTrueNegativeCases =
    options.cleanTrueNegativeCases ?? counts.trueNegative;
  const cleanFalsePositiveCases = options.cleanFalsePositiveCases ?? 0;
  const cleanSpecificityDefined = cleanCaseCount > 0;
  const cleanSpecificity = cleanSpecificityDefined
    ? cleanTrueNegativeCases / cleanCaseCount
    : 0;
  const duplicateCount = options.duplicateCount ?? 0;
  const rawActualCount = totalActual + duplicateCount;
  const sourceLines = options.sourceLines;

  return {
    totalExpected,
    totalActual,
    truePositive: counts.truePositive,
    falsePositive: counts.falsePositive,
    falseNegative: counts.falseNegative,
    trueNegativeCases: cleanTrueNegativeCases,
    precision,
    precisionDefined,
    precisionInterval: precisionDefined
      ? wilsonInterval(counts.truePositive, precisionDenominator)
      : null,
    recall,
    recallDefined,
    recallInterval: recallDefined
      ? wilsonInterval(counts.truePositive, recallDenominator)
      : null,
    f1,
    f1Defined,
    falsePositiveRate: cleanSpecificityDefined ? 1 - cleanSpecificity : 0,
    falsePositiveRateDefined: cleanSpecificityDefined,
    falseNegativeRate: recallDefined ? counts.falseNegative / recallDenominator : 0,
    macroF1: 0,
    weightedF1: 0,
    groupMetricsDefined: false,
    macroF1IncludingSpurious: 0,
    weightedF1IncludingSpurious: 0,
    predictionOnlyGroupCount: 0,
    categorySupport: options.categorySupport ?? totalExpected,
    supportedCategoryCount:
      options.supportedCategoryCount ?? (totalExpected > 0 ? 1 : 0),
    duplicateCount,
    duplicateRate: rawActualCount > 0 ? duplicateCount / rawActualCount : 0,
    cleanCaseCount,
    cleanTrueNegativeCases,
    cleanFalsePositiveCases,
    cleanSpecificity,
    cleanSpecificityDefined,
    cleanSpecificityInterval: cleanSpecificityDefined
      ? wilsonInterval(cleanTrueNegativeCases, cleanCaseCount)
      : null,
    falseFindingsPerKloc:
      typeof sourceLines === "number" && sourceLines > 0
        ? counts.falsePositive / (sourceLines / 1_000)
        : null,
  };
}

export function computeMetrics(
  matchResult: MatchResult,
  options: Pick<MetricComputationOptions, "sourceLines"> = {},
): EvalMetrics {
  return computeSuiteMetrics([matchResult], options);
}

export function computeSuiteMetrics(
  matchResults: readonly MatchResult[],
  options: Pick<MetricComputationOptions, "sourceLines"> = {},
): EvalMetrics {
  const counts = matchResults.reduce<DetectionCounts>(
    (total, result) => ({
      truePositive: total.truePositive + result.matches.length,
      falsePositive: total.falsePositive + result.falsePositives.length,
      falseNegative: total.falseNegative + result.falseNegatives.length,
      trueNegative: total.trueNegative + (result.trueNegative ? 1 : 0),
    }),
    { truePositive: 0, falsePositive: 0, falseNegative: 0, trueNegative: 0 },
  );
  const cleanResults = matchResults.filter(
    (result) => result.matches.length + result.falseNegatives.length === 0,
  );
  const cleanFalsePositiveCases = cleanResults.filter(
    (result) => result.falsePositives.length > 0,
  ).length;
  const duplicateCount = matchResults.reduce(
    (total, result) => total + result.ignoredActual.length,
    0,
  );
  const totalExpected = counts.truePositive + counts.falseNegative;
  const totalActual = counts.truePositive + counts.falsePositive;

  return computeMetricsFromCounts(counts, totalExpected, totalActual, {
    duplicateCount,
    cleanCaseCount: cleanResults.length,
    cleanTrueNegativeCases: cleanResults.length - cleanFalsePositiveCases,
    cleanFalsePositiveCases,
    ...(typeof options.sourceLines === "number"
      ? { sourceLines: options.sourceLines }
      : {}),
  });
}

export function evaluateFindings(
  expected: readonly (GroundTruthFinding | SimpleGroundTruthFinding)[],
  actual: readonly Finding[],
  options: { fixtureRoot?: string } = {},
): EvalMetrics {
  const normalizedExpected = expected.map((finding) =>
    normalizeGroundTruthFinding(
      toGroundTruthFinding(finding),
      options.fixtureRoot,
    ),
  );
  const projectedActual = projectFindings(actual, options);
  return computeMetrics(matchFindings(normalizedExpected, projectedActual));
}

/**
 * Compatibility wrapper for older CLI/report callers. Matching semantics are
 * now the same strict, optimal semantics as the canonical evaluator.
 */
export function evaluateFindingsSimple(
  expected: readonly SimpleGroundTruthFinding[],
  actual: readonly Finding[],
  minScore = DEFAULT_MATCH_THRESHOLDS.minMatchScore,
): SimpleEvalMetrics {
  const normalizedExpected = expected.map((finding) =>
    normalizeGroundTruthFinding(toGroundTruthFinding(finding)),
  );
  const projectedActual = projectFindings(actual);
  const matchResult = matchFindings(normalizedExpected, projectedActual, {
    ...DEFAULT_MATCH_THRESHOLDS,
    minMatchScore: minScore,
  }, { dedupeMode: "legacy" });
  const metrics = computeMetrics(matchResult);

  return {
    totalExpected: metrics.totalExpected,
    totalActual: metrics.totalActual,
    truePositive: metrics.truePositive,
    falsePositive: metrics.falsePositive,
    falseNegative: metrics.falseNegative,
    precision: metrics.precision,
    recall: metrics.recall,
    f1: metrics.f1,
    matches: matchResult.matches.map((match) => ({
      expectedId: match.expectedId,
      findingId: match.actualId,
      score: match.evidenceScore,
    })),
    unmatchedExpected: matchResult.falseNegatives.map((finding) => finding.id),
    unmatchedActual: matchResult.falsePositives.map((finding) => finding.id),
    ignoredActual: matchResult.ignoredActual.map((item) => ({
      findingId: item.id,
      reason: item.reason,
      duplicateOfId: item.duplicateOfId,
    })),
  };
}

export function scoreMatch(
  expected: SimpleGroundTruthFinding,
  actual: Finding,
): number {
  const candidate = scoreCandidate(
    normalizeGroundTruthFinding(toGroundTruthFinding(expected)),
    projectFinding(actual),
  );
  return candidate.eligible ? candidate.evidenceScore : 0;
}

export function computeSelectiveMetrics(
  counts: SelectiveEvaluationCounts,
): SelectiveMetrics {
  assertNonNegativeIntegers(counts);
  const rejectedTruePositive = counts.rejectedTruePositive ?? 0;
  const rejectedFalsePositive = counts.rejectedFalsePositive ?? 0;
  if (
    counts.acceptedTruePositive +
      counts.needsReviewTruePositive +
      rejectedTruePositive >
    counts.totalExpected
  ) {
    throw new Error(
      "selective true-positive dispositions cannot exceed totalExpected",
    );
  }
  const acceptedPredictions =
    counts.acceptedTruePositive + counts.acceptedFalsePositive;
  const needsReviewPredictions =
    counts.needsReviewTruePositive + counts.needsReviewFalsePositive;
  const rejectedPredictions = rejectedTruePositive + rejectedFalsePositive;
  const totalPredictions =
    acceptedPredictions + needsReviewPredictions + rejectedPredictions;
  const selectivePrecisionDefined = acceptedPredictions > 0;
  const acceptedCoverageDefined = counts.totalExpected > 0;

  return {
    totalPredictions,
    abstainedPredictions: needsReviewPredictions,
    abstentionRate:
      totalPredictions > 0 ? needsReviewPredictions / totalPredictions : 0,
    abstentionRateDefined: totalPredictions > 0,
    selectivePrecision: selectivePrecisionDefined
      ? counts.acceptedTruePositive / acceptedPredictions
      : 0,
    selectivePrecisionDefined,
    selectivePrecisionInterval: selectivePrecisionDefined
      ? wilsonInterval(counts.acceptedTruePositive, acceptedPredictions)
      : null,
    acceptedCoverage: acceptedCoverageDefined
      ? counts.acceptedTruePositive / counts.totalExpected
      : 0,
    acceptedCoverageDefined,
    needsReviewRecall: acceptedCoverageDefined
      ? counts.needsReviewTruePositive / counts.totalExpected
      : 0,
    needsReviewRecallDefined: acceptedCoverageDefined,
  };
}

export function computeExecutionCompleteness(
  input: ExecutionCompletenessInput,
): ExecutionCompleteness {
  const planned = uniqueSorted(input.plannedComponents);
  const completed = new Set(uniqueSorted(input.completedComponents));
  const failedComponents = uniqueSorted(input.failedComponents ?? []);
  const skippedComponents = uniqueSorted(input.skippedComponents ?? []);
  const unsupportedLanguages = uniqueSorted(input.unsupportedLanguages ?? []);
  const degradedReasons = uniqueSorted(input.degradedReasons ?? []);
  const completedComponentCount = planned.filter((component) =>
    completed.has(component),
  ).length;
  const eligibleFiles =
    typeof input.eligibleFiles === "number" && input.eligibleFiles >= 0
      ? input.eligibleFiles
      : null;
  const inspectedFiles =
    typeof input.inspectedFiles === "number" && input.inspectedFiles >= 0
      ? input.inspectedFiles
      : null;
  const fileCoverage =
    eligibleFiles !== null && eligibleFiles > 0 && inspectedFiles !== null
      ? Math.min(1, inspectedFiles / eligibleFiles)
      : eligibleFiles === 0 && inspectedFiles === 0
        ? 1
        : null;
  const componentCompletionRate =
    planned.length > 0 ? completedComponentCount / planned.length : 1;
  const degraded =
    failedComponents.length > 0 ||
    unsupportedLanguages.length > 0 ||
    degradedReasons.length > 0;
  const partial =
    skippedComponents.length > 0 ||
    componentCompletionRate < 1 ||
    (fileCoverage !== null && fileCoverage < 1);

  return {
    status: degraded ? "degraded" : partial ? "partial" : "complete",
    plannedComponentCount: planned.length,
    completedComponentCount,
    failedComponents,
    skippedComponents,
    componentCompletionRate,
    eligibleFiles,
    inspectedFiles,
    fileCoverage,
    inspectedBytes:
      typeof input.inspectedBytes === "number" && input.inspectedBytes > 0
        ? input.inspectedBytes
        : 0,
    unsupportedLanguages,
    degradedReasons,
  };
}

export function wilsonInterval(
  successes: number,
  trials: number,
  confidence = 0.95,
): WilsonInterval {
  if (
    !Number.isSafeInteger(successes) ||
    !Number.isSafeInteger(trials) ||
    successes < 0 ||
    trials <= 0 ||
    successes > trials
  ) {
    throw new Error(
      "Wilson interval requires integer successes within a positive trial count",
    );
  }
  if (confidence <= 0 || confidence >= 1) {
    throw new Error("Wilson confidence must be between zero and one");
  }

  const z = confidenceToZ(confidence);
  const proportion = successes / trials;
  const zSquared = z * z;
  const denominator = 1 + zSquared / trials;
  const center = (proportion + zSquared / (2 * trials)) / denominator;
  const margin =
    (z *
      Math.sqrt(
        (proportion * (1 - proportion) + zSquared / (4 * trials)) / trials,
      )) /
    denominator;

  return {
    lower: Math.max(0, center - margin),
    upper: Math.min(1, center + margin),
    confidence,
  };
}

export function fScore(precision: number, recall: number): number {
  if (precision + recall === 0) {
    return 0;
  }

  return (2 * precision * recall) / (precision + recall);
}

export function safeRatio(
  numerator: number,
  denominator: number,
  emptyValue: number,
): number {
  if (denominator === 0) {
    return emptyValue;
  }

  return numerator / denominator;
}

function toGroundTruthFinding(
  input: GroundTruthFinding | SimpleGroundTruthFinding,
): GroundTruthFinding {
  if ("title" in input && "identifiers" in input && Array.isArray(input.cwe)) {
    return input;
  }

  return {
    id: input.id,
    category: input.category,
    title: input.id,
    severity: input.severity,
    cwe: input.cwe ?? [],
    identifiers: {
      cve: input.identifiers?.cve ?? [],
      ghsa: input.identifiers?.ghsa ?? [],
      osv: input.identifiers?.osv ?? [],
    },
    ...(input.location
      ? {
          location: {
            path:
              "path" in input.location
                ? input.location.path
                : input.location.file,
            ...(typeof input.location.startLine === "number"
              ? { startLine: input.location.startLine }
              : {}),
            ...(typeof input.location.endLine === "number"
              ? { endLine: input.location.endLine }
              : {}),
          },
        }
      : {}),
    ...(input.package ? { package: { ...input.package } } : {}),
  };
}

function assertNonNegativeIntegers(counts: SelectiveEvaluationCounts): void {
  for (const [key, value] of Object.entries(counts)) {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error(`${key} must be a non-negative integer`);
    }
  }
}

function uniqueSorted(values: readonly string[]): string[] {
  return [...new Set(values.filter((value) => value.trim() !== ""))].sort();
}

function confidenceToZ(confidence: number): number {
  if (Math.abs(confidence - 0.9) < 1e-9) return 1.6448536269514722;
  if (Math.abs(confidence - 0.95) < 1e-9) return 1.959963984540054;
  if (Math.abs(confidence - 0.99) < 1e-9) return 2.5758293035489004;
  throw new Error("Supported Wilson confidence levels are 0.90, 0.95, and 0.99");
}
