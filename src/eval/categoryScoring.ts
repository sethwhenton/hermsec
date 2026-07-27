import { computeMetricsFromCounts } from "./metrics.js";
import type {
  DetectionCounts,
  EvalFindingCategory,
  EvalMetrics,
  GroupedMetricSummary,
  MatchResult,
} from "./schema.js";
import { inferPrimaryVulnerabilityClass } from "./vulnerabilityClass.js";

export const EVAL_CATEGORIES: readonly EvalFindingCategory[] = [
  "code",
  "dependency",
  "secret",
  "supply-chain",
  "config",
];

export const UNCLASSIFIED_VULNERABILITY_CLASS = "<unclassified>";

type GroupCounts = DetectionCounts & {
  cleanCaseCount: number;
  cleanFalsePositiveCases: number;
};

export function computeCategoryMetrics(
  input: MatchResult | readonly MatchResult[],
): Record<EvalFindingCategory, EvalMetrics> {
  const results = asResults(input);
  const counts = Object.fromEntries(
    EVAL_CATEGORIES.map((category) => [category, emptyGroupCounts()]),
  ) as Record<EvalFindingCategory, GroupCounts>;

  for (const result of results) {
    for (const match of result.matches) {
      counts[match.expectedCategory].truePositive += 1;
    }
    for (const finding of result.falsePositives) {
      counts[finding.category].falsePositive += 1;
    }
    for (const finding of result.falseNegatives) {
      counts[finding.category].falseNegative += 1;
    }

    if (isCleanResult(result)) {
      for (const category of EVAL_CATEGORIES) {
        counts[category].cleanCaseCount += 1;
        const failed = result.falsePositives.some(
          (finding) => finding.category === category,
        );
        if (failed) {
          counts[category].cleanFalsePositiveCases += 1;
        } else {
          counts[category].trueNegative += 1;
        }
      }
    }
  }

  return Object.fromEntries(
    EVAL_CATEGORIES.map((category) => [
      category,
      metricsForGroup(counts[category]),
    ]),
  ) as Record<EvalFindingCategory, EvalMetrics>;
}

export function computeVulnerabilityClassMetrics(
  input: MatchResult | readonly MatchResult[],
): Record<string, EvalMetrics> {
  const results = asResults(input);
  const classes = collectVulnerabilityClasses(results);
  const counts = new Map(
    classes.map((vulnerabilityClass) => [
      vulnerabilityClass,
      emptyGroupCounts(),
    ]),
  );

  for (const result of results) {
    for (const match of result.matches) {
      if (match.expectedVulnerabilityClass) {
        ensureGroup(counts, match.expectedVulnerabilityClass).truePositive += 1;
      }
    }
    for (const finding of result.falseNegatives) {
      const vulnerabilityClass =
        inferPrimaryVulnerabilityClass(finding) ??
        UNCLASSIFIED_VULNERABILITY_CLASS;
      ensureGroup(counts, vulnerabilityClass).falseNegative += 1;
    }
    for (const finding of result.falsePositives) {
      const vulnerabilityClass =
        inferPrimaryVulnerabilityClass(finding) ??
        UNCLASSIFIED_VULNERABILITY_CLASS;
      ensureGroup(counts, vulnerabilityClass).falsePositive += 1;
    }

    if (isCleanResult(result)) {
      const failedClasses = new Set(
        result.falsePositives
          .map(
            (finding) =>
              inferPrimaryVulnerabilityClass(finding) ??
              UNCLASSIFIED_VULNERABILITY_CLASS,
          ),
      );
      for (const vulnerabilityClass of classes) {
        const classCounts = ensureGroup(counts, vulnerabilityClass);
        classCounts.cleanCaseCount += 1;
        if (failedClasses.has(vulnerabilityClass)) {
          classCounts.cleanFalsePositiveCases += 1;
        } else {
          classCounts.trueNegative += 1;
        }
      }
    }
  }

  return Object.fromEntries(
    [...counts.entries()]
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([vulnerabilityClass, classCounts]) => [
        vulnerabilityClass,
        metricsForGroup(classCounts),
      ]),
  );
}

export function computeGroupedMetricSummary(
  byGroup: Readonly<Record<string, EvalMetrics>>,
): GroupedMetricSummary {
  const allGroups = Object.values(byGroup);
  const supportedGroups = allGroups.filter(
    (metrics) => metrics.categorySupport > 0,
  );
  const observedGroups = allGroups.filter(
    (metrics) => metrics.categorySupport > 0 || metrics.totalActual > 0,
  );
  const truthSupport = supportedGroups.reduce(
    (total, metrics) => total + metrics.categorySupport,
    0,
  );
  const observedWeight = observedGroups.reduce(
    (total, metrics) =>
      total + metrics.categorySupport + metrics.falsePositive,
    0,
  );
  const predictionOnlyGroupCount = observedGroups.filter(
    (metrics) =>
      metrics.categorySupport === 0 && metrics.falsePositive > 0,
  ).length;

  return {
    supportedMacroF1:
      supportedGroups.length > 0
        ? average(supportedGroups.map((metrics) => metrics.f1))
        : 0,
    supportedWeightedF1:
      truthSupport > 0
        ? supportedGroups.reduce(
            (total, metrics) =>
              total + metrics.f1 * metrics.categorySupport,
            0,
          ) / truthSupport
        : 0,
    supportedGroupCount: supportedGroups.length,
    truthSupport,
    observedMacroF1:
      observedGroups.length > 0
        ? average(observedGroups.map((metrics) => metrics.f1))
        : 0,
    observedWeightedF1:
      observedWeight > 0
        ? observedGroups.reduce(
            (total, metrics) =>
              total +
              metrics.f1 *
                (metrics.categorySupport + metrics.falsePositive),
            0,
          ) / observedWeight
        : 0,
    observedGroupCount: observedGroups.length,
    observedWeight,
    predictionOnlyGroupCount,
  };
}

export function applyGroupedF1(
  overall: EvalMetrics,
  byGroup: Readonly<Record<string, EvalMetrics>>,
): EvalMetrics {
  const summary = computeGroupedMetricSummary(byGroup);
  return {
    ...overall,
    macroF1: summary.supportedMacroF1,
    weightedF1: summary.supportedWeightedF1,
    groupMetricsDefined: summary.supportedGroupCount > 0,
    macroF1IncludingSpurious: summary.observedMacroF1,
    weightedF1IncludingSpurious: summary.observedWeightedF1,
    predictionOnlyGroupCount: summary.predictionOnlyGroupCount,
    categorySupport: summary.truthSupport,
    supportedCategoryCount: summary.supportedGroupCount,
  };
}

export function applyMacroAndWeightedF1(
  overall: EvalMetrics,
  byCategory: Record<EvalFindingCategory, EvalMetrics>,
): EvalMetrics {
  return applyGroupedF1(overall, byCategory);
}

function metricsForGroup(counts: GroupCounts): EvalMetrics {
  const support = counts.truePositive + counts.falseNegative;
  return computeMetricsFromCounts(
    counts,
    support,
    counts.truePositive + counts.falsePositive,
    {
      categorySupport: support,
      supportedCategoryCount: support > 0 ? 1 : 0,
      cleanCaseCount: counts.cleanCaseCount,
      cleanTrueNegativeCases:
        counts.cleanCaseCount - counts.cleanFalsePositiveCases,
      cleanFalsePositiveCases: counts.cleanFalsePositiveCases,
    },
  );
}

function collectVulnerabilityClasses(
  results: readonly MatchResult[],
): string[] {
  const classes = new Set<string>();
  for (const result of results) {
    for (const match of result.matches) {
      if (match.expectedVulnerabilityClass) {
        classes.add(match.expectedVulnerabilityClass);
      }
      if (match.actualVulnerabilityClass) {
        classes.add(match.actualVulnerabilityClass);
      }
    }
    for (const finding of [
      ...result.falseNegatives,
      ...result.falsePositives,
    ]) {
      classes.add(
        inferPrimaryVulnerabilityClass(finding) ??
          UNCLASSIFIED_VULNERABILITY_CLASS,
      );
    }
  }
  return [...classes].sort();
}

function ensureGroup(
  counts: Map<string, GroupCounts>,
  key: string,
): GroupCounts {
  const existing = counts.get(key);
  if (existing) {
    return existing;
  }
  const created = emptyGroupCounts();
  counts.set(key, created);
  return created;
}

function emptyGroupCounts(): GroupCounts {
  return {
    truePositive: 0,
    falsePositive: 0,
    falseNegative: 0,
    trueNegative: 0,
    cleanCaseCount: 0,
    cleanFalsePositiveCases: 0,
  };
}

function isCleanResult(result: MatchResult): boolean {
  return result.matches.length + result.falseNegatives.length === 0;
}

function asResults(
  input: MatchResult | readonly MatchResult[],
): readonly MatchResult[] {
  return Array.isArray(input) ? input : [input];
}

function average(values: readonly number[]): number {
  return values.reduce((total, value) => total + value, 0) / values.length;
}
