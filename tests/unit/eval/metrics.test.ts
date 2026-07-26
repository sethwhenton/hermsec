import assert from "node:assert/strict";
import test from "node:test";
import {
  applyGroupedF1,
  applyMacroAndWeightedF1,
  computeCategoryMetrics,
  computeExecutionCompleteness,
  computeGroupedMetricSummary,
  computeMetrics,
  computeSelectiveMetrics,
  computeSuiteMetrics,
  computeVulnerabilityClassMetrics,
  matchFindings,
  UNCLASSIFIED_VULNERABILITY_CLASS,
  wilsonInterval,
  type ActualFindingProjection,
  type GroundTruthFinding,
} from "../../../src/eval/index.js";

test("an empty clean case uses specificity and does not invent precision or recall", () => {
  const result = matchFindings([], []);
  const metrics = applyGroupedF1(
    computeMetrics(result),
    computeVulnerabilityClassMetrics(result),
  );

  assert.equal(metrics.precision, 0);
  assert.equal(metrics.precisionDefined, false);
  assert.equal(metrics.recall, 0);
  assert.equal(metrics.recallDefined, false);
  assert.equal(metrics.f1Defined, false);
  assert.equal(metrics.cleanCaseCount, 1);
  assert.equal(metrics.cleanSpecificity, 1);
  assert.equal(metrics.cleanSpecificityDefined, true);
  assert.equal(metrics.falsePositiveRate, 0);
  assert.equal(metrics.groupMetricsDefined, false);
});

test("an empty-truth case with findings is a clean-case failure", () => {
  const metrics = computeMetrics(matchFindings([], [makeActual("FP", 10)]), {
    sourceLines: 200,
  });

  assert.equal(metrics.falsePositive, 1);
  assert.equal(metrics.precisionDefined, true);
  assert.equal(metrics.precision, 0);
  assert.equal(metrics.recallDefined, false);
  assert.equal(metrics.cleanSpecificity, 0);
  assert.equal(metrics.falsePositiveRate, 1);
  assert.equal(metrics.falseFindingsPerKloc, 5);
});

test("a positive case with no predictions reports zero recall without perfect precision", () => {
  const metrics = computeMetrics(matchFindings([makeTruth("GT", 10)], []));

  assert.equal(metrics.precision, 0);
  assert.equal(metrics.precisionDefined, false);
  assert.equal(metrics.recall, 0);
  assert.equal(metrics.recallDefined, true);
  assert.equal(metrics.f1, 0);
  assert.equal(metrics.f1Defined, false);
});

test("suite metrics keep finding false positives separate from clean-case specificity", () => {
  const positive = matchFindings(
    [makeTruth("GT", 10)],
    [makeActual("TP", 10), makeActual("FP-POSITIVE", 80)],
  );
  const cleanPass = matchFindings([], []);
  const cleanFail = matchFindings([], [makeActual("FP-CLEAN", 90)]);
  const metrics = computeSuiteMetrics([positive, cleanPass, cleanFail], {
    sourceLines: 1_000,
  });

  assert.equal(metrics.truePositive, 1);
  assert.equal(metrics.falsePositive, 2);
  assert.equal(metrics.cleanCaseCount, 2);
  assert.equal(metrics.cleanTrueNegativeCases, 1);
  assert.equal(metrics.cleanFalsePositiveCases, 1);
  assert.equal(metrics.cleanSpecificity, 0.5);
  assert.equal(metrics.falseFindingsPerKloc, 2);
});

test("macro and weighted F1 exclude categories with no expected support", () => {
  const result = matchFindings(
    [makeTruth("GT", 10)],
    [makeActual("TP", 10)],
  );
  const overall = computeMetrics(result);
  const byCategory = computeCategoryMetrics(result);
  const combined = applyMacroAndWeightedF1(overall, byCategory);

  assert.equal(byCategory.code.categorySupport, 1);
  assert.equal(byCategory.dependency.categorySupport, 0);
  assert.equal(combined.macroF1, 1);
  assert.equal(combined.weightedF1, 1);
  assert.equal(combined.supportedCategoryCount, 1);
});

test("vulnerability-class metrics retain supported and prediction-only classes", () => {
  const result = matchFindings(
    [makeTruth("GT", 10)],
    [makeActual("TP", 10), makeActual("FP-CMD", 90)],
  );
  const byClass = computeVulnerabilityClassMetrics(result);

  assert.equal(byClass["sql-injection"]?.categorySupport, 1);
  assert.equal(byClass["sql-injection"]?.truePositive, 1);
  assert.equal(byClass["command-injection"]?.categorySupport, 0);
  assert.equal(byClass["command-injection"]?.falsePositive, 1);
});

test("macro and weighted F1 are computed from supported classes rather than copied from micro F1", () => {
  const expected = [
    makeTruth("GT-SQL-1", 10),
    makeTruth("GT-SQL-2", 20),
    {
      ...makeTruth("GT-CMD", 30),
      vulnerabilityClass: "command-injection",
      title: "Command injection",
      cwe: ["CWE-78"],
      ruleIds: ["test.command-injection"],
    },
  ];
  const result = matchFindings(expected, [
    makeActual("ACTUAL-SQL-1", 10),
    makeActual("ACTUAL-SQL-2", 20),
  ]);
  const overall = computeMetrics(result);
  const byClass = computeVulnerabilityClassMetrics(result);
  const grouped = applyGroupedF1(overall, byClass);

  assert.equal(grouped.f1, 0.8);
  assert.equal(grouped.macroF1, 0.5);
  assert.equal(grouped.weightedF1, 2 / 3);
  assert.notEqual(grouped.macroF1, grouped.f1);
  assert.notEqual(grouped.weightedF1, grouped.f1);
  assert.equal(grouped.groupMetricsDefined, true);
});

test("prediction-only classes are reported in a separate spurious-inclusive macro", () => {
  const result = matchFindings(
    [makeTruth("GT", 10)],
    [makeActual("TP", 10), makeActual("FP-CMD", 90)],
  );
  const byClass = computeVulnerabilityClassMetrics(result);
  const summary = computeGroupedMetricSummary(byClass);
  const grouped = applyGroupedF1(computeMetrics(result), byClass);

  assert.equal(summary.supportedMacroF1, 1);
  assert.equal(summary.observedMacroF1, 0.5);
  assert.equal(summary.predictionOnlyGroupCount, 1);
  assert.equal(grouped.macroF1, 1);
  assert.equal(grouped.macroF1IncludingSpurious, 0.5);
  assert.equal(grouped.predictionOnlyGroupCount, 1);
});

test("prediction-only categories lower the spurious-inclusive category macro", () => {
  const result = matchFindings(
    [makeTruth("GT", 10)],
    [
      makeActual("TP", 10),
      {
        ...makeActual("FP-CONFIG", 90),
        category: "config",
        vulnerabilityClass: "insecure-configuration",
        title: "Insecure configuration",
        cwe: [],
        ruleIds: ["test.insecure-config"],
      },
    ],
  );
  const byCategory = computeCategoryMetrics(result);
  const summary = computeGroupedMetricSummary(byCategory);

  assert.equal(byCategory.config.categorySupport, 0);
  assert.equal(byCategory.config.falsePositive, 1);
  assert.equal(summary.supportedMacroF1, 1);
  assert.equal(summary.observedMacroF1, 0.5);
  assert.equal(summary.predictionOnlyGroupCount, 1);
});

test("unclassifiable false predictions remain visible in class macro reporting", () => {
  const unclassified: ActualFindingProjection = {
    ...makeActual("UNKNOWN", 90),
    fingerprint: "unclassified-fingerprint",
    title: "Unexpected analyzer output",
    cwe: [],
    ruleIds: [],
  };
  delete unclassified.vulnerabilityClass;
  const result = matchFindings(
    [makeTruth("GT", 10)],
    [makeActual("TP", 10), unclassified],
  );
  const byClass = computeVulnerabilityClassMetrics(result);
  const summary = computeGroupedMetricSummary(byClass);

  assert.equal(
    byClass[UNCLASSIFIED_VULNERABILITY_CLASS]?.falsePositive,
    1,
  );
  assert.equal(summary.supportedMacroF1, 1);
  assert.equal(summary.observedMacroF1, 0.5);
});

test("Wilson intervals are bounded and include the observed proportion", () => {
  const interval = wilsonInterval(8, 10);

  assert.ok(interval.lower > 0);
  assert.ok(interval.upper < 1);
  assert.ok(interval.lower < 0.8);
  assert.ok(interval.upper > 0.8);
  assert.equal(interval.confidence, 0.95);
});

test("selective metrics expose abstention, selective precision, and coverage", () => {
  const metrics = computeSelectiveMetrics({
    totalExpected: 10,
    acceptedTruePositive: 6,
    acceptedFalsePositive: 2,
    needsReviewTruePositive: 2,
    needsReviewFalsePositive: 1,
    rejectedTruePositive: 1,
    rejectedFalsePositive: 0,
  });

  assert.equal(metrics.totalPredictions, 12);
  assert.equal(metrics.abstainedPredictions, 3);
  assert.equal(metrics.abstentionRate, 0.25);
  assert.equal(metrics.selectivePrecision, 0.75);
  assert.equal(metrics.acceptedCoverage, 0.6);
  assert.equal(metrics.needsReviewRecall, 0.2);
  assert.throws(
    () =>
      computeSelectiveMetrics({
        totalExpected: 1,
        acceptedTruePositive: 1,
        acceptedFalsePositive: 0,
        needsReviewTruePositive: 1,
        needsReviewFalsePositive: 0,
      }),
    /cannot exceed totalExpected/,
  );
});

test("execution completeness reports partial and degraded runs explicitly", () => {
  const partial = computeExecutionCompleteness({
    plannedComponents: ["profile", "scanner", "agent"],
    completedComponents: ["profile", "scanner"],
    skippedComponents: ["agent"],
    eligibleFiles: 10,
    inspectedFiles: 8,
    inspectedBytes: 4_096,
  });
  const degraded = computeExecutionCompleteness({
    plannedComponents: ["profile", "scanner"],
    completedComponents: ["profile"],
    failedComponents: ["scanner"],
    unsupportedLanguages: ["cobol"],
    degradedReasons: ["scanner unavailable"],
  });

  assert.equal(partial.status, "partial");
  assert.equal(partial.componentCompletionRate, 2 / 3);
  assert.equal(partial.fileCoverage, 0.8);
  assert.equal(degraded.status, "degraded");
  assert.deepEqual(degraded.failedComponents, ["scanner"]);
  assert.deepEqual(degraded.unsupportedLanguages, ["cobol"]);
});

function makeTruth(id: string, line: number): GroundTruthFinding {
  return {
    id,
    category: "code",
    vulnerabilityClass: "sql-injection",
    title: "SQL injection",
    severity: "high",
    cwe: ["CWE-89"],
    identifiers: { cve: [], ghsa: [], osv: [] },
    location: { path: "src/app.js", startLine: line },
    ruleIds: ["test.sql-injection"],
  };
}

function makeActual(id: string, line: number): ActualFindingProjection {
  return {
    id,
    fingerprint: `fingerprint-${id}`,
    category: "code",
    vulnerabilityClass:
      id.startsWith("FP") && line >= 80
        ? "command-injection"
        : "sql-injection",
    title:
      id.startsWith("FP") && line >= 80
        ? "Command injection"
        : "SQL injection",
    severity: "high",
    cwe:
      id.startsWith("FP") && line >= 80 ? ["CWE-78"] : ["CWE-89"],
    identifiers: { cve: [], ghsa: [], osv: [] },
    ruleIds:
      id.startsWith("FP") && line >= 80
        ? ["test.command-injection"]
        : ["test.sql-injection"],
    location: { path: "src/app.js", startLine: line },
  };
}
