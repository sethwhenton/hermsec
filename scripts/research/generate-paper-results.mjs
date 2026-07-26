import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const MODES = Object.freeze([
  "scanner-only",
  "single-agent",
  "moa-low",
  "moa-high",
  "scanner-single",
  "scanner-moa-low",
  "scanner-moa-high",
]);

const MODE_DETAILS = Object.freeze({
  "scanner-only": Object.freeze({
    label: "Scanner only",
    macro: "ScannerOnly",
  }),
  "single-agent": Object.freeze({
    label: "Single agent",
    macro: "SingleAgent",
  }),
  "moa-low": Object.freeze({
    label: "MoA Low",
    macro: "MoaLow",
  }),
  "moa-high": Object.freeze({
    label: "MoA High",
    macro: "MoaHigh",
  }),
  "scanner-single": Object.freeze({
    label: "Scanner + Single",
    macro: "ScannerSingle",
  }),
  "scanner-moa-low": Object.freeze({
    label: "Scanner + MoA Low",
    macro: "ScannerMoaLow",
  }),
  "scanner-moa-high": Object.freeze({
    label: "Scanner + MoA High",
    macro: "ScannerMoaHigh",
  }),
});

const PHYSICAL_MODES = new Set([
  "scanner-only",
  "single-agent",
  "moa-low",
  "moa-high",
]);

const CELL_STATUSES = Object.freeze([
  "success",
  "partial",
  "degraded",
  "canceled",
  "failed",
]);

const SUMMARY_OUTPUT_FILES = Object.freeze([
  "completeness.csv",
  "cost-table.tex",
  "cost.csv",
  "metrics-table.tex",
  "metrics.csv",
  "metrics.md",
  "summary.json",
]);

const INTEGRITY_RECEIPT_FILE = "integrity-receipt.json";
const SOURCE_FILES = Object.freeze(
  [...SUMMARY_OUTPUT_FILES, INTEGRITY_RECEIPT_FILE].sort(compareText),
);

const OUTPUT_FILES = Object.freeze([
  "generated/results-macros.tex",
  "generated/results-provenance.json",
]);

const INPUT_CONTRACT_SCHEMA_VERSION = "2.0";
const PROVENANCE_SCHEMA_VERSION = "2.0";
const RECEIPT_SCHEMA_VERSION = "1.0";
const SUITE_INDEX_SCHEMA_VERSION = 3;
const SOURCE_INDEX_ENVELOPE_SCHEMA_VERSION = "1.0";
const STRUCTURAL_SOURCE_STATE_SCHEMA_VERSION = "2.0";
const FIXTURE_PROJECT_ROOT = "project";
const MAX_SOURCE_FILE_BYTES = 16 * 1024 * 1024;
const MAX_SOURCE_BUNDLE_BYTES = 48 * 1024 * 1024;
const RECEIPT_INTEGRITY_NOTICE = Object.freeze({
  kind: "sha256-tamper-evident",
  authenticated: false,
  notice:
    "Hashes detect accidental changes and unsophisticated tampering only. They are not signed or authenticated; a writer with artifact access can recompute them.",
});
const EXPORT_INTEGRITY_NOTICE = Object.freeze({
  kind: "sha256-tamper-evident",
  authenticated: false,
  notice:
    "The source summary is byte-bound to a validated v3 suite and independently re-derived by the deterministic summarizer, but the hashes are not digitally signed.",
});

const SECRET_PATTERNS = Object.freeze([
  /\bsk-or-v1-[A-Za-z0-9_-]{20,}\b/gu,
  /\bsk-ant-[A-Za-z0-9_-]{16,}\b/gu,
  /\bsk-[A-Za-z0-9_-]{20,}\b/gu,
  /\bAIza[0-9A-Za-z_-]{35}\b/gu,
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/gu,
  /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/gu,
  /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql):\/\/[^:\s/@]+:[^@\s/]+@[^\s"'<>]+/giu,
  /\bgh[pousr]_[A-Za-z0-9]{12,}\b/gu,
  /\bgithub_pat_[A-Za-z0-9_]{12,}\b/gu,
  /\bAKIA[0-9A-Z]{16}\b/gu,
  /\bnpm_[A-Za-z0-9]{20,}\b/gu,
  /\bpypi-AgEI[A-Za-z0-9_-]{20,}\b/gu,
  /\bhf_[A-Za-z0-9]{20,}\b/gu,
  /\bsk_live_[A-Za-z0-9]{16,}\b/gu,
  /\b\d{6,12}:[A-Za-z0-9_-]{24,}\b/gu,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/gu,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{16,}\b/giu,
  /\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|secret)\s*[:=]\s*["']?[A-Za-z0-9._~+/=-]{12,}/giu,
]);

class PaperExportError extends Error {}

if (
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  try {
    await main();
  } catch (error) {
    const message =
      error instanceof PaperExportError
        ? error.message
        : "Unable to generate paper result artifacts.";
    process.stderr.write(`${message}\n`);
    process.exitCode = 1;
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    printHelp();
    return;
  }
  if (!args.summary) {
    throw new PaperExportError("--summary is required.");
  }
  if (!args.suite) {
    throw new PaperExportError(
      "--suite is required and must name the original validated v3 suite.",
    );
  }
  if (!args.out) {
    throw new PaperExportError(
      "--out is required and must name a fresh directory.",
    );
  }

  const summaryDirectory = path.resolve(args.summary);
  const suiteDirectory = path.resolve(args.suite);
  const outputDirectory = path.resolve(args.out);
  const source = await readAndValidateSourceBundle(
    summaryDirectory,
    suiteDirectory,
  );
  await assertSeparateOutput(
    summaryDirectory,
    source.realDirectory,
    suiteDirectory,
    source.realSuiteDirectory,
    outputDirectory,
  );

  const macros = renderResultMacros(
    source.summary,
    source.verifiedEvidence,
  );
  const provenance = buildProvenance(source, macros);
  await writeFreshOutput(outputDirectory, macros, provenance);

  process.stdout.write(
    `${JSON.stringify({
      schemaVersion: PROVENANCE_SCHEMA_VERSION,
      inputContractSchemaVersion: INPUT_CONTRACT_SCHEMA_VERSION,
      suiteId: source.summary.suiteId,
      sourceBundleSha256: source.bundleSha256,
      upstreamBindingSha256: source.receipt.upstreamBindingSha256,
      files: [...OUTPUT_FILES],
    })}\n`,
  );
}

function parseArgs(values) {
  const parsed = { help: false };
  for (let index = 0; index < values.length; index += 1) {
    const value = values[index];
    if (value === "--help" || value === "-h") {
      parsed.help = true;
      continue;
    }
    if (
      value !== "--summary" &&
      value !== "--suite" &&
      value !== "--out"
    ) {
      throw new PaperExportError(`Unknown argument: ${value}`);
    }
    const next = values[index + 1];
    if (!next || next.startsWith("--")) {
      throw new PaperExportError(`${value} requires a value.`);
    }
    parsed[
      value === "--summary"
        ? "summary"
        : value === "--suite"
          ? "suite"
          : "out"
    ] = next;
    index += 1;
  }
  return parsed;
}

async function readAndValidateSourceBundle(
  summaryDirectory,
  suiteDirectory,
) {
  const [summarySource, suiteSource] = await Promise.all([
    readExactTextDirectory(
      summaryDirectory,
      SOURCE_FILES,
      "summary",
    ),
    resolveRealInputDirectory(suiteDirectory, "suite"),
  ]);
  const realDirectory = summarySource.realDirectory;
  const realSuiteDirectory = suiteSource.realDirectory;
  assertDistinctInputDirectories(realDirectory, realSuiteDirectory);

  let summary;
  let receiptDocument;
  try {
    summary = JSON.parse(summarySource.contents.get("summary.json"));
  } catch {
    throw new PaperExportError("summary.json is not valid JSON.");
  }
  try {
    receiptDocument = JSON.parse(
      summarySource.contents.get(INTEGRITY_RECEIPT_FILE),
    );
  } catch {
    throw new PaperExportError(
      "integrity-receipt.json is not valid JSON.",
    );
  }

  assertNoSensitiveStrings(summary, "summary.json");
  assertNoSensitiveStrings(
    receiptDocument,
    INTEGRITY_RECEIPT_FILE,
  );
  const validated = validateSummary(summary);
  const expected = renderSummaryBundle(summary);
  for (const fileName of SUMMARY_OUTPUT_FILES) {
    const actual = summarySource.contents.get(fileName);
    const expectedContent = expected.get(fileName);
    if (actual !== expectedContent) {
      throw new PaperExportError(
        `Summary artifact ${fileName} does not reconcile with summary.json.`,
      );
    }
  }

  const receipt = validateIntegrityReceipt(
    receiptDocument,
    validated,
    summarySource.contents,
  );
  const suiteBinding = await validateOriginalSuite(
    realSuiteDirectory,
    receipt,
    validated,
  );
  await verifyCanonicalSummaryDerivation(
    realSuiteDirectory,
    summarySource.contents,
  );

  const bundleSha256 = sha256(
    canonicalJson({
      schemaVersion: INPUT_CONTRACT_SCHEMA_VERSION,
      artifacts: summarySource.bindings,
      upstreamBindingSha256: receipt.upstreamBindingSha256,
    }),
  );
  return {
    realDirectory,
    realSuiteDirectory,
    summary,
    validated,
    receipt,
    verifiedEvidence: deriveVerifiedEvidence(receipt, validated),
    suiteBinding,
    bindings: summarySource.bindings,
    bundleSha256,
  };
}

export function validateSummary(summary) {
  const document = objectValue(summary, "summary.json");
  assertExactKeys(
    document,
    [
      "schemaVersion",
      "suiteId",
      "execution",
      "fixtureCount",
      "modeCount",
      "cellCount",
      "modeOrder",
      "totals",
      "modes",
    ],
    [],
    "summary.json",
  );
  expectEqual(document.schemaVersion, "1.0", "summary schemaVersion");
  const suiteId = safeText(
    requiredString(document.suiteId, "summary suiteId"),
    "summary suiteId",
  );
  const execution = oneOf(
    document.execution,
    ["mock", "replay", "live"],
    "summary execution",
  );
  const fixtureCount = positiveInteger(
    document.fixtureCount,
    "summary fixtureCount",
  );
  expectEqual(document.modeCount, MODES.length, "summary modeCount");
  const cellCount = positiveInteger(
    document.cellCount,
    "summary cellCount",
  );
  expectEqual(
    cellCount,
    fixtureCount * MODES.length,
    "summary cellCount",
  );
  expectArrayEqual(
    arrayValue(document.modeOrder, "summary modeOrder"),
    [...MODES],
    "summary modeOrder",
  );

  const totals = validateTotals(document.totals, cellCount);
  const modes = arrayValue(document.modes, "summary modes");
  if (modes.length !== MODES.length) {
    throw new PaperExportError(
      "summary modes must contain the complete seven-mode matrix.",
    );
  }

  const validatedModes = modes.map((mode, index) =>
    validateMode(mode, MODES[index], fixtureCount),
  );
  const truthCounts = new Set(
    validatedModes.map((mode) => mode.metrics.totalExpected),
  );
  if (truthCounts.size !== 1) {
    throw new PaperExportError(
      "Per-mode truth counts do not reconcile across the seven-mode matrix.",
    );
  }
  const truthCount = validatedModes[0].metrics.totalExpected;
  validateAggregateTotals(totals, validatedModes, cellCount);

  return {
    suiteId,
    execution,
    fixtureCount,
    truthCount,
    cellCount,
    totals,
    modes: validatedModes,
  };
}

function validateTotals(value, cellCount) {
  const totals = objectValue(value, "summary totals");
  assertExactKeys(
    totals,
    [
      "actualPhysicalSpendUsd",
      "conservativeCommittedUsd",
      "attributedCostUsd",
      "physicalTokens",
      "attributedTokens",
      "physicalModelCalls",
      "attributedModelCalls",
      "degradedCaseCount",
      "degradationReasonCount",
      "statusCounts",
    ],
    [],
    "summary totals",
  );
  const output = {
    actualPhysicalSpendUsd: nonNegativeNumber(
      totals.actualPhysicalSpendUsd,
      "summary actual physical spend",
    ),
    conservativeCommittedUsd: nonNegativeNumber(
      totals.conservativeCommittedUsd,
      "summary conservative committed spend",
    ),
    attributedCostUsd: nonNegativeNumber(
      totals.attributedCostUsd,
      "summary attributed cost",
    ),
    physicalTokens: nonNegativeInteger(
      totals.physicalTokens,
      "summary physical tokens",
    ),
    attributedTokens: nonNegativeInteger(
      totals.attributedTokens,
      "summary attributed tokens",
    ),
    physicalModelCalls: nonNegativeInteger(
      totals.physicalModelCalls,
      "summary physical model calls",
    ),
    attributedModelCalls: nonNegativeInteger(
      totals.attributedModelCalls,
      "summary attributed model calls",
    ),
    degradedCaseCount: nonNegativeInteger(
      totals.degradedCaseCount,
      "summary degraded case count",
    ),
    degradationReasonCount: nonNegativeInteger(
      totals.degradationReasonCount,
      "summary degradation reason count",
    ),
    statusCounts: validateStatusCounts(
      totals.statusCounts,
      cellCount,
      "summary status counts",
    ),
  };
  if (
    output.conservativeCommittedUsd + 1e-12 <
    output.actualPhysicalSpendUsd
  ) {
    throw new PaperExportError(
      "Conservative committed spend cannot be below physical spend.",
    );
  }
  return output;
}

function validateMode(value, expectedMode, fixtureCount) {
  const mode = objectValue(value, `${expectedMode} mode`);
  assertExactKeys(
    mode,
    [
      "mode",
      "label",
      "metrics",
      "classMetrics",
      "completeness",
      "statusCounts",
      "degradation",
      "evidenceCaveat",
      "cost",
    ],
    [],
    `${expectedMode} mode`,
  );
  expectEqual(mode.mode, expectedMode, `${expectedMode} mode id`);
  expectEqual(
    mode.label,
    MODE_DETAILS[expectedMode].label,
    `${expectedMode} label`,
  );
  const metrics = validateMetrics(mode.metrics, `${expectedMode} metrics`);
  const classMetrics = arrayValue(
    mode.classMetrics,
    `${expectedMode} classMetrics`,
  ).map((entry, index) =>
    validateClassMetrics(
      entry,
      `${expectedMode} classMetrics ${index}`,
    ),
  );
  const classNames = classMetrics.map(
    (entry) => entry.vulnerabilityClass,
  );
  if (new Set(classNames).size !== classNames.length) {
    throw new PaperExportError(
      `${expectedMode} classMetrics contains duplicate classes.`,
    );
  }
  expectArrayEqual(
    classNames,
    [...classNames].sort(compareText),
    `${expectedMode} classMetrics order`,
  );
  if (classMetrics.length > 0) {
    for (const field of [
      "truePositive",
      "falsePositive",
      "falseNegative",
      "totalExpected",
      "totalActual",
    ]) {
      expectEqual(
        classMetrics.reduce((total, entry) => total + entry[field], 0),
        metrics[field],
        `${expectedMode} class ${field}`,
      );
    }
  } else if (
    metrics.totalExpected !== 0 ||
    metrics.totalActual !== 0
  ) {
    throw new PaperExportError(
      `${expectedMode} omits class metrics for non-empty findings.`,
    );
  }
  const supportedClasses = classMetrics.filter(
    (entry) => entry.categorySupport > 0,
  );
  const recomputedClassMacroF1 =
    supportedClasses.length === 0
      ? 0
      : supportedClasses.reduce(
          (total, entry) => total + entry.f1,
          0,
        ) / supportedClasses.length;
  const classSupport = supportedClasses.reduce(
    (total, entry) => total + entry.categorySupport,
    0,
  );
  const recomputedClassWeightedF1 =
    classSupport === 0
      ? 0
      : supportedClasses.reduce(
          (total, entry) =>
            total + entry.f1 * entry.categorySupport,
          0,
        ) / classSupport;
  nearlyEqual(
    metrics.classMacroF1,
    recomputedClassMacroF1,
    `${expectedMode} recomputed class macro F1`,
  );
  nearlyEqual(
    metrics.classWeightedF1,
    recomputedClassWeightedF1,
    `${expectedMode} recomputed class weighted F1`,
  );

  const completeness = validateCompleteness(
    mode.completeness,
    `${expectedMode} completeness`,
  );
  const statusCounts = validateStatusCounts(
    mode.statusCounts,
    fixtureCount,
    `${expectedMode} status counts`,
  );
  const degradation = objectValue(
    mode.degradation,
    `${expectedMode} degradation`,
  );
  assertExactKeys(
    degradation,
    ["affectedCaseCount", "reasonCount"],
    [],
    `${expectedMode} degradation`,
  );
  const affectedCaseCount = nonNegativeInteger(
    degradation.affectedCaseCount,
    `${expectedMode} affected case count`,
  );
  if (affectedCaseCount > fixtureCount) {
    throw new PaperExportError(
      `${expectedMode} affected case count exceeds fixture count.`,
    );
  }
  const reasonCount = nonNegativeInteger(
    degradation.reasonCount,
    `${expectedMode} degradation reason count`,
  );
  expectEqual(
    reasonCount,
    completeness.degradedReasonCount,
    `${expectedMode} degradation reason binding`,
  );
  const evidenceCaveat = safeText(
    requiredString(
      mode.evidenceCaveat,
      `${expectedMode} evidence caveat`,
    ),
    `${expectedMode} evidence caveat`,
  );
  const cost = validateCost(mode.cost, expectedMode, fixtureCount);
  const comparison = evaluateModeEligibility(
    {
      completeness,
      statusCounts,
      degradation: {
        affectedCaseCount,
        reasonCount,
      },
    },
    fixtureCount,
  );
  return {
    mode: expectedMode,
    label: MODE_DETAILS[expectedMode].label,
    metrics,
    classMetrics,
    completeness,
    statusCounts,
    degradation: {
      affectedCaseCount,
      reasonCount,
    },
    evidenceCaveat,
    cost,
    comparison,
  };
}

export function evaluateModeEligibility(mode, fixtureCount) {
  const reasons = [];
  if (mode.statusCounts.success !== fixtureCount) {
    reasons.push("not-all-cells-successful");
  }
  for (const status of CELL_STATUSES.filter(
    (candidate) => candidate !== "success",
  )) {
    if (mode.statusCounts[status] !== 0) {
      reasons.push(`status-${status}`);
    }
  }
  if (mode.completeness.status !== "complete") {
    reasons.push(`completeness-${mode.completeness.status}`);
  }
  if (
    mode.completeness.completedComponentCount !==
      mode.completeness.plannedComponentCount ||
    mode.completeness.failedComponentCount !== 0 ||
    mode.completeness.skippedComponentCount !== 0 ||
    mode.completeness.componentCompletionRate !== 1
  ) {
    reasons.push("component-matrix-incomplete");
  }
  if (
    mode.completeness.fileCoverage !== null &&
    mode.completeness.fileCoverage !== 1
  ) {
    reasons.push("file-coverage-incomplete");
  }
  if (mode.completeness.unsupportedLanguageCount !== 0) {
    reasons.push("unsupported-language-coverage");
  }
  if (
    mode.degradation.affectedCaseCount !== 0 ||
    mode.degradation.reasonCount !== 0 ||
    mode.completeness.degradedReasonCount !== 0
  ) {
    reasons.push("degraded-evidence");
  }
  return Object.freeze({
    eligible: reasons.length === 0,
    reasons: Object.freeze([...new Set(reasons)]),
  });
}

function validateMetrics(value, label) {
  const metrics = objectValue(value, label);
  assertExactKeys(
    metrics,
    [
      "totalExpected",
      "totalActual",
      "precision",
      "recall",
      "f1",
      "truePositive",
      "falsePositive",
      "falseNegative",
      "classMacroF1",
      "classWeightedF1",
    ],
    [],
    label,
  );
  const output = {
    totalExpected: nonNegativeInteger(
      metrics.totalExpected,
      `${label} totalExpected`,
    ),
    totalActual: nonNegativeInteger(
      metrics.totalActual,
      `${label} totalActual`,
    ),
    precision: probability(metrics.precision, `${label} precision`),
    recall: probability(metrics.recall, `${label} recall`),
    f1: probability(metrics.f1, `${label} F1`),
    truePositive: nonNegativeInteger(
      metrics.truePositive,
      `${label} truePositive`,
    ),
    falsePositive: nonNegativeInteger(
      metrics.falsePositive,
      `${label} falsePositive`,
    ),
    falseNegative: nonNegativeInteger(
      metrics.falseNegative,
      `${label} falseNegative`,
    ),
    classMacroF1: probability(
      metrics.classMacroF1,
      `${label} classMacroF1`,
    ),
    classWeightedF1: probability(
      metrics.classWeightedF1,
      `${label} classWeightedF1`,
    ),
  };
  validateMetricArithmetic(output, label);
  return output;
}

function validateClassMetrics(value, label) {
  const metrics = objectValue(value, label);
  assertExactKeys(
    metrics,
    [
      "vulnerabilityClass",
      "totalExpected",
      "totalActual",
      "precision",
      "recall",
      "f1",
      "truePositive",
      "falsePositive",
      "falseNegative",
      "categorySupport",
    ],
    [],
    label,
  );
  const output = {
    vulnerabilityClass: safeText(
      requiredString(
        metrics.vulnerabilityClass,
        `${label} vulnerabilityClass`,
      ),
      `${label} vulnerabilityClass`,
    ),
    totalExpected: nonNegativeInteger(
      metrics.totalExpected,
      `${label} totalExpected`,
    ),
    totalActual: nonNegativeInteger(
      metrics.totalActual,
      `${label} totalActual`,
    ),
    precision: probability(metrics.precision, `${label} precision`),
    recall: probability(metrics.recall, `${label} recall`),
    f1: probability(metrics.f1, `${label} F1`),
    truePositive: nonNegativeInteger(
      metrics.truePositive,
      `${label} truePositive`,
    ),
    falsePositive: nonNegativeInteger(
      metrics.falsePositive,
      `${label} falsePositive`,
    ),
    falseNegative: nonNegativeInteger(
      metrics.falseNegative,
      `${label} falseNegative`,
    ),
    categorySupport: nonNegativeInteger(
      metrics.categorySupport,
      `${label} categorySupport`,
    ),
  };
  validateMetricArithmetic(output, label);
  expectEqual(
    output.categorySupport,
    output.totalExpected,
    `${label} categorySupport`,
  );
  return output;
}

function validateMetricArithmetic(metrics, label) {
  expectEqual(
    metrics.totalExpected,
    metrics.truePositive + metrics.falseNegative,
    `${label} expected count`,
  );
  expectEqual(
    metrics.totalActual,
    metrics.truePositive + metrics.falsePositive,
    `${label} actual count`,
  );
  const precision =
    metrics.truePositive + metrics.falsePositive === 0
      ? 0
      : metrics.truePositive /
        (metrics.truePositive + metrics.falsePositive);
  const recall =
    metrics.truePositive + metrics.falseNegative === 0
      ? 0
      : metrics.truePositive /
        (metrics.truePositive + metrics.falseNegative);
  const f1 =
    precision + recall === 0
      ? 0
      : (2 * precision * recall) / (precision + recall);
  nearlyEqual(metrics.precision, precision, `${label} precision`);
  nearlyEqual(metrics.recall, recall, `${label} recall`);
  nearlyEqual(metrics.f1, f1, `${label} F1`);
}

function validateCompleteness(value, label) {
  const completeness = objectValue(value, label);
  assertExactKeys(
    completeness,
    [
      "status",
      "plannedComponentCount",
      "completedComponentCount",
      "failedComponents",
      "failedComponentCount",
      "skippedComponents",
      "skippedComponentCount",
      "componentCompletionRate",
      "eligibleFiles",
      "inspectedFiles",
      "fileCoverage",
      "inspectedBytes",
      "unsupportedLanguages",
      "unsupportedLanguageCount",
      "degradedReasons",
      "degradedReasonCount",
    ],
    [],
    label,
  );
  const plannedComponentCount = nonNegativeInteger(
    completeness.plannedComponentCount,
    `${label} plannedComponentCount`,
  );
  const completedComponentCount = nonNegativeInteger(
    completeness.completedComponentCount,
    `${label} completedComponentCount`,
  );
  const failedComponents = safeStringArray(
    completeness.failedComponents,
    `${label} failedComponents`,
  );
  const skippedComponents = safeStringArray(
    completeness.skippedComponents,
    `${label} skippedComponents`,
  );
  const unsupportedLanguages = safeStringArray(
    completeness.unsupportedLanguages,
    `${label} unsupportedLanguages`,
  );
  const degradedReasons = safeStringArray(
    completeness.degradedReasons,
    `${label} degradedReasons`,
  );
  const failedComponentCount = nonNegativeInteger(
    completeness.failedComponentCount,
    `${label} failedComponentCount`,
  );
  const skippedComponentCount = nonNegativeInteger(
    completeness.skippedComponentCount,
    `${label} skippedComponentCount`,
  );
  const unsupportedLanguageCount = nonNegativeInteger(
    completeness.unsupportedLanguageCount,
    `${label} unsupportedLanguageCount`,
  );
  const degradedReasonCount = nonNegativeInteger(
    completeness.degradedReasonCount,
    `${label} degradedReasonCount`,
  );
  expectEqual(
    failedComponentCount,
    failedComponents.length,
    `${label} failed component binding`,
  );
  expectEqual(
    skippedComponentCount,
    skippedComponents.length,
    `${label} skipped component binding`,
  );
  expectEqual(
    unsupportedLanguageCount,
    unsupportedLanguages.length,
    `${label} unsupported language binding`,
  );
  expectEqual(
    degradedReasonCount,
    degradedReasons.length,
    `${label} degraded reason binding`,
  );
  expectEqual(
    plannedComponentCount,
    completedComponentCount +
      failedComponentCount +
      skippedComponentCount,
    `${label} component count`,
  );
  const componentCompletionRate = probability(
    completeness.componentCompletionRate,
    `${label} componentCompletionRate`,
  );
  nearlyEqual(
    componentCompletionRate,
    plannedComponentCount === 0
      ? 1
      : completedComponentCount / plannedComponentCount,
    `${label} component completion rate`,
  );

  const eligibleFiles = nullableNonNegativeInteger(
    completeness.eligibleFiles,
    `${label} eligibleFiles`,
  );
  const inspectedFiles = nullableNonNegativeInteger(
    completeness.inspectedFiles,
    `${label} inspectedFiles`,
  );
  const fileCoverage = nullableProbability(
    completeness.fileCoverage,
    `${label} fileCoverage`,
  );
  if (
    (eligibleFiles === null) !== (inspectedFiles === null) ||
    (eligibleFiles === null) !== (fileCoverage === null)
  ) {
    throw new PaperExportError(
      `${label} file coverage fields must be present or absent together.`,
    );
  }
  if (eligibleFiles !== null) {
    if (inspectedFiles > eligibleFiles) {
      throw new PaperExportError(
        `${label} inspectedFiles exceeds eligibleFiles.`,
      );
    }
    nearlyEqual(
      fileCoverage,
      eligibleFiles === 0 ? 1 : inspectedFiles / eligibleFiles,
      `${label} fileCoverage`,
    );
  }

  return {
    status: oneOf(
      completeness.status,
      ["complete", "partial", "degraded"],
      `${label} status`,
    ),
    plannedComponentCount,
    completedComponentCount,
    failedComponents,
    failedComponentCount,
    skippedComponents,
    skippedComponentCount,
    componentCompletionRate,
    eligibleFiles,
    inspectedFiles,
    fileCoverage,
    inspectedBytes: nonNegativeInteger(
      completeness.inspectedBytes,
      `${label} inspectedBytes`,
    ),
    unsupportedLanguages,
    unsupportedLanguageCount,
    degradedReasons,
    degradedReasonCount,
  };
}

function validateStatusCounts(value, expectedTotal, label) {
  const counts = objectValue(value, label);
  assertExactKeys(counts, CELL_STATUSES, [], label);
  const output = Object.fromEntries(
    CELL_STATUSES.map((status) => [
      status,
      nonNegativeInteger(counts[status], `${label} ${status}`),
    ]),
  );
  expectEqual(
    CELL_STATUSES.reduce((total, status) => total + output[status], 0),
    expectedTotal,
    `${label} total`,
  );
  return output;
}

function validateCost(value, mode, fixtureCount) {
  const cost = objectValue(value, `${mode} cost`);
  assertExactKeys(
    cost,
    [
      "actualPhysicalSpendUsd",
      "conservativeCommittedUsd",
      "attributedCostUsd",
      "physicalModelCalls",
      "attributedModelCalls",
      "physicalTokens",
      "attributedTokens",
      "physicalCellCount",
      "derivedCellCount",
    ],
    [],
    `${mode} cost`,
  );
  const output = {
    actualPhysicalSpendUsd: nonNegativeNumber(
      cost.actualPhysicalSpendUsd,
      `${mode} actualPhysicalSpendUsd`,
    ),
    conservativeCommittedUsd: nonNegativeNumber(
      cost.conservativeCommittedUsd,
      `${mode} conservativeCommittedUsd`,
    ),
    attributedCostUsd: nonNegativeNumber(
      cost.attributedCostUsd,
      `${mode} attributedCostUsd`,
    ),
    physicalModelCalls: nonNegativeInteger(
      cost.physicalModelCalls,
      `${mode} physicalModelCalls`,
    ),
    attributedModelCalls: nonNegativeInteger(
      cost.attributedModelCalls,
      `${mode} attributedModelCalls`,
    ),
    physicalTokens: nonNegativeInteger(
      cost.physicalTokens,
      `${mode} physicalTokens`,
    ),
    attributedTokens: nonNegativeInteger(
      cost.attributedTokens,
      `${mode} attributedTokens`,
    ),
    physicalCellCount: nonNegativeInteger(
      cost.physicalCellCount,
      `${mode} physicalCellCount`,
    ),
    derivedCellCount: nonNegativeInteger(
      cost.derivedCellCount,
      `${mode} derivedCellCount`,
    ),
  };
  expectEqual(
    output.physicalCellCount + output.derivedCellCount,
    fixtureCount,
    `${mode} physical/derived cell count`,
  );
  if (PHYSICAL_MODES.has(mode)) {
    expectEqual(
      output.physicalCellCount,
      fixtureCount,
      `${mode} physical cell count`,
    );
  } else {
    expectEqual(output.physicalCellCount, 0, `${mode} physical cell count`);
    nearlyEqual(
      output.actualPhysicalSpendUsd,
      0,
      `${mode} physical spend`,
    );
    expectEqual(output.physicalTokens, 0, `${mode} physical tokens`);
    expectEqual(
      output.physicalModelCalls,
      0,
      `${mode} physical model calls`,
    );
  }
  if (
    output.conservativeCommittedUsd + 1e-12 <
    output.actualPhysicalSpendUsd
  ) {
    throw new PaperExportError(
      `${mode} conservative committed spend is below physical spend.`,
    );
  }
  return output;
}

function validateAggregateTotals(totals, modes, cellCount) {
  const aggregate = {
    actualPhysicalSpendUsd: 0,
    conservativeCommittedUsd: 0,
    attributedCostUsd: 0,
    physicalTokens: 0,
    attributedTokens: 0,
    physicalModelCalls: 0,
    attributedModelCalls: 0,
    degradedCaseCount: 0,
    degradationReasonCount: 0,
    statusCounts: Object.fromEntries(
      CELL_STATUSES.map((status) => [status, 0]),
    ),
  };
  for (const mode of modes) {
    for (const field of [
      "actualPhysicalSpendUsd",
      "conservativeCommittedUsd",
      "attributedCostUsd",
      "physicalTokens",
      "attributedTokens",
      "physicalModelCalls",
      "attributedModelCalls",
    ]) {
      aggregate[field] += mode.cost[field];
    }
    aggregate.degradedCaseCount += mode.degradation.affectedCaseCount;
    aggregate.degradationReasonCount += mode.degradation.reasonCount;
    for (const status of CELL_STATUSES) {
      aggregate.statusCounts[status] += mode.statusCounts[status];
    }
  }
  for (const field of [
    "actualPhysicalSpendUsd",
    "conservativeCommittedUsd",
    "attributedCostUsd",
  ]) {
    nearlyEqual(totals[field], aggregate[field], `summary total ${field}`);
  }
  for (const field of [
    "physicalTokens",
    "attributedTokens",
    "physicalModelCalls",
    "attributedModelCalls",
    "degradedCaseCount",
    "degradationReasonCount",
  ]) {
    expectEqual(totals[field], aggregate[field], `summary total ${field}`);
  }
  expectEqual(
    CELL_STATUSES.reduce(
      (total, status) => total + aggregate.statusCounts[status],
      0,
    ),
    cellCount,
    "aggregate status cell count",
  );
  for (const status of CELL_STATUSES) {
    expectEqual(
      totals.statusCounts[status],
      aggregate.statusCounts[status],
      `summary status total ${status}`,
    );
  }
}

function validateIntegrityReceipt(value, summary, contents) {
  const receipt = objectValue(value, INTEGRITY_RECEIPT_FILE);
  assertExactKeys(
    receipt,
    [
      "schemaVersion",
      "suiteId",
      "integrity",
      "generator",
      "upstream",
      "upstreamBindingSha256",
      "outputBindings",
      "outputSetSha256",
      "derivationBindingSha256",
      "downstreamEvidence",
      "verification",
      "receiptSha256",
    ],
    [],
    INTEGRITY_RECEIPT_FILE,
  );
  expectEqual(
    receipt.schemaVersion,
    RECEIPT_SCHEMA_VERSION,
    "integrity receipt schemaVersion",
  );
  expectEqual(receipt.suiteId, summary.suiteId, "receipt suiteId");
  assertIntegrityNotice(receipt.integrity, "receipt integrity");
  const generator = validateDigestBinding(
    receipt.generator,
    "receipt generator",
    ["scripts/research/summarize-seven-mode.mjs"],
  );
  const upstream = validateReceiptUpstream(receipt.upstream);
  const upstreamBindingSha256 = expectDigest(
    receipt.upstreamBindingSha256,
    "receipt upstreamBindingSha256",
  );
  expectEqual(
    upstreamBindingSha256,
    sha256(canonicalJson(upstream)),
    "receipt upstream binding digest",
  );

  const outputBindings = arrayValue(
    receipt.outputBindings,
    "receipt outputBindings",
  ).map((entry, index) =>
    validateDigestBinding(
      entry,
      `receipt output binding ${index}`,
      SUMMARY_OUTPUT_FILES,
    ),
  );
  assertUniqueSortedBindings(
    outputBindings,
    SUMMARY_OUTPUT_FILES,
    "receipt output bindings",
  );
  const actualOutputBindings = SUMMARY_OUTPUT_FILES.map((fileName) => {
    const content = Buffer.from(contents.get(fileName), "utf8");
    return {
      path: fileName,
      bytes: content.byteLength,
      sha256: sha256(content),
    };
  }).sort((left, right) => compareText(left.path, right.path));
  canonicalEqual(
    outputBindings,
    actualOutputBindings,
    "receipt summary output bindings",
  );
  const outputSetSha256 = expectDigest(
    receipt.outputSetSha256,
    "receipt outputSetSha256",
  );
  expectEqual(
    outputSetSha256,
    sha256(canonicalJson(outputBindings)),
    "receipt output set digest",
  );
  const derivationBindingSha256 = expectDigest(
    receipt.derivationBindingSha256,
    "receipt derivationBindingSha256",
  );
  expectEqual(
    derivationBindingSha256,
    sha256(
      canonicalJson({
        generatorSha256: generator.sha256,
        suiteIndexSha256: upstream.suiteIndex.sha256,
        upstreamBindingSha256,
        outputSetSha256,
      }),
    ),
    "receipt derivation binding digest",
  );
  const downstreamEvidence = validateReceiptDownstreamEvidence(
    receipt.downstreamEvidence,
    upstream,
    summary,
  );
  const verification = objectValue(
    receipt.verification,
    "receipt verification",
  );
  assertExactKeys(
    verification,
    ["requiresDeterministicRerun", "instructions"],
    [],
    "receipt verification",
  );
  expectEqual(
    verification.requiresDeterministicRerun,
    true,
    "receipt deterministic rerun requirement",
  );
  safeText(
    requiredString(
      verification.instructions,
      "receipt verification instructions",
    ),
    "receipt verification instructions",
  );
  const receiptSha256 = expectDigest(
    receipt.receiptSha256,
    "receipt receiptSha256",
  );
  const { receiptSha256: _digest, ...unsigned } = receipt;
  expectEqual(
    receiptSha256,
    sha256(canonicalJson(unsigned)),
    "receipt self digest",
  );
  return {
    schemaVersion: RECEIPT_SCHEMA_VERSION,
    suiteId: summary.suiteId,
    generator,
    upstream,
    upstreamBindingSha256,
    outputBindings,
    outputSetSha256,
    derivationBindingSha256,
    downstreamEvidence,
    receiptSha256,
  };
}

function validateReceiptUpstream(value) {
  const upstream = objectValue(value, "receipt upstream");
  assertExactKeys(
    upstream,
    [
      "suiteIndex",
      "suiteArtifacts",
      "runManifests",
      "runManifestSetSha256",
      "sourceTruth",
      "sourceTruthSetSha256",
    ],
    [],
    "receipt upstream",
  );
  const suiteIndex = objectValue(
    upstream.suiteIndex,
    "receipt suite index",
  );
  assertExactKeys(
    suiteIndex,
    ["path", "bytes", "sha256", "indexSha256"],
    [],
    "receipt suite index",
  );
  expectEqual(
    suiteIndex.path,
    "suite-index.json",
    "receipt suite index path",
  );
  const validatedSuiteIndex = {
    path: "suite-index.json",
    bytes: nonNegativeInteger(
      suiteIndex.bytes,
      "receipt suite index bytes",
    ),
    sha256: expectDigest(
      suiteIndex.sha256,
      "receipt suite index sha256",
    ),
    indexSha256: expectDigest(
      suiteIndex.indexSha256,
      "receipt suite index indexSha256",
    ),
  };
  const suiteArtifacts = arrayValue(
    upstream.suiteArtifacts,
    "receipt suite artifacts",
  ).map((entry, index) =>
    validateDigestBinding(
      entry,
      `receipt suite artifact ${index}`,
    ),
  );
  assertUniqueSortedBindings(
    suiteArtifacts,
    undefined,
    "receipt suite artifacts",
  );
  const runManifests = arrayValue(
    upstream.runManifests,
    "receipt run manifests",
  ).map((candidate, index) => {
    const entry = objectValue(
      candidate,
      `receipt run manifest ${index}`,
    );
    assertExactKeys(
      entry,
      [
        "runId",
        "fixtureId",
        "mode",
        "path",
        "bytes",
        "sha256",
        "manifestSha256",
        "durationMs",
      ],
      [],
      `receipt run manifest ${index}`,
    );
    return {
      runId: safeText(
        requiredString(
          entry.runId,
          `receipt run manifest ${index} runId`,
        ),
        `receipt run manifest ${index} runId`,
      ),
      fixtureId: safeText(
        requiredString(
          entry.fixtureId,
          `receipt run manifest ${index} fixtureId`,
        ),
        `receipt run manifest ${index} fixtureId`,
      ),
      mode: oneOf(
        entry.mode,
        MODES,
        `receipt run manifest ${index} mode`,
      ),
      path: safeRelativeArtifactPath(
        entry.path,
        `receipt run manifest ${index} path`,
      ),
      bytes: nonNegativeInteger(
        entry.bytes,
        `receipt run manifest ${index} bytes`,
      ),
      sha256: expectDigest(
        entry.sha256,
        `receipt run manifest ${index} sha256`,
      ),
      manifestSha256: expectDigest(
        entry.manifestSha256,
        `receipt run manifest ${index} manifestSha256`,
      ),
      durationMs: nonNegativeInteger(
        entry.durationMs,
        `receipt run manifest ${index} durationMs`,
      ),
    };
  });
  const expectedRunOrder = [...runManifests].sort(
    (left, right) =>
      compareText(left.mode, right.mode) ||
      compareText(left.fixtureId, right.fixtureId),
  );
  canonicalEqual(
    runManifests,
    expectedRunOrder,
    "receipt run manifest order",
  );
  assertUniqueValues(
    runManifests.map((entry) => entry.runId),
    "receipt run IDs",
  );
  assertUniqueValues(
    runManifests.map((entry) => entry.path),
    "receipt run manifest paths",
  );
  const runManifestSetSha256 = expectDigest(
    upstream.runManifestSetSha256,
    "receipt runManifestSetSha256",
  );
  expectEqual(
    runManifestSetSha256,
    sha256(canonicalJson(runManifests)),
    "receipt run manifest set digest",
  );

  const sourceTruth = arrayValue(
    upstream.sourceTruth,
    "receipt source/truth bindings",
  ).map((candidate, index) => {
    const entry = objectValue(
      candidate,
      `receipt source/truth binding ${index}`,
    );
    assertExactKeys(
      entry,
      [
        "fixtureId",
        "path",
        "artifactSha256",
        "fixtureDigestSha256",
        "manifestSha256",
        "truthSha256",
        "sourceStateSha256",
        "projectDigestSha256",
        "evaluatorDigestSha256",
        "layoutBindingSha256",
        "subjectDigestSha256",
        "subjectFixtureBindingSha256",
      ],
      [],
      `receipt source/truth binding ${index}`,
    );
    return {
      fixtureId: safeText(
        requiredString(
          entry.fixtureId,
          `receipt source/truth binding ${index} fixtureId`,
        ),
        `receipt source/truth binding ${index} fixtureId`,
      ),
      path: safeRelativeArtifactPath(
        entry.path,
        `receipt source/truth binding ${index} path`,
      ),
      artifactSha256: expectDigest(
        entry.artifactSha256,
        `receipt source/truth binding ${index} artifactSha256`,
      ),
      fixtureDigestSha256: expectDigest(
        entry.fixtureDigestSha256,
        `receipt source/truth binding ${index} fixtureDigestSha256`,
      ),
      manifestSha256: expectDigest(
        entry.manifestSha256,
        `receipt source/truth binding ${index} manifestSha256`,
      ),
      truthSha256: expectDigest(
        entry.truthSha256,
        `receipt source/truth binding ${index} truthSha256`,
      ),
      sourceStateSha256: expectDigest(
        entry.sourceStateSha256,
        `receipt source/truth binding ${index} sourceStateSha256`,
      ),
      projectDigestSha256: expectDigest(
        entry.projectDigestSha256,
        `receipt source/truth binding ${index} projectDigestSha256`,
      ),
      evaluatorDigestSha256: expectDigest(
        entry.evaluatorDigestSha256,
        `receipt source/truth binding ${index} evaluatorDigestSha256`,
      ),
      layoutBindingSha256: expectDigest(
        entry.layoutBindingSha256,
        `receipt source/truth binding ${index} layoutBindingSha256`,
      ),
      subjectDigestSha256: expectDigest(
        entry.subjectDigestSha256,
        `receipt source/truth binding ${index} subjectDigestSha256`,
      ),
      subjectFixtureBindingSha256: expectDigest(
        entry.subjectFixtureBindingSha256,
        `receipt source/truth binding ${index} subjectFixtureBindingSha256`,
      ),
    };
  });
  canonicalEqual(
    sourceTruth,
    [...sourceTruth].sort((left, right) =>
      compareText(left.fixtureId, right.fixtureId),
    ),
    "receipt source/truth order",
  );
  assertUniqueValues(
    sourceTruth.map((entry) => entry.fixtureId),
    "receipt source/truth fixture IDs",
  );
  const sourceTruthSetSha256 = expectDigest(
    upstream.sourceTruthSetSha256,
    "receipt sourceTruthSetSha256",
  );
  expectEqual(
    sourceTruthSetSha256,
    sha256(canonicalJson(sourceTruth)),
    "receipt source/truth set digest",
  );
  return {
    suiteIndex: validatedSuiteIndex,
    suiteArtifacts,
    runManifests,
    runManifestSetSha256,
    sourceTruth,
    sourceTruthSetSha256,
  };
}

function validateReceiptDownstreamEvidence(value, upstream, summary) {
  const evidence = objectValue(value, "receipt downstream evidence");
  assertExactKeys(
    evidence,
    ["manifestRate", "runtime", "replayAgreement"],
    [],
    "receipt downstream evidence",
  );
  const manifestRate = objectValue(
    evidence.manifestRate,
    "receipt manifest rate",
  );
  assertExactKeys(
    manifestRate,
    [
      "status",
      "evidenceSha256",
      "verifiedManifestCount",
      "expectedManifestCount",
      "value",
    ],
    [],
    "receipt manifest rate",
  );
  expectEqual(
    manifestRate.status,
    "available",
    "receipt manifest rate status",
  );
  expectEqual(
    expectDigest(
      manifestRate.evidenceSha256,
      "receipt manifest rate evidenceSha256",
    ),
    upstream.runManifestSetSha256,
    "receipt manifest rate evidence binding",
  );
  const verifiedManifestCount = nonNegativeInteger(
    manifestRate.verifiedManifestCount,
    "receipt verified manifest count",
  );
  const expectedManifestCount = positiveInteger(
    manifestRate.expectedManifestCount,
    "receipt expected manifest count",
  );
  expectEqual(
    verifiedManifestCount,
    upstream.runManifests.length,
    "receipt verified manifest count",
  );
  expectEqual(
    expectedManifestCount,
    summary.cellCount,
    "receipt expected manifest count",
  );
  const manifestValue = probability(
    manifestRate.value,
    "receipt manifest rate value",
  );
  nearlyEqual(
    manifestValue,
    verifiedManifestCount / expectedManifestCount,
    "receipt manifest rate",
  );

  const runtime = objectValue(evidence.runtime, "receipt runtime");
  assertExactKeys(
    runtime,
    ["status", "evidenceSha256", "source", "byMode"],
    [],
    "receipt runtime",
  );
  expectEqual(runtime.status, "available", "receipt runtime status");
  expectEqual(
    expectDigest(
      runtime.evidenceSha256,
      "receipt runtime evidenceSha256",
    ),
    upstream.runManifestSetSha256,
    "receipt runtime evidence binding",
  );
  safeText(
    requiredString(runtime.source, "receipt runtime source"),
    "receipt runtime source",
  );
  const runtimeByMode = arrayValue(
    runtime.byMode,
    "receipt runtime byMode",
  ).map((candidate, index) => {
    const entry = objectValue(
      candidate,
      `receipt runtime mode ${index}`,
    );
    assertExactKeys(
      entry,
      [
        "mode",
        "runCount",
        "totalMilliseconds",
        "meanMilliseconds",
      ],
      [],
      `receipt runtime mode ${index}`,
    );
    return {
      mode: oneOf(
        entry.mode,
        MODES,
        `receipt runtime mode ${index} mode`,
      ),
      runCount: nonNegativeInteger(
        entry.runCount,
        `receipt runtime mode ${index} runCount`,
      ),
      totalMilliseconds: nonNegativeInteger(
        entry.totalMilliseconds,
        `receipt runtime mode ${index} totalMilliseconds`,
      ),
      meanMilliseconds:
        entry.meanMilliseconds === null
          ? null
          : nonNegativeNumber(
              entry.meanMilliseconds,
              `receipt runtime mode ${index} meanMilliseconds`,
            ),
    };
  });
  expectArrayEqual(
    runtimeByMode.map((entry) => entry.mode),
    [...MODES],
    "receipt runtime mode order",
  );
  for (const entry of runtimeByMode) {
    const durations = upstream.runManifests
      .filter((manifest) => manifest.mode === entry.mode)
      .map((manifest) => manifest.durationMs);
    const totalMilliseconds = durations.reduce(
      (total, duration) => total + duration,
      0,
    );
    expectEqual(entry.runCount, durations.length, `${entry.mode} run count`);
    expectEqual(
      entry.totalMilliseconds,
      totalMilliseconds,
      `${entry.mode} runtime total`,
    );
    if (durations.length === 0) {
      expectEqual(
        entry.meanMilliseconds,
        null,
        `${entry.mode} runtime mean`,
      );
    } else {
      nearlyEqual(
        entry.meanMilliseconds,
        totalMilliseconds / durations.length,
        `${entry.mode} runtime mean`,
      );
    }
  }

  const replayAgreement = objectValue(
    evidence.replayAgreement,
    "receipt replay agreement",
  );
  assertExactKeys(
    replayAgreement,
    ["status", "reason"],
    [],
    "receipt replay agreement",
  );
  expectEqual(
    replayAgreement.status,
    "unavailable",
    "receipt replay agreement status",
  );
  const replayReason = safeText(
    requiredString(
      replayAgreement.reason,
      "receipt replay agreement reason",
    ),
    "receipt replay agreement reason",
  );
  return {
    manifestRate: {
      status: "available",
      verifiedManifestCount,
      expectedManifestCount,
      value: manifestValue,
    },
    runtime: {
      status: "available",
      byMode: runtimeByMode,
    },
    replayAgreement: {
      status: "unavailable",
      reason: replayReason,
    },
  };
}

async function validateOriginalSuite(suiteDirectory, receipt, summary) {
  const summarizerPath = fileURLToPath(
    new URL("./summarize-seven-mode.mjs", import.meta.url),
  );
  const summarizerContent = await readBoundFile(
    summarizerPath,
    "deterministic summarizer",
  );
  expectEqual(
    summarizerContent.byteLength,
    receipt.generator.bytes,
    "receipt generator byte binding",
  );
  expectEqual(
    sha256(summarizerContent),
    receipt.generator.sha256,
    "receipt generator digest binding",
  );
  const validateSuiteIndex = await loadSuiteIndexValidator();
  let validation;
  try {
    validation = await validateSuiteIndex(suiteDirectory);
  } catch {
    throw new PaperExportError(
      "Unable to validate the original v3 suite integrity chain.",
    );
  }
  if (
    !validation?.valid ||
    !validation.index ||
    validation.index.schemaVersion !== SUITE_INDEX_SCHEMA_VERSION
  ) {
    throw new PaperExportError(
      "The original suite failed v3 index, artifact, run, or truth validation.",
    );
  }
  const index = objectValue(validation.index, "validated suite index");
  assertNoSensitiveStrings(index, "validated suite index");
  expectEqual(index.suiteId, summary.suiteId, "suite index suiteId");
  const indexPath = await resolveConfinedRegularFile(
    suiteDirectory,
    path.join(suiteDirectory, "suite-index.json"),
    "suite-index.json",
    "suite",
  );
  const indexContent = await readBoundFile(
    indexPath,
    "suite-index.json",
  );
  expectEqual(
    indexContent.byteLength,
    receipt.upstream.suiteIndex.bytes,
    "suite index receipt byte binding",
  );
  expectEqual(
    sha256(indexContent),
    receipt.upstream.suiteIndex.sha256,
    "suite index receipt digest binding",
  );
  expectEqual(
    index.indexSha256,
    receipt.upstream.suiteIndex.indexSha256,
    "suite index canonical digest binding",
  );
  const { indexSha256, ...unsignedIndex } = index;
  expectEqual(
    indexSha256,
    sha256(canonicalJson(unsignedIndex)),
    "suite index self digest",
  );

  const indexArtifacts = arrayValue(
    index.artifacts,
    "suite index artifacts",
  ).map((entry, entryIndex) =>
    validateDigestBinding(
      entry,
      `suite index artifact ${entryIndex}`,
    ),
  );
  assertUniqueSortedBindings(
    indexArtifacts,
    undefined,
    "suite index artifacts",
  );
  canonicalEqual(
    receipt.upstream.suiteArtifacts,
    indexArtifacts,
    "receipt suite artifact bindings",
  );

  const experimentSummary = await readWrappedSuiteArtifact(
    suiteDirectory,
    "experiment-summary.json",
  );
  const cells = arrayValue(
    objectValue(
      experimentSummary,
      "suite experiment summary",
    ).cells,
    "suite experiment cells",
  );
  const cellsByManifest = new Map();
  for (const [indexEntry, candidate] of cells.entries()) {
    const cell = objectValue(
      candidate,
      `suite experiment cell ${indexEntry}`,
    );
    const manifestPath = safeRelativeArtifactPath(
      cell.manifestPath,
      `suite experiment cell ${indexEntry} manifestPath`,
    );
    if (cellsByManifest.has(manifestPath)) {
      throw new PaperExportError(
        "The original suite repeats a run manifest binding.",
      );
    }
    cellsByManifest.set(manifestPath, {
      runId: safeText(
        requiredString(
          cell.runId,
          `suite experiment cell ${indexEntry} runId`,
        ),
        `suite experiment cell ${indexEntry} runId`,
      ),
      fixtureId: safeText(
        requiredString(
          cell.fixtureId,
          `suite experiment cell ${indexEntry} fixtureId`,
        ),
        `suite experiment cell ${indexEntry} fixtureId`,
      ),
      mode: oneOf(
        cell.mode,
        MODES,
        `suite experiment cell ${indexEntry} mode`,
      ),
    });
  }
  const runBindings = [];
  for (const [indexEntry, candidate] of arrayValue(
    index.runs,
    "suite index runs",
  ).entries()) {
    const run = objectValue(candidate, `suite index run ${indexEntry}`);
    const manifestPath = safeRelativeArtifactPath(
      run.path,
      `suite index run ${indexEntry} path`,
    );
    const cell = cellsByManifest.get(manifestPath);
    if (!cell) {
      throw new PaperExportError(
        "The original suite run index does not bind the experiment matrix.",
      );
    }
    expectEqual(run.runId, cell.runId, "suite run/cell runId");
    const absoluteManifestPath = await resolveConfinedRegularFile(
      suiteDirectory,
      path.join(suiteDirectory, ...manifestPath.split("/")),
      manifestPath,
      "suite",
    );
    const manifestContent = await readBoundFile(
      absoluteManifestPath,
      "suite run manifest",
    );
    const manifest = parseJsonBuffer(
      manifestContent,
      "suite run manifest",
    );
    assertNoSensitiveStrings(manifest, "suite run manifest");
    const manifestObject = objectValue(
      manifest,
      "suite run manifest",
    );
    expectEqual(
      manifestObject.schemaVersion,
      2,
      "suite run manifest schemaVersion",
    );
    expectEqual(
      manifestObject.runId,
      cell.runId,
      "suite run manifest runId",
    );
    expectEqual(
      manifestObject.suite,
      summary.suiteId,
      "suite run manifest suiteId",
    );
    expectEqual(
      manifestObject.mode,
      cell.mode,
      "suite run manifest mode",
    );
    const manifestSha256 = expectDigest(
      manifestObject.manifestSha256,
      "suite run manifest manifestSha256",
    );
    const {
      manifestSha256: _manifestDigest,
      ...unsignedManifest
    } = manifestObject;
    expectEqual(
      manifestSha256,
      sha256(canonicalJson(unsignedManifest)),
      "suite run manifest self digest",
    );
    expectEqual(
      manifestSha256,
      run.manifestSha256,
      "suite run index manifest digest",
    );
    const startedAt = validTimestamp(
      manifestObject.startedAt,
      "suite run manifest startedAt",
    );
    const finishedAt = validTimestamp(
      manifestObject.finishedAt,
      "suite run manifest finishedAt",
    );
    const durationMs = finishedAt - startedAt;
    if (!Number.isSafeInteger(durationMs) || durationMs < 0) {
      throw new PaperExportError(
        "Suite run manifest timestamps do not yield a valid duration.",
      );
    }
    runBindings.push({
      runId: cell.runId,
      fixtureId: cell.fixtureId,
      mode: cell.mode,
      path: manifestPath,
      bytes: manifestContent.byteLength,
      sha256: sha256(manifestContent),
      manifestSha256,
      durationMs,
    });
  }
  runBindings.sort(
    (left, right) =>
      compareText(left.mode, right.mode) ||
      compareText(left.fixtureId, right.fixtureId),
  );
  canonicalEqual(
    receipt.upstream.runManifests,
    runBindings,
    "receipt run manifest bindings",
  );

  const sourceIndex = objectValue(
    await readWrappedSuiteArtifact(
      suiteDirectory,
      "source-index.json",
    ),
    "suite source index",
  );
  assertExactKeys(
    sourceIndex,
    ["fixtures", "schemaVersion", "suiteId"],
    [],
    "suite source index",
  );
  expectEqual(
    sourceIndex.schemaVersion,
    SOURCE_INDEX_ENVELOPE_SCHEMA_VERSION,
    "suite source index schemaVersion",
  );
  expectEqual(
    sourceIndex.suiteId,
    summary.suiteId,
    "suite source index suiteId",
  );
  const sourceByFixture = new Map();
  for (const [indexEntry, candidate] of arrayValue(
    sourceIndex.fixtures,
    "suite source fixtures",
  ).entries()) {
    const entry = objectValue(
      candidate,
      `suite source fixture ${indexEntry}`,
    );
    const fixtureId = safeText(
      requiredString(
        entry.fixtureId,
        `suite source fixture ${indexEntry} fixtureId`,
      ),
      `suite source fixture ${indexEntry} fixtureId`,
    );
    if (sourceByFixture.has(fixtureId)) {
      throw new PaperExportError(
        "The suite source index repeats a fixture identity.",
      );
    }
    sourceByFixture.set(fixtureId, entry);
  }
  const fixtureTruth = arrayValue(
    index.fixtureTruth,
    "suite index fixtureTruth",
  );
  const sourceTruth = [];
  const boundFixtureIds = new Set();
  for (const [indexEntry, candidate] of fixtureTruth.entries()) {
    const binding = objectValue(
      candidate,
      `suite index fixtureTruth ${indexEntry}`,
    );
    assertExactKeys(
      binding,
      [
        "artifactSha256",
        "evaluatorDigestSha256",
        "fixtureDigestSha256",
        "fixtureId",
        "layoutBindingSha256",
        "pairId",
        "path",
        "projectDigestSha256",
        "projectRoot",
        "variant",
      ],
      [],
      `suite index fixtureTruth ${indexEntry}`,
    );
    const fixtureId = safeText(
      requiredString(
        binding.fixtureId,
        `suite index fixtureTruth ${indexEntry} fixtureId`,
      ),
      `suite index fixtureTruth ${indexEntry} fixtureId`,
    );
    if (boundFixtureIds.has(fixtureId)) {
      throw new PaperExportError(
        "The suite index repeats a structural fixture truth binding.",
      );
    }
    boundFixtureIds.add(fixtureId);
    const pairId = safeText(
      requiredString(
        binding.pairId,
        `suite index fixtureTruth ${indexEntry} pairId`,
      ),
      `suite index fixtureTruth ${indexEntry} pairId`,
    );
    const variant = oneOf(
      binding.variant,
      ["vulnerable", "clean"],
      `suite index fixtureTruth ${indexEntry} variant`,
    );
    expectEqual(
      binding.projectRoot,
      FIXTURE_PROJECT_ROOT,
      `suite index fixtureTruth ${indexEntry} projectRoot`,
    );
    const fixtureDigestSha256 = expectDigest(
      binding.fixtureDigestSha256,
      `suite index fixtureTruth ${indexEntry} fixtureDigestSha256`,
    );
    const projectDigestSha256 = expectDigest(
      binding.projectDigestSha256,
      `suite index fixtureTruth ${indexEntry} projectDigestSha256`,
    );
    const evaluatorDigestSha256 = expectDigest(
      binding.evaluatorDigestSha256,
      `suite index fixtureTruth ${indexEntry} evaluatorDigestSha256`,
    );
    const layoutBindingSha256 = expectDigest(
      binding.layoutBindingSha256,
      `suite index fixtureTruth ${indexEntry} layoutBindingSha256`,
    );
    const source = objectValue(
      sourceByFixture.get(fixtureId),
      `suite source fixture ${fixtureId}`,
    );
    assertExactKeys(
      source,
      [
        "evaluator",
        "files",
        "fixtureDigestSha256",
        "fixtureId",
        "language",
        "layoutBindingSha256",
        "pairId",
        "project",
        "schemaVersion",
        "subject",
        "truthArtifact",
        "variant",
      ],
      [],
      `suite source fixture ${fixtureId}`,
    );
    const truthArtifact = objectValue(
      source.truthArtifact,
      `suite source fixture ${fixtureId} truthArtifact`,
    );
    assertExactKeys(
      truthArtifact,
      [
        "evaluatorDigestSha256",
        "fixtureDigestSha256",
        "layoutBindingSha256",
        "path",
        "projectDigestSha256",
      ],
      [],
      `suite source fixture ${fixtureId} truthArtifact`,
    );
    const artifactPath = safeRelativeArtifactPath(
      binding.path,
      `suite index fixtureTruth ${indexEntry} path`,
    );
    expectEqual(
      truthArtifact.path,
      artifactPath,
      `suite source fixture ${fixtureId} truth path`,
    );
    expectEqual(
      truthArtifact.fixtureDigestSha256,
      fixtureDigestSha256,
      `suite source fixture ${fixtureId} truth digest`,
    );
    expectEqual(
      truthArtifact.projectDigestSha256,
      projectDigestSha256,
      `suite source fixture ${fixtureId} truth project digest`,
    );
    expectEqual(
      truthArtifact.evaluatorDigestSha256,
      evaluatorDigestSha256,
      `suite source fixture ${fixtureId} truth evaluator digest`,
    );
    expectEqual(
      truthArtifact.layoutBindingSha256,
      layoutBindingSha256,
      `suite source fixture ${fixtureId} truth layout binding`,
    );
    const artifact = indexArtifacts.find(
      (entry) => entry.path === artifactPath,
    );
    if (!artifact) {
      throw new PaperExportError(
        "Suite fixture/truth binding references an unindexed artifact.",
      );
    }
    expectEqual(
      binding.artifactSha256,
      artifact.sha256,
      "suite fixture/truth artifact digest",
    );
    const evidence = objectValue(
      await readWrappedSuiteArtifact(suiteDirectory, artifactPath),
      `suite truth fixture ${fixtureId}`,
    );
    expectEqual(
      evidence.fixtureId,
      fixtureId,
      `suite truth fixture ${fixtureId} identity`,
    );
    const manifest = objectValue(
      evidence.manifest,
      `suite truth fixture ${fixtureId} manifest`,
    );
    const truth = objectValue(
      evidence.truth,
      `suite truth fixture ${fixtureId} truth`,
    );
    const evidenceSourceState = objectValue(
      evidence.sourceState,
      `suite truth fixture ${fixtureId} sourceState`,
    );
    const {
      truthArtifact: _truthArtifact,
      ...sourceStateValue
    } = source;
    const normalizedSourceState = validateStructuralSourceState(
      sourceStateValue,
      fixtureId,
    );
    canonicalEqual(
      evidenceSourceState,
      normalizedSourceState,
      `suite truth fixture ${fixtureId} source-state binding`,
    );
    expectEqual(
      normalizedSourceState.pairId,
      pairId,
      `suite source fixture ${fixtureId} pairId binding`,
    );
    expectEqual(
      normalizedSourceState.variant,
      variant,
      `suite source fixture ${fixtureId} variant binding`,
    );
    expectEqual(
      normalizedSourceState.fixtureDigestSha256,
      fixtureDigestSha256,
      `suite source fixture ${fixtureId} fixture digest binding`,
    );
    expectEqual(
      normalizedSourceState.project.projectDigestSha256,
      projectDigestSha256,
      `suite source fixture ${fixtureId} project digest binding`,
    );
    expectEqual(
      normalizedSourceState.evaluator.evaluatorDigestSha256,
      evaluatorDigestSha256,
      `suite source fixture ${fixtureId} evaluator digest binding`,
    );
    expectEqual(
      normalizedSourceState.layoutBindingSha256,
      layoutBindingSha256,
      `suite source fixture ${fixtureId} layout binding`,
    );
    const subjectDigestSha256 =
      normalizedSourceState.subject.subjectDigestSha256;
    const subjectFixtureBindingSha256 =
      normalizedSourceState.subject.fixtureBindingSha256;
    expectEqual(
      subjectDigestSha256,
      projectDigestSha256,
      `suite source fixture ${fixtureId} subject/project digest alias`,
    );
    expectEqual(
      subjectFixtureBindingSha256,
      layoutBindingSha256,
      `suite source fixture ${fixtureId} subject/layout binding alias`,
    );
    const internalBinding = objectValue(
      evidence.binding,
      `suite truth fixture ${fixtureId} binding`,
    );
    assertExactKeys(
      internalBinding,
      [
        "evaluatorDigestSha256",
        "fixtureDigestSha256",
        "layoutBindingSha256",
        "manifestSha256",
        "projectDigestSha256",
        "projectRoot",
        "sourceStateSha256",
        "subjectDigestSha256",
        "subjectFixtureBindingSha256",
        "truthSha256",
      ],
      [],
      `suite truth fixture ${fixtureId} binding`,
    );
    const manifestSha256 = expectDigest(
      internalBinding.manifestSha256,
      `suite truth fixture ${fixtureId} manifestSha256`,
    );
    const truthSha256 = expectDigest(
      internalBinding.truthSha256,
      `suite truth fixture ${fixtureId} truthSha256`,
    );
    const sourceStateSha256 = expectDigest(
      internalBinding.sourceStateSha256,
      `suite truth fixture ${fixtureId} sourceStateSha256`,
    );
    expectEqual(
      manifestSha256,
      sha256(canonicalJson(manifest)),
      `suite truth fixture ${fixtureId} manifest digest`,
    );
    expectEqual(
      truthSha256,
      sha256(canonicalJson(truth)),
      `suite truth fixture ${fixtureId} truth digest`,
    );
    expectEqual(
      sourceStateSha256,
      sha256(canonicalJson(normalizedSourceState)),
      `suite truth fixture ${fixtureId} source-state digest`,
    );
    validateStructuralFixtureManifest(
      manifest,
      normalizedSourceState,
      fixtureId,
    );
    expectEqual(
      truth.fixtureId,
      fixtureId,
      `suite truth fixture ${fixtureId} truth identity`,
    );
    expectEqual(
      truth.schemaVersion,
      "2.0",
      `suite truth fixture ${fixtureId} truth schemaVersion`,
    );
    expectEqual(
      nonNegativeInteger(
        manifest.expectedFindingCount,
        `suite truth fixture ${fixtureId} expectedFindingCount`,
      ),
      arrayValue(
        truth.findings,
        `suite truth fixture ${fixtureId} truth findings`,
      ).length,
      `suite truth fixture ${fixtureId} truth finding count`,
    );
    expectEqual(
      evidence.pairId,
      pairId,
      `suite truth fixture ${fixtureId} pairId binding`,
    );
    expectEqual(
      evidence.variant,
      variant,
      `suite truth fixture ${fixtureId} variant binding`,
    );
    expectEqual(
      internalBinding.fixtureDigestSha256,
      fixtureDigestSha256,
      `suite truth fixture ${fixtureId} fixture digest`,
    );
    expectEqual(
      internalBinding.projectRoot,
      FIXTURE_PROJECT_ROOT,
      `suite truth fixture ${fixtureId} project root`,
    );
    expectEqual(
      internalBinding.projectDigestSha256,
      projectDigestSha256,
      `suite truth fixture ${fixtureId} project digest`,
    );
    expectEqual(
      internalBinding.evaluatorDigestSha256,
      evaluatorDigestSha256,
      `suite truth fixture ${fixtureId} evaluator digest`,
    );
    expectEqual(
      internalBinding.layoutBindingSha256,
      layoutBindingSha256,
      `suite truth fixture ${fixtureId} layout binding`,
    );
    expectEqual(
      internalBinding.subjectDigestSha256,
      subjectDigestSha256,
      `suite truth fixture ${fixtureId} subject digest`,
    );
    expectEqual(
      internalBinding.subjectFixtureBindingSha256,
      subjectFixtureBindingSha256,
      `suite truth fixture ${fixtureId} subject fixture binding`,
    );
    sourceTruth.push({
      fixtureId,
      path: artifactPath,
      artifactSha256: expectDigest(
        binding.artifactSha256,
        `suite truth fixture ${fixtureId} artifactSha256`,
      ),
      fixtureDigestSha256,
      manifestSha256,
      truthSha256,
      sourceStateSha256,
      projectDigestSha256,
      evaluatorDigestSha256,
      layoutBindingSha256,
      subjectDigestSha256,
      subjectFixtureBindingSha256,
    });
  }
  expectArrayEqual(
    [...sourceByFixture.keys()].sort(compareText),
    [...boundFixtureIds].sort(compareText),
    "suite source-index structural fixture coverage",
  );
  sourceTruth.sort((left, right) =>
    compareText(left.fixtureId, right.fixtureId),
  );
  canonicalEqual(
    receipt.upstream.sourceTruth,
    sourceTruth,
    "receipt source/truth bindings",
  );
  return {
    schemaVersion: SUITE_INDEX_SCHEMA_VERSION,
    indexSha256,
    indexFileSha256: sha256(indexContent),
  };
}

export function validateStructuralSourceState(value, fixtureId) {
  const label = `suite source fixture ${fixtureId}`;
  const state = objectValue(value, `${label} structural source state`);
  if (state.schemaVersion !== STRUCTURAL_SOURCE_STATE_SCHEMA_VERSION) {
    throw new PaperExportError(
      `${label} uses legacy structural source-state schema ${String(
        state.schemaVersion,
      )}; schema ${STRUCTURAL_SOURCE_STATE_SCHEMA_VERSION} is required.`,
    );
  }
  assertExactKeys(
    state,
    [
      "evaluator",
      "files",
      "fixtureDigestSha256",
      "fixtureId",
      "language",
      "layoutBindingSha256",
      "pairId",
      "project",
      "schemaVersion",
      "subject",
      "variant",
    ],
    [],
    `${label} structural source state`,
  );
  expectEqual(state.fixtureId, fixtureId, `${label} identity`);
  const pairId = safeText(
    requiredString(state.pairId, `${label} pairId`),
    `${label} pairId`,
  );
  const variant = oneOf(
    state.variant,
    ["vulnerable", "clean"],
    `${label} variant`,
  );
  const language = safeText(
    requiredString(state.language, `${label} language`),
    `${label} language`,
  );
  const fullFiles = readStructuralFileRecords(
    state.files,
    `${label} fixture files`,
    { forbiddenCaseFoldedPaths: [FIXTURE_PROJECT_ROOT] },
  );
  if (fullFiles.length === 0) {
    throw new PaperExportError(
      `${label} structural fixture inventory is empty.`,
    );
  }

  const project = objectValue(state.project, `${label} project`);
  assertExactKeys(
    project,
    ["files", "projectDigestSha256", "root"],
    [],
    `${label} project`,
  );
  expectEqual(
    project.root,
    FIXTURE_PROJECT_ROOT,
    `${label} project root`,
  );
  const projectFiles = readStructuralFileRecords(
    project.files,
    `${label} project files`,
  );
  if (projectFiles.length === 0) {
    throw new PaperExportError(
      `${label} structural project/ subtree is empty.`,
    );
  }

  const evaluator = objectValue(state.evaluator, `${label} evaluator`);
  assertExactKeys(
    evaluator,
    ["evaluatorDigestSha256", "files"],
    [],
    `${label} evaluator`,
  );
  const evaluatorFiles = readStructuralFileRecords(
    evaluator.files,
    `${label} evaluator files`,
  );
  const projectPrefix = `${FIXTURE_PROJECT_ROOT}/`;
  const expectedProjectFiles = fullFiles
    .filter((file) => file.path.startsWith(projectPrefix))
    .map((file) => ({
      ...file,
      path: file.path.slice(projectPrefix.length),
    }));
  const expectedEvaluatorFiles = fullFiles.filter(
    (file) => !file.path.startsWith(projectPrefix),
  );
  if (
    expectedEvaluatorFiles.some(
      (file) =>
        file.path.includes("/") ||
        file.path.toLowerCase() === FIXTURE_PROJECT_ROOT,
    )
  ) {
    throw new PaperExportError(
      `${label} contains an unclassified or misplaced path outside, or colliding with, the explicit project/ subtree.`,
    );
  }
  canonicalEqual(
    projectFiles,
    expectedProjectFiles,
    `${label} exact project-relative inventory`,
  );
  canonicalEqual(
    evaluatorFiles,
    expectedEvaluatorFiles,
    `${label} exact evaluator inventory`,
  );
  if (
    !evaluatorFiles.some((file) => file.path === "fixture.json") ||
    !evaluatorFiles.some((file) => file.path === "truth.json")
  ) {
    throw new PaperExportError(
      `${label} evaluator inventory must contain fixture.json and truth.json outside project/.`,
    );
  }

  const fixtureDigestSha256 = sha256(prettyCanonicalJson(fullFiles));
  const projectDigestSha256 = sha256(prettyCanonicalJson(projectFiles));
  const evaluatorDigestSha256 = sha256(
    prettyCanonicalJson(evaluatorFiles),
  );
  const layoutBindingSha256 = sha256(
    canonicalJson({
      projectRoot: FIXTURE_PROJECT_ROOT,
      fixtureDigestSha256,
      projectDigestSha256,
      evaluatorDigestSha256,
    }),
  );
  for (const [actual, expected, digestLabel] of [
    [
      expectDigest(
        state.fixtureDigestSha256,
        `${label} fixtureDigestSha256`,
      ),
      fixtureDigestSha256,
      `${label} recomputed fixture digest`,
    ],
    [
      expectDigest(
        project.projectDigestSha256,
        `${label} projectDigestSha256`,
      ),
      projectDigestSha256,
      `${label} recomputed project digest`,
    ],
    [
      expectDigest(
        evaluator.evaluatorDigestSha256,
        `${label} evaluatorDigestSha256`,
      ),
      evaluatorDigestSha256,
      `${label} recomputed evaluator digest`,
    ],
    [
      expectDigest(
        state.layoutBindingSha256,
        `${label} layoutBindingSha256`,
      ),
      layoutBindingSha256,
      `${label} recomputed structural layout binding`,
    ],
  ]) {
    expectEqual(actual, expected, digestLabel);
  }

  const subject = objectValue(
    state.subject,
    `${label} structural compatibility subject`,
  );
  assertExactKeys(
    subject,
    [
      "excludedControlFiles",
      "files",
      "fixtureBindingSha256",
      "subjectDigestSha256",
    ],
    [],
    `${label} structural compatibility subject`,
  );
  const subjectFiles = readStructuralFileRecords(
    subject.files,
    `${label} compatibility subject files`,
  );
  const excludedControlFiles = safeStringArray(
    subject.excludedControlFiles,
    `${label} compatibility excluded evaluator files`,
  ).map((entry, index) =>
    safeRelativeArtifactPath(
      entry,
      `${label} excluded evaluator file ${index}`,
    ),
  );
  canonicalEqual(
    subjectFiles,
    projectFiles,
    `${label} project/subject compatibility inventory`,
  );
  expectArrayEqual(
    excludedControlFiles,
    evaluatorFiles.map((file) => file.path),
    `${label} evaluator exclusion inventory`,
  );
  expectEqual(
    expectDigest(
      subject.subjectDigestSha256,
      `${label} subjectDigestSha256`,
    ),
    projectDigestSha256,
    `${label} project/subject digest binding`,
  );
  expectEqual(
    expectDigest(
      subject.fixtureBindingSha256,
      `${label} subject fixtureBindingSha256`,
    ),
    layoutBindingSha256,
    `${label} project/subject layout binding`,
  );

  const normalized = {
    schemaVersion: STRUCTURAL_SOURCE_STATE_SCHEMA_VERSION,
    fixtureId,
    pairId,
    variant,
    language,
    files: fullFiles,
    fixtureDigestSha256,
    project: {
      root: FIXTURE_PROJECT_ROOT,
      files: projectFiles,
      projectDigestSha256,
    },
    evaluator: {
      files: evaluatorFiles,
      evaluatorDigestSha256,
    },
    layoutBindingSha256,
    subject: {
      files: subjectFiles,
      subjectDigestSha256: projectDigestSha256,
      excludedControlFiles,
      fixtureBindingSha256: layoutBindingSha256,
    },
  };
  canonicalEqual(
    state,
    normalized,
    `${label} exact structural source-state schema`,
  );
  return normalized;
}

function readStructuralFileRecords(value, label, options = {}) {
  const records = arrayValue(value, label).map((candidate, index) => {
    const record = objectValue(candidate, `${label} ${index}`);
    assertExactKeys(
      record,
      ["bytes", "path", "sha256"],
      [],
      `${label} ${index}`,
    );
    const relativePath = safeRelativeArtifactPath(
      record.path,
      `${label} ${index} path`,
    );
    if (
      (options.forbiddenCaseFoldedPaths ?? []).some(
        (forbidden) =>
          relativePath.toLowerCase() === forbidden.toLowerCase(),
      )
    ) {
      throw new PaperExportError(
        `${label} contains a path colliding with the explicit ${FIXTURE_PROJECT_ROOT}/ subtree.`,
      );
    }
    return {
      path: relativePath,
      bytes: nonNegativeInteger(
        record.bytes,
        `${label} ${index} bytes`,
      ),
      sha256: expectDigest(record.sha256, `${label} ${index} sha256`),
    };
  });
  assertUniqueValues(
    records.map((record) => record.path),
    `${label} paths`,
  );
  const foldedPaths = records.map((record) =>
    record.path.toLowerCase(),
  );
  if (new Set(foldedPaths).size !== foldedPaths.length) {
    throw new PaperExportError(
      `${label} contains case-folded path aliases.`,
    );
  }
  canonicalEqual(
    records,
    [...records].sort((left, right) =>
      left.path.localeCompare(right.path),
    ),
    `${label} canonical ordering`,
  );
  canonicalEqual(value, records, `${label} exact record schema`);
  return records;
}

function validateStructuralFixtureManifest(manifest, sourceState, fixtureId) {
  const label = `suite truth fixture ${fixtureId} manifest`;
  assertExactKeys(
    manifest,
    [
      "entrypoints",
      "evaluatorFiles",
      "expectedFindingCount",
      "id",
      "language",
      "pairedFixtureId",
      "pairId",
      "projectRoot",
      "safety",
      "schemaVersion",
      "sourceFiles",
      "supportedVulnerabilityClasses",
      "variant",
    ],
    [],
    label,
  );
  expectEqual(manifest.schemaVersion, "2.0", `${label} schemaVersion`);
  expectEqual(manifest.id, fixtureId, `${label} identity`);
  expectEqual(manifest.pairId, sourceState.pairId, `${label} pairId`);
  expectEqual(manifest.variant, sourceState.variant, `${label} variant`);
  expectEqual(manifest.language, sourceState.language, `${label} language`);
  expectEqual(
    manifest.projectRoot,
    FIXTURE_PROJECT_ROOT,
    `${label} projectRoot`,
  );
  safeText(
    requiredString(manifest.pairedFixtureId, `${label} pairedFixtureId`),
    `${label} pairedFixtureId`,
  );

  const evaluatorFiles = safeStringArray(
    manifest.evaluatorFiles,
    `${label} evaluatorFiles`,
  ).map((entry, index) => {
    const relativePath = safeRelativeArtifactPath(
      entry,
      `${label} evaluatorFiles ${index}`,
    );
    if (relativePath.includes("/")) {
      throw new PaperExportError(
        `${label} evaluatorFiles must name root-level files outside project/.`,
      );
    }
    return relativePath;
  });
  if (
    evaluatorFiles.length === 0 ||
    !evaluatorFiles.includes("truth.json") ||
    evaluatorFiles.includes("fixture.json")
  ) {
    throw new PaperExportError(
      `${label} evaluatorFiles must include truth.json and omit fixture.json.`,
    );
  }
  assertCaseFoldedUnique(evaluatorFiles, `${label} evaluatorFiles`);
  expectArrayEqual(
    evaluatorFiles,
    [...evaluatorFiles].sort((left, right) =>
      left.localeCompare(right),
    ),
    `${label} evaluatorFiles order`,
  );
  expectArrayEqual(
    sourceState.evaluator.files.map((file) => file.path),
    ["fixture.json", ...evaluatorFiles].sort((left, right) =>
      left.localeCompare(right),
    ),
    `${label} declared evaluator inventory`,
  );

  const projectPaths = new Set(
    sourceState.project.files.map((file) => file.path),
  );
  for (const [field, values] of [
    ["sourceFiles", manifest.sourceFiles],
    ["entrypoints", manifest.entrypoints],
  ]) {
    const paths = safeStringArray(values, `${label} ${field}`).map(
      (entry, index) =>
        safeRelativeArtifactPath(
          entry,
          `${label} ${field} ${index}`,
        ),
    );
    if (paths.length === 0) {
      throw new PaperExportError(`${label} ${field} must not be empty.`);
    }
    assertCaseFoldedUnique(paths, `${label} ${field}`);
    expectArrayEqual(
      paths,
      [...paths].sort((left, right) => left.localeCompare(right)),
      `${label} ${field} order`,
    );
    for (const relativePath of paths) {
      if (!projectPaths.has(relativePath)) {
        throw new PaperExportError(
          `${label} ${field} references a file outside the bound project inventory.`,
        );
      }
    }
  }
}

function assertCaseFoldedUnique(values, label) {
  const folded = values.map((value) => value.toLowerCase());
  if (new Set(folded).size !== folded.length) {
    throw new PaperExportError(
      `${label} contains case-folded path aliases.`,
    );
  }
}

async function loadSuiteIndexValidator() {
  try {
    const module = await import(
      new URL("../../dist/src/research/runManifest.js", import.meta.url)
    );
    if (typeof module.validateSuiteIndex !== "function") {
      throw new Error("validator export missing");
    }
    return module.validateSuiteIndex;
  } catch {
    throw new PaperExportError(
      "The built v3 suite validator is unavailable. Run the root build before exporting paper results.",
    );
  }
}

async function verifyCanonicalSummaryDerivation(
  suiteDirectory,
  suppliedContents,
) {
  const temporaryDirectory = await fs.mkdtemp(
    path.join(os.tmpdir(), "hermsec-paper-export-verify-"),
  );
  const regeneratedDirectory = path.join(
    temporaryDirectory,
    "summary",
  );
  try {
    const summarizerPath = fileURLToPath(
      new URL("./summarize-seven-mode.mjs", import.meta.url),
    );
    const result = await runNodeScript(summarizerPath, [
      "--suite",
      suiteDirectory,
      "--out",
      regeneratedDirectory,
    ]);
    if (result.code !== 0) {
      throw new PaperExportError(
        "The original suite could not be re-derived by the deterministic summarizer.",
      );
    }
    const regenerated = await readExactTextDirectory(
      regeneratedDirectory,
      SOURCE_FILES,
      "regenerated summary",
    );
    for (const fileName of SOURCE_FILES) {
      if (
        regenerated.contents.get(fileName) !==
        suppliedContents.get(fileName)
      ) {
        throw new PaperExportError(
          `The supplied summary artifact ${fileName} does not match deterministic derivation from the original v3 suite.`,
        );
      }
    }
  } finally {
    await fs.rm(temporaryDirectory, {
      recursive: true,
      force: true,
    });
  }
}

function deriveVerifiedEvidence(receipt, summary) {
  const durations = receipt.upstream.runManifests
    .map((entry) => entry.durationMs)
    .sort((left, right) => left - right);
  const middle = Math.floor(durations.length / 2);
  const medianWallClockMs =
    durations.length === 0
      ? null
      : durations.length % 2 === 1
        ? durations[middle]
        : (durations[middle - 1] + durations[middle]) / 2;
  return Object.freeze({
    manifestValidation: Object.freeze({
      available: true,
      validated:
        receipt.downstreamEvidence.manifestRate
          .verifiedManifestCount,
      total:
        receipt.downstreamEvidence.manifestRate
          .expectedManifestCount,
      rate: receipt.downstreamEvidence.manifestRate.value,
    }),
    replayAgreement: Object.freeze({
      available: false,
      reason:
        receipt.downstreamEvidence.replayAgreement.reason,
    }),
    runtime: Object.freeze({
      available: medianWallClockMs !== null,
      medianWallClockMs,
      sampleCount: durations.length,
      source:
        "verified integrity receipt run-manifest durations",
    }),
    suiteId: summary.suiteId,
  });
}

function renderSummaryBundle(summary) {
  return new Map([
    ["summary.json", `${JSON.stringify(summary, null, 2)}\n`],
    ["metrics.csv", renderMetricsCsv(summary)],
    ["metrics.md", renderMetricsMarkdown(summary)],
    ["completeness.csv", renderCompletenessCsv(summary)],
    ["cost.csv", renderCostCsv(summary)],
    ["metrics-table.tex", renderMetricsLatex(summary)],
    ["cost-table.tex", renderCostLatex(summary)],
  ]);
}

function renderMetricsCsv(summary) {
  const rows = [
    [
      "mode",
      "scope",
      "vulnerability_class",
      "precision",
      "recall",
      "f1",
      "true_positive",
      "false_positive",
      "false_negative",
      "class_macro_f1",
      "class_weighted_f1",
      "evidence_caveat",
    ],
  ];
  for (const mode of summary.modes) {
    rows.push([
      mode.mode,
      "overall",
      "",
      numberText(mode.metrics.precision),
      numberText(mode.metrics.recall),
      numberText(mode.metrics.f1),
      mode.metrics.truePositive,
      mode.metrics.falsePositive,
      mode.metrics.falseNegative,
      numberText(mode.metrics.classMacroF1),
      numberText(mode.metrics.classWeightedF1),
      mode.evidenceCaveat,
    ]);
    for (const metric of mode.classMetrics) {
      rows.push([
        mode.mode,
        "class",
        metric.vulnerabilityClass,
        numberText(metric.precision),
        numberText(metric.recall),
        numberText(metric.f1),
        metric.truePositive,
        metric.falsePositive,
        metric.falseNegative,
        "",
        "",
        "",
      ]);
    }
  }
  return `${rows.map(csvRow).join("\n")}\n`;
}

function renderCompletenessCsv(summary) {
  const rows = [
    [
      "mode",
      "completeness_status",
      "planned_components",
      "completed_components",
      "failed_components",
      "skipped_components",
      "component_completion_rate",
      "eligible_files",
      "inspected_files",
      "file_coverage",
      "inspected_bytes",
      "unsupported_language_count",
      "degraded_case_count",
      "degradation_reason_count",
      "status_success",
      "status_partial",
      "status_degraded",
      "status_canceled",
      "status_failed",
    ],
  ];
  for (const mode of summary.modes) {
    const completeness = mode.completeness;
    rows.push([
      mode.mode,
      completeness.status,
      completeness.plannedComponentCount,
      completeness.completedComponentCount,
      completeness.failedComponentCount,
      completeness.skippedComponentCount,
      numberText(completeness.componentCompletionRate),
      nullableText(completeness.eligibleFiles),
      nullableText(completeness.inspectedFiles),
      nullableText(completeness.fileCoverage),
      completeness.inspectedBytes,
      completeness.unsupportedLanguageCount,
      mode.degradation.affectedCaseCount,
      mode.degradation.reasonCount,
      mode.statusCounts.success,
      mode.statusCounts.partial,
      mode.statusCounts.degraded,
      mode.statusCounts.canceled,
      mode.statusCounts.failed,
    ]);
  }
  return `${rows.map(csvRow).join("\n")}\n`;
}

function renderCostCsv(summary) {
  const rows = [
    [
      "mode",
      "physical_cost_usd",
      "conservative_committed_usd",
      "attributed_cost_usd",
      "physical_tokens",
      "attributed_tokens",
      "physical_model_calls",
      "attributed_model_calls",
      "physical_cells",
      "derived_cells",
    ],
  ];
  for (const mode of summary.modes) {
    rows.push([
      mode.mode,
      numberText(mode.cost.actualPhysicalSpendUsd),
      numberText(mode.cost.conservativeCommittedUsd),
      numberText(mode.cost.attributedCostUsd),
      mode.cost.physicalTokens,
      mode.cost.attributedTokens,
      mode.cost.physicalModelCalls,
      mode.cost.attributedModelCalls,
      mode.cost.physicalCellCount,
      mode.cost.derivedCellCount,
    ]);
  }
  return `${rows.map(csvRow).join("\n")}\n`;
}

function renderMetricsMarkdown(summary) {
  const lines = [
    "# Seven-mode experiment metrics",
    "",
    `Suite: \`${markdownInline(summary.suiteId)}\``,
    "",
    "> Counts and ratios are recomputed from per-case match evidence. Metrics remain visible for incomplete runs, but the evidence caveat must be considered before comparison.",
    "",
    "| Mode | Precision | Recall | F1 | TP | FP | FN | Class macro F1 | Class weighted F1 | Evidence caveat |",
    "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
  ];
  for (const mode of summary.modes) {
    lines.push(
      `| ${markdownCell(mode.label)} | ${displayRatio(mode.metrics.precision)} | ${displayRatio(mode.metrics.recall)} | ${displayRatio(mode.metrics.f1)} | ${mode.metrics.truePositive} | ${mode.metrics.falsePositive} | ${mode.metrics.falseNegative} | ${displayRatio(mode.metrics.classMacroF1)} | ${displayRatio(mode.metrics.classWeightedF1)} | ${markdownCell(mode.evidenceCaveat)} |`,
    );
  }
  lines.push(
    "",
    "## Per-class metrics",
    "",
    "| Mode | Vulnerability class | Precision | Recall | F1 | TP | FP | FN |",
    "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
  );
  for (const mode of summary.modes) {
    if (mode.classMetrics.length === 0) {
      lines.push(
        `| ${markdownCell(mode.label)} | None | - | - | - | 0 | 0 | 0 |`,
      );
      continue;
    }
    for (const metric of mode.classMetrics) {
      lines.push(
        `| ${markdownCell(mode.label)} | ${markdownCell(metric.vulnerabilityClass)} | ${displayRatio(metric.precision)} | ${displayRatio(metric.recall)} | ${displayRatio(metric.f1)} | ${metric.truePositive} | ${metric.falsePositive} | ${metric.falseNegative} |`,
      );
    }
  }
  lines.push("");
  return `${lines.join("\n")}\n`;
}

function renderMetricsLatex(summary) {
  const lines = [
    "% Generated deterministically by Hermsec. Values are proportions.",
    "% Counts and ratios are recomputed from immutable per-case match evidence.",
    "% Evidence caveats identify partial, degraded, canceled, or failed cells.",
    "\\begin{tabular}{lrrrrrrrrl}",
    "\\hline",
    "Mode & Precision & Recall & F1 & TP & FP & FN & Macro F1 & Weighted F1 & Evidence caveat \\\\",
    "\\hline",
  ];
  for (const mode of summary.modes) {
    lines.push(
      `${latexEscape(mode.label)} & ${displayRatio(mode.metrics.precision)} & ${displayRatio(mode.metrics.recall)} & ${displayRatio(mode.metrics.f1)} & ${mode.metrics.truePositive} & ${mode.metrics.falsePositive} & ${mode.metrics.falseNegative} & ${displayRatio(mode.metrics.classMacroF1)} & ${displayRatio(mode.metrics.classWeightedF1)} & ${latexEscape(mode.evidenceCaveat)} \\\\`,
    );
  }
  lines.push(
    "\\hline",
    "\\end{tabular}",
    "",
    "% Per-class metrics",
    "\\begin{tabular}{llrrrrrr}",
    "\\hline",
    "Mode & Class & Precision & Recall & F1 & TP & FP & FN \\\\",
    "\\hline",
  );
  for (const mode of summary.modes) {
    for (const metric of mode.classMetrics) {
      lines.push(
        `${latexEscape(mode.label)} & ${latexEscape(metric.vulnerabilityClass)} & ${displayRatio(metric.precision)} & ${displayRatio(metric.recall)} & ${displayRatio(metric.f1)} & ${metric.truePositive} & ${metric.falsePositive} & ${metric.falseNegative} \\\\`,
      );
    }
  }
  lines.push("\\hline", "\\end{tabular}", "");
  return `${lines.join("\n")}\n`;
}

function renderCostLatex(summary) {
  const lines = [
    "% Generated deterministically by Hermsec.",
    "\\begin{tabular}{lrrrrrr}",
    "\\hline",
    "Mode & Physical USD & Attributed USD & Physical tokens & Attributed tokens & Physical calls & Attributed calls \\\\",
    "\\hline",
  ];
  for (const mode of summary.modes) {
    lines.push(
      `${latexEscape(mode.label)} & ${costText(mode.cost.actualPhysicalSpendUsd)} & ${costText(mode.cost.attributedCostUsd)} & ${mode.cost.physicalTokens} & ${mode.cost.attributedTokens} & ${mode.cost.physicalModelCalls} & ${mode.cost.attributedModelCalls} \\\\`,
    );
  }
  lines.push("\\hline", "\\end{tabular}", "");
  return `${lines.join("\n")}\n`;
}

export function renderResultMacros(
  sourceSummary,
  verifiedEvidence = Object.freeze({
    manifestValidation: Object.freeze({ available: false }),
    replayAgreement: Object.freeze({ available: false }),
    runtime: Object.freeze({ available: false }),
  }),
) {
  const summary = validateSummary(sourceSummary);
  const lines = [
    "% Generated deterministically by Hermsec.",
    "% Source values are accepted only after v3 suite and receipt reconciliation.",
    "% Do not edit quantitative macros by hand.",
    "",
    "\\newcommand{\\ResultUnavailable}{\\textit{N/A}}",
    "\\newcommand{\\ResultPending}{\\ResultUnavailable}",
    "",
    "% Suite, dataset, and execution completeness.",
    macro(
      "ExperimentSuiteId",
      `\\texttt{${latexEscape(summary.suiteId)}}`,
    ),
    macro("DatasetSuiteCount", "1"),
    macro(
      "ExperimentExecution",
      `\\texttt{${latexEscape(summary.execution)}}`,
    ),
    macro("DatasetFixtureCount", String(summary.fixtureCount)),
    macro("DatasetTruthCount", String(summary.truthCount)),
    macro("CompletedCellCount", String(summary.totals.statusCounts.success)),
    macro("ExpectedCellCount", String(summary.cellCount)),
    macro("PartialCellCount", String(summary.totals.statusCounts.partial)),
    macro("DegradedCellCount", String(summary.totals.statusCounts.degraded)),
    macro("CanceledCellCount", String(summary.totals.statusCounts.canceled)),
    macro("FailedCellCount", String(summary.totals.statusCounts.failed)),
    "",
    "% Aggregate mode metrics and attributed costs.",
  ];

  for (const mode of summary.modes) {
    const stem = MODE_DETAILS[mode.mode].macro;
    const comparable = mode.comparison.eligible;
    lines.push(
      macro(
        `${stem}Precision`,
        comparable
          ? displayRatio(mode.metrics.precision)
          : "\\ResultUnavailable",
      ),
      macro(
        `${stem}Recall`,
        comparable
          ? displayRatio(mode.metrics.recall)
          : "\\ResultUnavailable",
      ),
      macro(
        `${stem}FOne`,
        comparable
          ? displayRatio(mode.metrics.f1)
          : "\\ResultUnavailable",
      ),
      macro(
        `${stem}Cost`,
        comparable
          ? `\\$${costText(mode.cost.attributedCostUsd)}`
          : "\\ResultUnavailable",
      ),
      "",
    );
  }

  const comparableModes = summary.modes.filter(
    (mode) => mode.comparison.eligible,
  );
  const bestPrecision = bestMode(comparableModes, "precision");
  const bestRecall = bestMode(comparableModes, "recall");
  const bestFOne = bestMode(comparableModes, "f1");
  lines.push(
    "% Comparative, cost, replay, and runtime results.",
    macro(
      "BestFOneMode",
      bestFOne
        ? `\\texttt{${latexEscape(bestFOne.mode)}}`
        : "\\ResultUnavailable",
    ),
    macro(
      "BestFOneValue",
      bestFOne
        ? displayRatio(bestFOne.metrics.f1)
        : "\\ResultUnavailable",
    ),
    macro(
      "BestRecallMode",
      bestRecall
        ? `\\texttt{${latexEscape(bestRecall.mode)}}`
        : "\\ResultUnavailable",
    ),
    macro(
      "BestRecallValue",
      bestRecall
        ? displayRatio(bestRecall.metrics.recall)
        : "\\ResultUnavailable",
    ),
    macro(
      "BestPrecisionMode",
      bestPrecision
        ? `\\texttt{${latexEscape(bestPrecision.mode)}}`
        : "\\ResultUnavailable",
    ),
    macro(
      "BestPrecisionValue",
      bestPrecision
        ? displayRatio(bestPrecision.metrics.precision)
        : "\\ResultUnavailable",
    ),
    macro(
      "TotalPhysicalCost",
      `\\$${costText(summary.totals.actualPhysicalSpendUsd)}`,
    ),
    macro(
      "ReplayAgreement",
      verifiedEvidence.replayAgreement.available
        ? displayRatio(
            verifiedEvidence.replayAgreement.matchingCells /
              verifiedEvidence.replayAgreement.totalCells,
          )
        : "\\ResultUnavailable",
    ),
    macro(
      "ManifestValidationRate",
      verifiedEvidence.manifestValidation.available
        ? displayRatio(verifiedEvidence.manifestValidation.rate)
        : "\\ResultUnavailable",
    ),
    macro(
      "MedianWallClockTime",
      verifiedEvidence.runtime.available
        ? `${numberText(verifiedEvidence.runtime.medianWallClockMs)}\\,ms`
        : "\\ResultUnavailable",
    ),
    "",
  );
  return `${lines.join("\n")}\n`;
}

function buildProvenance(source, macros) {
  const summary = source.validated;
  const macroBytes = Buffer.byteLength(macros, "utf8");
  const macroSha256 = sha256(macros);
  const evidence = {
    manifestValidation: source.verifiedEvidence.manifestValidation.available
      ? {
          available: true,
          validated:
            source.verifiedEvidence.manifestValidation.validated,
          total: source.verifiedEvidence.manifestValidation.total,
          rate: source.verifiedEvidence.manifestValidation.rate,
          source:
            "integrity-receipt.json#/downstreamEvidence/manifestRate",
        }
      : {
          available: false,
          reason: "not available in verified bound evidence",
        },
    replayAgreement: source.verifiedEvidence.replayAgreement.available
      ? {
          available: true,
          matchingCells:
            source.verifiedEvidence.replayAgreement.matchingCells,
          totalCells:
            source.verifiedEvidence.replayAgreement.totalCells,
          rate:
            source.verifiedEvidence.replayAgreement.matchingCells /
            source.verifiedEvidence.replayAgreement.totalCells,
          source:
            "integrity-receipt.json#/downstreamEvidence/replayAgreement",
        }
      : {
          available: false,
          reason:
            source.verifiedEvidence.replayAgreement.reason ??
            "not available in verified bound evidence",
        },
    runtime: source.verifiedEvidence.runtime.available
      ? {
          available: true,
          medianWallClockMs:
            source.verifiedEvidence.runtime.medianWallClockMs,
          sampleCount: source.verifiedEvidence.runtime.sampleCount,
          source:
            "integrity-receipt.json#/upstream/runManifests/*/durationMs",
        }
      : {
          available: false,
          reason: "not available in verified bound evidence",
        },
  };
  const body = {
    schemaVersion: PROVENANCE_SCHEMA_VERSION,
    kind: "hermsec-paper-results-provenance",
    generator: {
      name: "scripts/research/generate-paper-results.mjs",
      version: "2.0",
      deterministic: true,
    },
    inputContract: {
      schemaVersion: INPUT_CONTRACT_SCHEMA_VERSION,
      requiredSummarySchemaVersion: "1.0",
      requiredReceiptSchemaVersion: RECEIPT_SCHEMA_VERSION,
      requiredSuiteIndexSchemaVersion: SUITE_INDEX_SCHEMA_VERSION,
    },
    source: {
      kind: "hermsec-seven-mode-summary-bundle",
      schemaVersion: source.summary.schemaVersion,
      suiteId: summary.suiteId,
      execution: summary.execution,
      bundleSha256: source.bundleSha256,
      artifacts: source.bindings,
      integrityReceiptSha256: source.receipt.receiptSha256,
      upstreamBindingSha256:
        source.receipt.upstreamBindingSha256,
      derivationBindingSha256:
        source.receipt.derivationBindingSha256,
      summarizerSha256: source.receipt.generator.sha256,
      suiteIndexSha256: source.suiteBinding.indexSha256,
      suiteIndexFileSha256:
        source.suiteBinding.indexFileSha256,
    },
    validation: {
      exactArtifactSet: true,
      regularFilesOnly: true,
      confinedReads: true,
      secretAndPathScan: "passed",
      schemaValidation: "passed",
      crossArtifactReconciliation: "passed",
      receiptVerification: "passed",
      v3SuiteTrustChain: "passed",
      deterministicSummarizerRerun: "byte-identical",
      classMetricRecomputation: "passed",
      modeMatrix: [...MODES],
      modeEligibility: Object.fromEntries(
        summary.modes.map((mode) => [
          mode.mode,
          {
            eligible: mode.comparison.eligible,
            reasons: mode.comparison.reasons,
          },
        ]),
      ),
    },
    macroSources: buildMacroSources(),
    optionalEvidence: evidence,
    output: {
      macros: {
        path: "generated/results-macros.tex",
        bytes: macroBytes,
        sha256: macroSha256,
      },
    },
    integrity: EXPORT_INTEGRITY_NOTICE,
  };
  return {
    ...body,
    provenanceSha256: sha256(canonicalJson(body)),
  };
}

function buildMacroSources() {
  const sources = {
    ExperimentSuiteId: "summary.json#/suiteId",
    DatasetSuiteCount: "constant:one-input-suite",
    ExperimentExecution: "summary.json#/execution",
    DatasetFixtureCount: "summary.json#/fixtureCount",
    DatasetTruthCount:
      "validated equality:summary.json#/modes/*/metrics/totalExpected",
    CompletedCellCount: "summary.json#/totals/statusCounts/success",
    ExpectedCellCount: "summary.json#/cellCount",
    PartialCellCount: "summary.json#/totals/statusCounts/partial",
    DegradedCellCount: "summary.json#/totals/statusCounts/degraded",
    CanceledCellCount: "summary.json#/totals/statusCounts/canceled",
    FailedCellCount: "summary.json#/totals/statusCounts/failed",
    BestFOneMode:
      "deterministic max:eligible complete successful modes only;summary.json#/modes/*/metrics/f1;tie=modeOrder",
    BestFOneValue:
      "deterministic max:eligible complete successful modes only;summary.json#/modes/*/metrics/f1;tie=modeOrder",
    BestRecallMode:
      "deterministic max:eligible complete successful modes only;summary.json#/modes/*/metrics/recall;tie=modeOrder",
    BestRecallValue:
      "deterministic max:eligible complete successful modes only;summary.json#/modes/*/metrics/recall;tie=modeOrder",
    BestPrecisionMode:
      "deterministic max:eligible complete successful modes only;summary.json#/modes/*/metrics/precision;tie=modeOrder",
    BestPrecisionValue:
      "deterministic max:eligible complete successful modes only;summary.json#/modes/*/metrics/precision;tie=modeOrder",
    TotalPhysicalCost:
      "summary.json#/totals/actualPhysicalSpendUsd",
    ReplayAgreement:
      "integrity-receipt.json#/downstreamEvidence/replayAgreement|N/A",
    ManifestValidationRate:
      "integrity-receipt.json#/downstreamEvidence/manifestRate",
    MedianWallClockTime:
      "derived median:integrity-receipt.json#/upstream/runManifests/*/durationMs|N/A",
  };
  for (const [index, mode] of MODES.entries()) {
    const stem = MODE_DETAILS[mode].macro;
    sources[`${stem}Precision`] =
      `eligible-complete-only:summary.json#/modes/${index}/metrics/precision|N/A`;
    sources[`${stem}Recall`] =
      `eligible-complete-only:summary.json#/modes/${index}/metrics/recall|N/A`;
    sources[`${stem}FOne`] =
      `eligible-complete-only:summary.json#/modes/${index}/metrics/f1|N/A`;
    sources[`${stem}Cost`] =
      `eligible-complete-only:summary.json#/modes/${index}/cost/attributedCostUsd|N/A`;
  }
  return sources;
}

async function writeFreshOutput(outputDirectory, macros, provenance) {
  await assertPathAbsent(outputDirectory, "--out directory");

  const parent = path.dirname(outputDirectory);
  try {
    await fs.mkdir(parent, { recursive: true });
  } catch {
    throw new PaperExportError("Unable to create the --out parent directory.");
  }

  let stagingDirectory;
  let published = false;
  try {
    stagingDirectory = await fs.mkdtemp(
      path.join(parent, `.${path.basename(outputDirectory)}.tmp-`),
    );
    const generatedDirectory = path.join(stagingDirectory, "generated");
    await fs.mkdir(generatedDirectory);
    await fs.writeFile(
      path.join(generatedDirectory, "results-macros.tex"),
      macros,
      { encoding: "utf8", flag: "wx" },
    );
    await fs.writeFile(
      path.join(generatedDirectory, "results-provenance.json"),
      `${JSON.stringify(provenance, null, 2)}\n`,
      { encoding: "utf8", flag: "wx" },
    );
    await validatePublishedOutputTree(stagingDirectory);
    await assertPathAbsent(outputDirectory, "--out directory");
    await fs.rename(stagingDirectory, outputDirectory);
    published = true;
    stagingDirectory = undefined;
    await validatePublishedOutputTree(outputDirectory);
    published = false;
  } catch (error) {
    if (error instanceof PaperExportError) {
      throw error;
    }
    throw new PaperExportError(
      "Unable to write paper result artifacts safely.",
    );
  } finally {
    if (stagingDirectory) {
      await fs.rm(stagingDirectory, { recursive: true, force: true });
    }
    if (published) {
      await fs.rm(outputDirectory, { recursive: true, force: true });
    }
  }
}

async function assertSeparateOutput(
  requestedSummaryDirectory,
  realSummaryDirectory,
  requestedSuiteDirectory,
  realSuiteDirectory,
  outputDirectory,
) {
  for (const [requested, real, label] of [
    [
      path.resolve(requestedSummaryDirectory),
      realSummaryDirectory,
      "source summary",
    ],
    [
      path.resolve(requestedSuiteDirectory),
      realSuiteDirectory,
      "original suite",
    ],
  ]) {
    const relativeFromRequested = path.relative(requested, outputDirectory);
    const relativeFromReal = path.relative(real, outputDirectory);
    if (
      isSameOrDescendant(relativeFromRequested) ||
      isSameOrDescendant(relativeFromReal)
    ) {
      throw new PaperExportError(
        `The --out directory must not be inside the ${label} directory.`,
      );
    }
  }
  const realCandidate = await resolveProspectivePath(outputDirectory);
  for (const [real, label] of [
    [realSummaryDirectory, "source summary"],
    [realSuiteDirectory, "original suite"],
  ]) {
    const relativeFromResolvedParent = path.relative(real, realCandidate);
    if (isSameOrDescendant(relativeFromResolvedParent)) {
      throw new PaperExportError(
        `The --out directory must not resolve inside the ${label} directory.`,
      );
    }
  }
}

async function resolveProspectivePath(candidatePath) {
  let cursor = path.resolve(candidatePath);
  const missingSegments = [];
  while (true) {
    try {
      await fs.lstat(cursor);
      const realAncestor = await fs.realpath(cursor);
      return path.join(realAncestor, ...missingSegments);
    } catch (error) {
      if (error?.code !== "ENOENT") {
        throw new PaperExportError(
          "Unable to resolve the prospective --out path.",
        );
      }
      const parent = path.dirname(cursor);
      if (parent === cursor) {
        throw new PaperExportError(
          "Unable to resolve the prospective --out path.",
        );
      }
      missingSegments.unshift(path.basename(cursor));
      cursor = parent;
    }
  }
}

function isSameOrDescendant(relativePath) {
  return (
    relativePath === "" ||
    (relativePath !== ".." &&
      !relativePath.startsWith(`..${path.sep}`) &&
      !path.isAbsolute(relativePath))
  );
}

async function resolveRealInputDirectory(directory, label) {
  const stat = await lstatOrThrow(directory, `${label} directory`);
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new PaperExportError(
      `The --${label} path must be a real directory, not a symbolic link or junction.`,
    );
  }
  let realDirectory;
  try {
    realDirectory = await fs.realpath(directory);
  } catch {
    throw new PaperExportError(
      `Unable to resolve the ${label} directory.`,
    );
  }
  const realStat = await lstatOrThrow(
    realDirectory,
    `resolved ${label} directory`,
  );
  if (!realStat.isDirectory() || realStat.isSymbolicLink()) {
    throw new PaperExportError(
      `The --${label} path must resolve to a real directory.`,
    );
  }
  return { realDirectory };
}

async function readExactTextDirectory(directory, expectedFiles, label) {
  const { realDirectory } = await resolveRealInputDirectory(
    directory,
    label,
  );
  let entries;
  try {
    entries = await fs.readdir(realDirectory, { withFileTypes: true });
  } catch {
    throw new PaperExportError(
      `Unable to enumerate the ${label} directory.`,
    );
  }
  const entryNames = entries.map((entry) => entry.name).sort(compareText);
  expectArrayEqual(
    entryNames,
    [...expectedFiles],
    `${label} artifact inventory`,
  );
  const contents = new Map();
  const bindings = [];
  let totalBytes = 0;
  for (const fileName of expectedFiles) {
    const entry = entries.find((candidate) => candidate.name === fileName);
    if (!entry || entry.isSymbolicLink() || !entry.isFile()) {
      throw new PaperExportError(
        `${label} artifact ${fileName} must be a regular file.`,
      );
    }
    const filePath = await resolveConfinedRegularFile(
      realDirectory,
      path.join(realDirectory, fileName),
      fileName,
      label,
    );
    const content = await readBoundFile(filePath, `${label} ${fileName}`);
    if (content.byteLength > MAX_SOURCE_FILE_BYTES) {
      throw new PaperExportError(
        `${label} artifact ${fileName} exceeds the size limit.`,
      );
    }
    totalBytes += content.byteLength;
    if (totalBytes > MAX_SOURCE_BUNDLE_BYTES) {
      throw new PaperExportError(`${label} artifact bundle is too large.`);
    }
    const text = decodeUtf8(content, `${label} ${fileName}`);
    assertNoSecrets(text, `${label} ${fileName}`);
    contents.set(fileName, text);
    bindings.push({
      path: fileName,
      bytes: content.byteLength,
      sha256: sha256(content),
    });
  }
  return {
    realDirectory,
    contents,
    bindings: bindings.sort((left, right) =>
      compareText(left.path, right.path),
    ),
  };
}

function assertDistinctInputDirectories(summaryDirectory, suiteDirectory) {
  const summaryFromSuite = path.relative(suiteDirectory, summaryDirectory);
  const suiteFromSummary = path.relative(summaryDirectory, suiteDirectory);
  if (
    isSameOrDescendant(summaryFromSuite) ||
    isSameOrDescendant(suiteFromSummary)
  ) {
    throw new PaperExportError(
      "The --summary and --suite directories must be separate, non-nested inputs.",
    );
  }
}

async function resolveConfinedRegularFile(
  rootDirectory,
  filePath,
  label,
  sourceLabel = "summary",
) {
  const candidate = path.resolve(filePath);
  const relative = path.relative(rootDirectory, candidate);
  if (
    relative === ".." ||
    relative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relative)
  ) {
    throw new PaperExportError(
      `${sourceLabel} artifact ${label} escapes its source directory.`,
    );
  }
  const stat = await lstatOrThrow(
    candidate,
    `${sourceLabel} artifact ${label}`,
  );
  if (stat.isSymbolicLink() || !stat.isFile()) {
    throw new PaperExportError(
      `${sourceLabel} artifact ${label} must be a regular file.`,
    );
  }
  let real;
  try {
    real = await fs.realpath(candidate);
  } catch {
    throw new PaperExportError(
      `Unable to resolve ${sourceLabel} artifact ${label}.`,
    );
  }
  const realRelative = path.relative(rootDirectory, real);
  if (
    realRelative === ".." ||
    realRelative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(realRelative)
  ) {
    throw new PaperExportError(
      `${sourceLabel} artifact ${label} resolves outside its source directory.`,
    );
  }
  return real;
}

async function readBoundFile(filePath, label) {
  try {
    return await fs.readFile(filePath);
  } catch {
    throw new PaperExportError(`Unable to read required ${label}.`);
  }
}

async function readWrappedSuiteArtifact(suiteDirectory, relativePath) {
  const filePath = await resolveConfinedRegularFile(
    suiteDirectory,
    path.join(suiteDirectory, ...relativePath.split("/")),
    relativePath,
    "suite",
  );
  const document = parseJsonBuffer(
    await readBoundFile(filePath, relativePath),
    relativePath,
  );
  const wrapper = objectValue(document, `${relativePath} wrapper`);
  expectEqual(
    wrapper.schemaVersion,
    "1.0",
    `${relativePath} wrapper schemaVersion`,
  );
  return objectValue(wrapper.data, `${relativePath} data`);
}

function parseJsonBuffer(content, label) {
  try {
    return JSON.parse(decodeUtf8(content, label));
  } catch (error) {
    if (error instanceof PaperExportError) {
      throw error;
    }
    throw new PaperExportError(`${label} is not valid JSON.`);
  }
}

async function runNodeScript(scriptPath, arguments_) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [scriptPath, ...arguments_], {
      cwd: path.resolve(fileURLToPath(new URL("../..", import.meta.url))),
      env: {
        PATH: process.env.PATH,
        SystemRoot: process.env.SystemRoot,
        TEMP: process.env.TEMP,
        TMP: process.env.TMP,
      },
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
    let stdout = "";
    let stderr = "";
    const append = (current, chunk) =>
      `${current}${chunk}`.slice(-64 * 1024);
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout = append(stdout, chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderr = append(stderr, chunk);
    });
    child.once("error", reject);
    child.once("close", (code) =>
      resolve({ code, stdout, stderr }),
    );
  });
}

async function assertPathAbsent(candidate, label) {
  try {
    await fs.lstat(candidate);
    throw new PaperExportError(
      `The ${label} already exists; choose a fresh path.`,
    );
  } catch (error) {
    if (error instanceof PaperExportError) {
      throw error;
    }
    if (error?.code !== "ENOENT") {
      throw new PaperExportError(`Unable to validate the ${label}.`);
    }
  }
}

async function validatePublishedOutputTree(outputDirectory) {
  const stat = await lstatOrThrow(
    outputDirectory,
    "staged output directory",
  );
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new PaperExportError(
      "The staged output must be a real directory.",
    );
  }
  const realRoot = await fs.realpath(outputDirectory);
  const rootEntries = await fs.readdir(realRoot, {
    withFileTypes: true,
  });
  expectArrayEqual(
    rootEntries.map((entry) => entry.name).sort(compareText),
    ["generated"],
    "published output root inventory",
  );
  const generatedEntry = rootEntries[0];
  if (
    !generatedEntry ||
    generatedEntry.isSymbolicLink() ||
    !generatedEntry.isDirectory()
  ) {
    throw new PaperExportError(
      "The generated output entry must be a real directory.",
    );
  }
  const generatedDirectory = path.join(realRoot, "generated");
  const generatedEntries = await fs.readdir(generatedDirectory, {
    withFileTypes: true,
  });
  expectArrayEqual(
    generatedEntries.map((entry) => entry.name).sort(compareText),
    ["results-macros.tex", "results-provenance.json"],
    "published output artifact inventory",
  );
  for (const entry of generatedEntries) {
    if (entry.isSymbolicLink() || !entry.isFile()) {
      throw new PaperExportError(
        "Published output artifacts must be regular files.",
      );
    }
    await resolveConfinedRegularFile(
      realRoot,
      path.join(generatedDirectory, entry.name),
      `generated/${entry.name}`,
      "output",
    );
  }
}

async function lstatOrThrow(filePath, label) {
  try {
    return await fs.lstat(filePath);
  } catch {
    throw new PaperExportError(`Unable to read required ${label}.`);
  }
}

function decodeUtf8(content, label) {
  const text = content.toString("utf8");
  if (Buffer.from(text, "utf8").compare(content) !== 0 || text.includes("\0")) {
    throw new PaperExportError(`${label} must be canonical UTF-8 text.`);
  }
  return text;
}

function assertNoSecrets(text, label) {
  for (const pattern of SECRET_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(text)) {
      throw new PaperExportError(
        `Potential secret material detected in ${label}; export refused.`,
      );
    }
  }
}

function assertNoSensitiveStrings(value, label, seen = new Set()) {
  if (typeof value === "string") {
    assertNoSecrets(value, label);
    safeText(value, label);
    return;
  }
  if (value === null || typeof value !== "object") {
    return;
  }
  if (seen.has(value)) {
    throw new PaperExportError(`${label} contains a cyclic value.`);
  }
  seen.add(value);
  if (Array.isArray(value)) {
    value.forEach((entry, index) =>
      assertNoSensitiveStrings(entry, `${label}[${index}]`, seen),
    );
  } else {
    for (const [key, entry] of Object.entries(value)) {
      safeText(key, `${label} key`);
      assertNoSensitiveStrings(entry, `${label}.${key}`, seen);
    }
  }
  seen.delete(value);
}

function safeText(value, label) {
  if (
    typeof value !== "string" ||
    value.length > 4096 ||
    /[\u0000-\u001f\u007f]/u.test(value) ||
    path.win32.isAbsolute(value) ||
    path.posix.isAbsolute(value) ||
    /(?:^|[\\/])\.\.(?:[\\/]|$)/u.test(value) ||
    /(?:^|[\s"'(])(?:[A-Za-z]:[\\/]|\\\\)/u.test(value) ||
    /(?:^|[\s"'(])file:\/\//iu.test(value)
  ) {
    throw new PaperExportError(
      `${label} contains unsafe path or control data.`,
    );
  }
  return value;
}

function requiredString(value, label) {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new PaperExportError(`${label} must be a non-empty string.`);
  }
  return value;
}

function safeStringArray(value, label) {
  const values = arrayValue(value, label).map((entry, index) =>
    safeText(
      requiredString(entry, `${label} ${index}`),
      `${label} ${index}`,
    ),
  );
  if (new Set(values).size !== values.length) {
    throw new PaperExportError(`${label} contains duplicate values.`);
  }
  return values;
}

function safeRelativeArtifactPath(value, label) {
  const text = safeText(requiredString(value, label), label);
  if (
    text.includes("\\") ||
    path.posix.isAbsolute(text) ||
    path.posix.normalize(text) !== text ||
    text === "." ||
    text.startsWith("../") ||
    text.includes("/../") ||
    text.endsWith("/..")
  ) {
    throw new PaperExportError(
      `${label} must be a normalized confined relative path.`,
    );
  }
  return text;
}

function validateDigestBinding(value, label, allowedPaths) {
  const binding = objectValue(value, label);
  assertExactKeys(
    binding,
    ["path", "bytes", "sha256"],
    [],
    label,
  );
  const relativePath = safeRelativeArtifactPath(
    binding.path,
    `${label} path`,
  );
  if (allowedPaths && !allowedPaths.includes(relativePath)) {
    throw new PaperExportError(`${label} names an unknown artifact.`);
  }
  return {
    path: relativePath,
    bytes: nonNegativeInteger(binding.bytes, `${label} bytes`),
    sha256: expectDigest(binding.sha256, `${label} sha256`),
  };
}

function assertUniqueSortedBindings(bindings, expectedPaths, label) {
  const paths = bindings.map((entry) => entry.path);
  assertUniqueValues(paths, `${label} paths`);
  expectArrayEqual(
    paths,
    [...paths].sort(compareText),
    `${label} order`,
  );
  if (expectedPaths) {
    expectArrayEqual(
      paths,
      [...expectedPaths].sort(compareText),
      `${label} set`,
    );
  }
}

function assertUniqueValues(values, label) {
  if (new Set(values).size !== values.length) {
    throw new PaperExportError(`${label} contains duplicate values.`);
  }
}

function objectValue(value, label) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new PaperExportError(`${label} must be a plain object.`);
  }
  return value;
}

function arrayValue(value, label) {
  if (!Array.isArray(value)) {
    throw new PaperExportError(`${label} must be an array.`);
  }
  return value;
}

function assertExactKeys(value, required, optional, label) {
  const keys = Object.keys(value).sort(compareText);
  const allowed = [...required, ...optional].sort(compareText);
  const missing = required.filter(
    (key) => !Object.prototype.hasOwnProperty.call(value, key),
  );
  const unknown = keys.filter((key) => !allowed.includes(key));
  if (missing.length > 0 || unknown.length > 0) {
    throw new PaperExportError(
      `${label} has an invalid field set (missing: ${missing.join(", ") || "none"}; unknown: ${unknown.join(", ") || "none"}).`,
    );
  }
}

function oneOf(value, allowed, label) {
  if (typeof value !== "string" || !allowed.includes(value)) {
    throw new PaperExportError(`${label} is invalid.`);
  }
  return value;
}

function nonNegativeNumber(value, label) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    throw new PaperExportError(`${label} must be a finite non-negative number.`);
  }
  return value;
}

function nonNegativeInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new PaperExportError(`${label} must be a non-negative integer.`);
  }
  return value;
}

function positiveInteger(value, label) {
  const output = nonNegativeInteger(value, label);
  if (output === 0) {
    throw new PaperExportError(`${label} must be greater than zero.`);
  }
  return output;
}

function probability(value, label) {
  const output = nonNegativeNumber(value, label);
  if (output > 1) {
    throw new PaperExportError(`${label} must be between zero and one.`);
  }
  return output;
}

function nullableNonNegativeInteger(value, label) {
  return value === null ? null : nonNegativeInteger(value, label);
}

function nullableProbability(value, label) {
  return value === null ? null : probability(value, label);
}

function expectEqual(actual, expected, label) {
  if (actual !== expected) {
    throw new PaperExportError(`${label} does not reconcile.`);
  }
}

function expectArrayEqual(actual, expected, label) {
  if (
    actual.length !== expected.length ||
    actual.some((entry, index) => entry !== expected[index])
  ) {
    throw new PaperExportError(`${label} does not reconcile.`);
  }
}

function canonicalEqual(actual, expected, label) {
  if (canonicalJson(actual) !== canonicalJson(expected)) {
    throw new PaperExportError(`${label} does not reconcile.`);
  }
}

function nearlyEqual(actual, expected, label) {
  const difference = Math.abs(actual - expected);
  const scale = Math.max(1, Math.abs(actual), Math.abs(expected));
  if (difference > 1e-9 * scale) {
    throw new PaperExportError(`${label} does not reconcile.`);
  }
}

function bestMode(modes, metric) {
  if (modes.length === 0) {
    return null;
  }
  return modes.reduce((best, candidate) =>
    candidate.metrics[metric] > best.metrics[metric] ? candidate : best,
  );
}

function expectDigest(value, label) {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/u.test(value)) {
    throw new PaperExportError(`${label} must be a lowercase SHA-256 digest.`);
  }
  return value;
}

function assertIntegrityNotice(value, label) {
  const notice = objectValue(value, label);
  assertExactKeys(
    notice,
    ["kind", "authenticated", "notice"],
    [],
    label,
  );
  canonicalEqual(notice, RECEIPT_INTEGRITY_NOTICE, label);
}

function validTimestamp(value, label) {
  if (typeof value !== "string" || Number.isNaN(Date.parse(value))) {
    throw new PaperExportError(`${label} must be a valid timestamp.`);
  }
  return Date.parse(value);
}

function macro(name, value) {
  return `\\newcommand{\\${name}}{${value}}`;
}

function csvRow(values) {
  return values.map(csvCell).join(",");
}

function csvCell(value) {
  let text = value === null || value === undefined ? "" : String(value);
  if (/^[=+@-]/u.test(text)) {
    text = `'${text}`;
  }
  if (/[",\r\n]/u.test(text)) {
    return `"${text.replaceAll('"', '""')}"`;
  }
  return text;
}

function numberText(value) {
  if (Number.isInteger(value)) {
    return String(value);
  }
  return value.toFixed(12).replace(/0+$/u, "").replace(/\.$/u, "");
}

function nullableText(value) {
  return value === null ? "" : numberText(value);
}

function displayRatio(value) {
  return value.toFixed(3);
}

function costText(value) {
  return value.toFixed(6);
}

function markdownCell(value) {
  return String(value)
    .replaceAll("\\", "\\\\")
    .replaceAll("|", "\\|")
    .replace(/\r?\n/gu, " ");
}

function markdownInline(value) {
  return String(value).replaceAll("`", "\\`");
}

function latexEscape(value) {
  const replacements = {
    "\\": "\\textbackslash{}",
    "&": "\\&",
    "%": "\\%",
    "$": "\\$",
    "#": "\\#",
    "_": "\\_",
    "{": "\\{",
    "}": "\\}",
    "~": "\\textasciitilde{}",
    "^": "\\textasciicircum{}",
  };
  return [...String(value)]
    .map((character) => replacements[character] ?? character)
    .join("");
}

function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

function prettyCanonicalJson(value) {
  return `${JSON.stringify(canonicalize(value), null, 2)}\n`;
}

function canonicalize(value) {
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort(compareText)
        .map((key) => [key, canonicalize(value[key])]),
    );
  }
  if (typeof value === "number" && !Number.isFinite(value)) {
    throw new PaperExportError("Cannot hash non-finite provenance data.");
  }
  return value;
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function printHelp() {
  process.stdout.write(`Hermsec deterministic paper-results exporter

Usage:
  node scripts/research/generate-paper-results.mjs \\
    --summary <validated-summary-directory> \\
    --suite <original-v3-suite-directory> \\
    --out <fresh-output-directory>

The source directory must contain exactly the eight artifacts emitted by
summarize-seven-mode.mjs, including integrity-receipt.json. The exporter
validates the original v3 suite, verifies every receipt binding, and reruns the
deterministic summarizer before writing generated/results-macros.tex and
generated/results-provenance.json. Existing output paths are refused.
`);
}
