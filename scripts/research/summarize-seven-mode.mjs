import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import process from "node:process";

const MODES = Object.freeze([
  "scanner-only",
  "single-agent",
  "moa-low",
  "moa-high",
  "scanner-single",
  "scanner-moa-low",
  "scanner-moa-high",
]);

const MODE_LABELS = Object.freeze({
  "scanner-only": "Scanner only",
  "single-agent": "Single agent",
  "moa-low": "MoA Low",
  "moa-high": "MoA High",
  "scanner-single": "Scanner + Single",
  "scanner-moa-low": "Scanner + MoA Low",
  "scanner-moa-high": "Scanner + MoA High",
});

const PHYSICAL_MODES = new Set([
  "scanner-only",
  "single-agent",
  "moa-low",
  "moa-high",
]);

const HYBRID_SOURCES = Object.freeze({
  "scanner-single": ["scanner-only", "single-agent"],
  "scanner-moa-low": ["scanner-only", "moa-low"],
  "scanner-moa-high": ["scanner-only", "moa-high"],
});

const CELL_STATUSES = Object.freeze([
  "success",
  "partial",
  "degraded",
  "canceled",
  "failed",
]);

const COMPLETENESS_STATUSES = Object.freeze([
  "complete",
  "partial",
  "degraded",
]);

const OUTPUT_FILES = Object.freeze([
  "summary.json",
  "metrics.csv",
  "metrics.md",
  "completeness.csv",
  "cost.csv",
  "metrics-table.tex",
  "cost-table.tex",
  "integrity-receipt.json",
]);

const RUN_MANIFEST_FILE = "run-manifest.json";
const SUITE_INDEX_FILE = "suite-index.json";
const COST_LEDGER_FILE = "cost-ledger.jsonl";
const MODEL_CALLS_FILE = "model-calls.json";
const CELL_ARTIFACTS = Object.freeze([
  "completeness.json",
  "cost.json",
  "detector-evidence.json",
  "model-calls.json",
  "result.json",
  "source-state.json",
]);
const REQUIRED_SUITE_ARTIFACTS = Object.freeze([
  "cost-ledger.jsonl",
  "evaluation.json",
  "experiment-summary.json",
  "source-index.json",
]);
const INTEGRITY_NOTICE = Object.freeze({
  kind: "sha256-tamper-evident",
  authenticated: false,
  notice:
    "Hashes detect accidental changes and unsophisticated tampering only. They are not signed or authenticated; a writer with artifact access can recompute them.",
});
const NANO_USD_PER_USD = 1_000_000_000;
const GLOBAL_BUDGET_USD = 3.25;
const GLOBAL_BUDGET_NANO_USD =
  GLOBAL_BUDGET_USD * NANO_USD_PER_USD;
const MODE_BUDGET_USD = Object.freeze({
  "scanner-only": 0,
  "single-agent": 0.015,
  "moa-low": 0.06,
  "moa-high": 0.12,
  "scanner-single": 0.015,
  "scanner-moa-low": 0.06,
  "scanner-moa-high": 0.12,
});
const DEEPSEEK_FLASH = "deepseek/deepseek-v4-flash";
const MIMO = "xiaomi/mimo-v2.5";
const MINIMAX_AGGREGATOR = "minimax/minimax-m3";
const EXACT_MODEL_ALLOWLIST = Object.freeze([
  DEEPSEEK_FLASH,
  MIMO,
  MINIMAX_AGGREGATOR,
]);
const MODEL_CALL_TERMINAL_STATES = Object.freeze([
  "succeeded",
  "failed",
  "canceled",
]);
const MODEL_CALL_TRACE_SCHEMA_VERSION = "2.0";
const MODEL_CALL_TRACE_ROLE_PLAN_VERSION = "2.0";
const MODEL_CALL_ERROR_CATEGORIES = Object.freeze([
  "aborted",
  "budget",
  "exact-model-policy",
  "provider-unavailable",
  "rate-limit",
  "replay",
  "timeout",
  "unsafe-request",
  "provider",
  "unknown",
]);
const MOA_SPECIALIST_ROLES = Object.freeze([
  "injection-and-execution",
  "identity-and-request-security",
  "sensitive-data-and-cryptography",
  "dependencies-and-supply-chain",
  "platform-storage-and-deployment",
]);
const MOA_ROLES = Object.freeze([
  ...MOA_SPECIALIST_ROLES,
  "moa-judge",
  "moa-aggregator",
]);
const FIXTURE_PROJECT_ROOT = "project";
const EXACT_ROLE_MODELS = Object.freeze({
  "single-agent-inspector": DEEPSEEK_FLASH,
  "injection-and-execution": DEEPSEEK_FLASH,
  "identity-and-request-security": DEEPSEEK_FLASH,
  "sensitive-data-and-cryptography": DEEPSEEK_FLASH,
  "dependencies-and-supply-chain": DEEPSEEK_FLASH,
  "platform-storage-and-deployment": DEEPSEEK_FLASH,
  "moa-judge": MIMO,
  "moa-aggregator": MINIMAX_AGGREGATOR,
});
const EVAL_CATEGORIES = Object.freeze([
  "code",
  "dependency",
  "secret",
  "supply-chain",
  "config",
]);
const UNCLASSIFIED_VULNERABILITY_CLASS = "<unclassified>";
const CWE_CLASSES = Object.freeze({
  "CWE-22": "path-traversal",
  "CWE-78": "command-injection",
  "CWE-79": "cross-site-scripting",
  "CWE-89": "sql-injection",
  "CWE-94": "code-injection",
  "CWE-200": "sensitive-data-exposure",
  "CWE-259": "hardcoded-secret",
  "CWE-287": "authentication-failure",
  "CWE-327": "weak-cryptography",
  "CWE-502": "unsafe-deserialization",
  "CWE-611": "xml-external-entity",
  "CWE-798": "hardcoded-secret",
  "CWE-918": "server-side-request-forgery",
});
const CLASS_PARENTS = Object.freeze({
  "reflected-xss": "cross-site-scripting",
  "stored-xss": "cross-site-scripting",
  "dom-xss": "cross-site-scripting",
  "os-command-injection": "command-injection",
  "shell-injection": "command-injection",
  "embedded-credential": "hardcoded-secret",
  "hardcoded-api-key": "hardcoded-secret",
});
const CLASS_TEXT_PATTERNS = Object.freeze([
  [/\b(sql injection|sqli)\b/iu, "sql-injection"],
  [/\b(command injection|shell injection|os command)\b/iu, "command-injection"],
  [/\breflected (?:cross[- ]site scripting|xss)\b/iu, "reflected-xss"],
  [/\bstored (?:cross[- ]site scripting|xss)\b/iu, "stored-xss"],
  [
    /\b(dom[- ]based (?:cross[- ]site scripting|xss)|dom xss)\b/iu,
    "dom-xss",
  ],
  [/\b(cross[- ]site scripting|xss)\b/iu, "cross-site-scripting"],
  [/\b(path traversal|directory traversal)\b/iu, "path-traversal"],
  [
    /\b(server[- ]side request forgery|ssrf)\b/iu,
    "server-side-request-forgery",
  ],
  [
    /\b(unsafe deseriali[sz]ation|insecure deseriali[sz]ation)\b/iu,
    "unsafe-deserialization",
  ],
  [/\b(xml external entity|xxe)\b/iu, "xml-external-entity"],
  [
    /\b(hardcoded|embedded|committed).{0,24}\b(secret|credential|api[-_ ]?key|token)\b/iu,
    "hardcoded-secret",
  ],
  [
    /\b(secret|credential|api[-_ ]?key|token).{0,24}\b(hardcoded|embedded|committed)\b/iu,
    "hardcoded-secret",
  ],
  [
    /\b(weak cryptography|weak crypto|insecure hash)\b/iu,
    "weak-cryptography",
  ],
  [
    /\b(authentication bypass|broken authentication)\b/iu,
    "authentication-failure",
  ],
  [
    /\b(vulnerable dependency|dependency advisory|known vulnerable package)\b/iu,
    "known-vulnerable-dependency",
  ],
]);

class SummaryError extends Error {}

try {
  await main();
} catch (error) {
  const message =
    error instanceof SummaryError
      ? error.message
      : "Unable to generate the seven-mode summary.";
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    printHelp();
    return;
  }
  if (!args.suite) {
    throw new SummaryError("--suite is required.");
  }
  if (!args.out) {
    throw new SummaryError("--out is required and must name a fresh directory.");
  }

  const suiteDirectory = path.resolve(args.suite);
  const outputDirectory = path.resolve(args.out);
  const [evaluation, experimentSummary] = await Promise.all([
    readWrappedJson(
      path.join(suiteDirectory, "evaluation.json"),
      "evaluation.json",
    ),
    readWrappedJson(
      path.join(suiteDirectory, "experiment-summary.json"),
      "experiment-summary.json",
    ),
  ]);
  const evaluationEngine = await loadEvaluationEngine();
  const built = await buildSummary(
    suiteDirectory,
    evaluation,
    experimentSummary,
    evaluationEngine,
  );
  const outputs = renderOutputs(built.summary);
  outputs.set(
    "integrity-receipt.json",
    await renderIntegrityReceipt(
      built.summary,
      built.receiptEvidence,
      outputs,
    ),
  );
  await writeFreshDirectory(outputDirectory, outputs);
  process.stdout.write(
    `${JSON.stringify({
      schemaVersion: "1.0",
      suiteId: built.summary.suiteId,
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
    if (value !== "--suite" && value !== "--out") {
      throw new SummaryError(`Unknown argument: ${value}`);
    }
    const next = values[index + 1];
    if (!next || next.startsWith("--")) {
      throw new SummaryError(`${value} requires a value.`);
    }
    parsed[value === "--suite" ? "suite" : "out"] = next;
    index += 1;
  }
  return parsed;
}

async function readWrappedJson(filePath, fileName) {
  let source;
  try {
    source = await fs.readFile(filePath, "utf8");
  } catch {
    throw new SummaryError(`Unable to read required ${fileName}.`);
  }
  let document;
  try {
    document = JSON.parse(source);
  } catch {
    throw new SummaryError(`${fileName} is not valid JSON.`);
  }
  const wrapper = objectValue(document, `${fileName} wrapper`);
  expectEqual(wrapper.schemaVersion, "1.0", `${fileName} schemaVersion`);
  stringArray(wrapper.redactionMarkers, `${fileName} redactionMarkers`);
  return objectValue(wrapper.data, `${fileName} data`);
}

async function loadEvaluationEngine() {
  try {
    const [matcher, projection] = await Promise.all([
      import(new URL("../../dist/src/eval/matcher.js", import.meta.url)),
      import(
        new URL(
          "../../dist/src/eval/findingProjection.js",
          import.meta.url,
        )
      ),
    ]);
    if (
      typeof matcher.matchFindings !== "function" ||
      typeof projection.projectFindings !== "function"
    ) {
      throw new Error("evaluation exports are unavailable");
    }
    return {
      matchFindings: matcher.matchFindings,
      projectFindings: projection.projectFindings,
    };
  } catch {
    throw new SummaryError(
      "The built Hermsec evaluation engine is unavailable. Run the root build before generating a seven-mode summary.",
    );
  }
}

async function buildSummary(
  suiteDirectory,
  evaluation,
  experimentSummary,
  evaluationEngine,
) {
  expectEqual(
    evaluation.schemaVersion,
    "1.0",
    "evaluation data schemaVersion",
  );
  expectEqual(
    experimentSummary.schemaVersion,
    "1.0",
    "experiment summary data schemaVersion",
  );
  const suiteId = safeOutputString(
    requiredString(experimentSummary.suiteId, "experiment suiteId"),
    "experiment suiteId",
  );
  expectEqual(evaluation.suiteId, suiteId, "evaluation suiteId");
  const execution = oneOf(
    experimentSummary.execution,
    ["mock", "replay", "live"],
    "experiment execution",
  );
  const fixtureIds = uniqueSafeStrings(
    experimentSummary.fixtureIds,
    "experiment fixtureIds",
  );
  if (fixtureIds.length === 0) {
    throw new SummaryError("experiment fixtureIds cannot be empty.");
  }
  assertExactModes(experimentSummary.modes, "experiment modes");

  const cellsByMode = validateCells(experimentSummary, fixtureIds);
  const runsByMode = validateEvaluation(evaluation, fixtureIds);
  validateExperimentTotals(
    experimentSummary,
    cellsByMode,
    fixtureIds.length,
    execution,
  );
  validateCanonicalCellCosts(cellsByMode, experimentSummary);
  const evidenceBindings = await validateSuiteEvidence({
    suiteDirectory,
    suiteId,
    execution,
    cellsByMode,
    runsByMode,
    evaluation,
    experimentSummary,
    evaluationEngine,
  });
  validateBoundPhysicalExecutionTotals({
    execution,
    experimentSummary,
    cellsByMode,
    fixtureCount: fixtureIds.length,
    fixtureIds,
    manifestBindings: evidenceBindings.manifestBindings,
  });
  await validateCostLedger({
    suiteDirectory,
    execution,
    cellsByMode,
    experimentSummary,
    manifestBindings: evidenceBindings.manifestBindings,
  });

  const modes = MODES.map((mode) => {
    const cells = cellsByMode.get(mode);
    const run = runsByMode.get(mode);
    const aggregateCost = aggregateCellCosts(cells);
    nearlyEqual(
      run.costUsd,
      aggregateCost.attributedCostUsd,
      `${mode} attributed cost`,
    );
    expectEqual(
      run.totalTokens,
      aggregateCost.attributedTokens,
      `${mode} attributed tokens`,
    );
    nearlyEqual(
      experimentSummary.attributedModeCostUsd[mode],
      aggregateCost.attributedCostUsd,
      `${mode} experiment attributed cost`,
    );
    const evidenceCaveat = validateStatusCompleteness(
      mode,
      cells,
      run.cases,
      run.completeness,
    );

    const statusCounts = countStatuses(cells);
    const caseCompleteness = run.cases.map((entry) => entry.completeness);
    const degradedCaseCount = caseCompleteness.filter(
      (entry) =>
        entry.status !== "complete" || entry.degradedReasonCount > 0,
    ).length;
    const degradationReasonCount = caseCompleteness.reduce(
      (total, entry) => total + entry.degradedReasonCount,
      0,
    );
    expectEqual(
      run.completeness.degradedReasonCount,
      degradationReasonCount,
      `${mode} aggregate degradation reason count`,
    );

    return {
      mode,
      label: MODE_LABELS[mode],
      metrics: run.metrics,
      classMetrics: run.classMetrics,
      completeness: run.completeness,
      statusCounts,
      degradation: {
        affectedCaseCount: degradedCaseCount,
        reasonCount: degradationReasonCount,
      },
      evidenceCaveat,
      cost: aggregateCost,
    };
  });

  const totals = modes.reduce(
    (output, mode) => {
      output.actualPhysicalSpendUsd += mode.cost.actualPhysicalSpendUsd;
      output.conservativeCommittedUsd +=
        mode.cost.conservativeCommittedUsd;
      output.attributedCostUsd += mode.cost.attributedCostUsd;
      output.physicalTokens += mode.cost.physicalTokens;
      output.attributedTokens += mode.cost.attributedTokens;
      output.physicalModelCalls += mode.cost.physicalModelCalls;
      output.attributedModelCalls += mode.cost.attributedModelCalls;
      output.degradedCaseCount += mode.degradation.affectedCaseCount;
      output.degradationReasonCount += mode.degradation.reasonCount;
      for (const status of CELL_STATUSES) {
        output.statusCounts[status] += mode.statusCounts[status];
      }
      return output;
    },
    {
      actualPhysicalSpendUsd: 0,
      conservativeCommittedUsd: 0,
      attributedCostUsd: 0,
      physicalTokens: 0,
      attributedTokens: 0,
      physicalModelCalls: 0,
      attributedModelCalls: 0,
      degradedCaseCount: 0,
      degradationReasonCount: 0,
      statusCounts: emptyStatusCounts(),
    },
  );
  nearlyEqual(
    totals.actualPhysicalSpendUsd,
    experimentSummary.actualPhysicalSpendUsd,
    "experiment actual physical spend",
  );
  nearlyEqual(
    totals.conservativeCommittedUsd,
    experimentSummary.conservativeCommittedUsd,
    "experiment conservative committed spend",
  );

  const summary = {
    schemaVersion: "1.0",
    suiteId,
    execution,
    fixtureCount: fixtureIds.length,
    modeCount: MODES.length,
    cellCount: fixtureIds.length * MODES.length,
    modeOrder: [...MODES],
    totals,
    modes,
  };
  return {
    summary,
    receiptEvidence: evidenceBindings.receiptEvidence,
  };
}

function validateCells(experimentSummary, fixtureIds) {
  const cells = arrayValue(experimentSummary.cells, "experiment cells");
  const expectedCellCount = fixtureIds.length * MODES.length;
  if (cells.length !== expectedCellCount) {
    throw new SummaryError(
      `experiment cells must contain the complete ${expectedCellCount}-cell seven-mode matrix.`,
    );
  }
  const fixtureSet = new Set(fixtureIds);
  const byMode = new Map(MODES.map((mode) => [mode, []]));
  const seen = new Set();
  const seenRunIds = new Set();
  const seenManifestPaths = new Set();
  for (const [index, candidate] of cells.entries()) {
    const cell = objectValue(candidate, `experiment cell ${index}`);
    const mode = canonicalMode(cell.mode, `experiment cell ${index} mode`);
    const runId = requiredString(
      cell.runId,
      `experiment cell ${index} runId`,
    );
    if (seenRunIds.has(runId)) {
      throw new SummaryError(`experiment cells repeat runId ${runId}.`);
    }
    seenRunIds.add(runId);
    const fixtureId = requiredString(
      cell.fixtureId,
      `experiment cell ${index} fixtureId`,
    );
    if (!fixtureSet.has(fixtureId)) {
      throw new SummaryError(
        `experiment cell ${index} uses an unknown fixtureId.`,
      );
    }
    const key = `${mode}\u0000${fixtureId}`;
    if (seen.has(key)) {
      throw new SummaryError(`experiment cells repeat ${mode}/${fixtureId}.`);
    }
    seen.add(key);
    const status = oneOf(
      cell.status,
      CELL_STATUSES,
      `experiment cell ${index} status`,
    );
    const physical = booleanValue(
      cell.physical,
      `experiment cell ${index} physical`,
    );
    expectEqual(
      physical,
      PHYSICAL_MODES.has(mode),
      `experiment cell ${index} physical mode contract`,
    );
    const derivedFrom = arrayValue(
      cell.derivedFrom,
      `experiment cell ${index} derivedFrom`,
    ).map((value, sourceIndex) =>
      canonicalMode(
        value,
        `experiment cell ${index} derivedFrom ${sourceIndex}`,
      ),
    );
    const expectedSources = HYBRID_SOURCES[mode] ?? [];
    expectStringArraysEqual(
      derivedFrom,
      expectedSources,
      `experiment cell ${index} derivedFrom`,
    );
    const cost = readCellCost(
      cell.cost,
      `experiment cell ${index} cost`,
    );
    if (!physical) {
      expectEqual(
        cost.actualPhysicalSpendUsd,
        0,
        `experiment cell ${index} physical spend`,
      );
      expectEqual(
        cost.conservativeCommittedUsd,
        0,
        `experiment cell ${index} committed spend`,
      );
      expectEqual(
        cost.physicalModelCalls,
        0,
        `experiment cell ${index} physical calls`,
      );
      expectEqual(
        cost.physicalTokens,
        0,
        `experiment cell ${index} physical tokens`,
      );
    }
    const manifestPath = safeRelativeArtifactPath(
      cell.manifestPath,
      `experiment cell ${index} manifestPath`,
    );
    if (
      path.posix.basename(manifestPath) !== RUN_MANIFEST_FILE ||
      seenManifestPaths.has(manifestPath)
    ) {
      throw new SummaryError(
        `experiment cell ${index} has an invalid or repeated manifestPath.`,
      );
    }
    seenManifestPaths.add(manifestPath);
    byMode.get(mode).push({
      runId,
      fixtureId,
      mode,
      status,
      physical,
      derivedFrom,
      cost,
      manifestPath,
    });
  }
  for (const mode of MODES) {
    const modeCells = byMode.get(mode);
    if (modeCells.length !== fixtureIds.length) {
      throw new SummaryError(
        `experiment mode ${mode} does not cover every fixture.`,
      );
    }
    modeCells.sort((left, right) =>
      compareText(left.fixtureId, right.fixtureId),
    );
  }
  return byMode;
}

function validateEvaluation(evaluation, fixtureIds) {
  const runs = arrayValue(evaluation.runs, "evaluation runs");
  if (runs.length !== MODES.length) {
    throw new SummaryError(
      "evaluation must contain exactly one run for each of the seven canonical modes.",
    );
  }
  const fixtureSet = new Set(fixtureIds);
  const byMode = new Map();
  const seenRunIds = new Set();
  for (const [index, candidate] of runs.entries()) {
    const run = objectValue(candidate, `evaluation run ${index}`);
    const mode = canonicalMode(run.mode, `evaluation run ${index} mode`);
    if (byMode.has(mode)) {
      throw new SummaryError(`evaluation repeats mode ${mode}.`);
    }
    const runId = requiredString(
      run.runId,
      `evaluation run ${index} runId`,
    );
    if (seenRunIds.has(runId)) {
      throw new SummaryError("evaluation repeats a runId.");
    }
    seenRunIds.add(runId);
    const cases = arrayValue(run.cases, `${mode} cases`);
    if (cases.length !== fixtureIds.length) {
      throw new SummaryError(
        `evaluation mode ${mode} does not cover every fixture.`,
      );
    }
    const seenFixtures = new Set();
    const normalizedCases = cases.map((caseCandidate, caseIndex) => {
      const evaluationCase = objectValue(
        caseCandidate,
        `${mode} case ${caseIndex}`,
      );
      const fixtureId = requiredString(
        evaluationCase.fixtureId,
        `${mode} case ${caseIndex} fixtureId`,
      );
      if (!fixtureSet.has(fixtureId) || seenFixtures.has(fixtureId)) {
        throw new SummaryError(
          `evaluation mode ${mode} has an unknown or repeated fixture.`,
        );
      }
      seenFixtures.add(fixtureId);
      const caseManifest = objectValue(
        evaluationCase.manifest,
        `${mode} case ${fixtureId} manifest`,
      );
      expectEqual(
        caseManifest.schemaVersion,
        "2.0",
        `${mode} case ${fixtureId} manifest schemaVersion`,
      );
      expectEqual(
        caseManifest.id,
        fixtureId,
        `${mode} case ${fixtureId} manifest id`,
      );
      const sourceFileCount = stringArray(
        caseManifest.sourceFiles,
        `${mode} case ${fixtureId} manifest sourceFiles`,
      ).length;
      const fixtureRoot = requiredString(
        evaluationCase.fixtureRoot,
        `${mode} case ${fixtureId} fixtureRoot`,
      );
      const truth = readEvaluationTruth(
        evaluationCase.truth,
        fixtureId,
        `${mode} case ${fixtureId} truth`,
      );
      const truthArtifactValue = objectValue(
        evaluationCase.truthArtifact,
        `${mode} case ${fixtureId} truthArtifact`,
      );
      const truthArtifact = {
        fixtureId: requiredString(
          truthArtifactValue.fixtureId,
          `${mode} case ${fixtureId} truthArtifact fixtureId`,
        ),
        path: safeRelativeArtifactPath(
          truthArtifactValue.path,
          `${mode} case ${fixtureId} truthArtifact path`,
        ),
        sha256: expectDigest(
          truthArtifactValue.sha256,
          `${mode} case ${fixtureId} truthArtifact sha256`,
        ),
        fixtureDigestSha256: expectDigest(
          truthArtifactValue.fixtureDigestSha256,
          `${mode} case ${fixtureId} truthArtifact fixtureDigestSha256`,
        ),
      };
      expectEqual(
        truthArtifact.fixtureId,
        fixtureId,
        `${mode} case ${fixtureId} truthArtifact identity`,
      );
      const matchResult = readMatchResult(
        evaluationCase.matchResult,
        `${mode} case ${fixtureId} matchResult`,
      );
      validateTruthMatchBinding(
        truth.findings,
        matchResult,
        `${mode} case ${fixtureId}`,
      );
      const derivedCase = deriveEvaluationMetrics([matchResult]);
      validateDerivedMetricClaims(
        readOverallMetrics(
          evaluationCase.metrics,
          `${mode} case ${fixtureId} metrics`,
        ),
        readClassMetrics(
          evaluationCase.metricsByClass,
          `${mode} case ${fixtureId} metricsByClass`,
        ),
        readClassSummary(
          evaluationCase.classSummary,
          `${mode} case ${fixtureId} classSummary`,
        ),
        derivedCase,
        `${mode} case ${fixtureId}`,
      );
      const completenessInput = readCompletenessInput(
        evaluationCase.completenessInput,
        `${mode} case ${fixtureId} completenessInput`,
        sourceFileCount,
      );
      const completeness = readCompleteness(
        evaluationCase.completeness,
        `${mode} case ${fixtureId} completeness`,
      );
      validateComputedCompleteness(
        completenessInput,
        completeness,
        `${mode} case ${fixtureId}`,
      );
      return {
        fixtureId,
        fixtureRoot,
        manifest: caseManifest,
        truth,
        truthArtifact,
        sourceFileCount,
        completenessInput,
        completeness,
        matchResult,
      };
    });
    normalizedCases.sort((left, right) =>
      compareText(left.fixtureId, right.fixtureId),
    );
    const runMatchResults = arrayValue(
      run.matchResults,
      `${mode} matchResults`,
    ).map((entry, matchIndex) =>
      readMatchResult(entry, `${mode} matchResults ${matchIndex}`),
    );
    if (runMatchResults.length !== normalizedCases.length) {
      throw new SummaryError(
        `${mode} run matchResults do not cover every evaluation case.`,
      );
    }
    for (const [caseIndex, evaluationCase] of normalizedCases.entries()) {
      canonicalEqual(
        runMatchResults[caseIndex].raw,
        evaluationCase.matchResult.raw,
        `${mode} run/case matchResult ${evaluationCase.fixtureId}`,
      );
    }
    const derivedRun = deriveEvaluationMetrics(
      normalizedCases.map((entry) => entry.matchResult),
    );
    validateDerivedMetricClaims(
      readOverallMetrics(run.metrics, `${mode} metrics`),
      readClassMetrics(run.metricsByClass, `${mode} metricsByClass`),
      readClassSummary(run.classSummary, `${mode} classSummary`),
      derivedRun,
      mode,
    );
    const completeness = readCompleteness(
      run.completeness,
      `${mode} completeness`,
    );
    validateAggregateCompleteness(normalizedCases, completeness, mode);
    byMode.set(mode, {
      costUsd: nonNegativeNumber(run.costUsd, `${mode} costUsd`),
      totalTokens: nonNegativeInteger(
        run.totalTokens,
        `${mode} totalTokens`,
      ),
      metrics: derivedRun.metrics,
      classMetrics: derivedRun.classMetrics,
      cases: normalizedCases,
      completeness,
    });
  }
  assertExactModes([...byMode.keys()], "evaluation modes");
  return byMode;
}

function validateExperimentTotals(
  summary,
  cellsByMode,
  fixtureCount,
  execution,
) {
  nonNegativeNumber(
    summary.actualPhysicalSpendUsd,
    "experiment actualPhysicalSpendUsd",
  );
  nonNegativeNumber(
    summary.conservativeCommittedUsd,
    "experiment conservativeCommittedUsd",
  );
  const costByMode = objectValue(
    summary.attributedModeCostUsd,
    "experiment attributedModeCostUsd",
  );
  assertExactModes(Object.keys(costByMode), "experiment attributed cost modes");
  for (const mode of MODES) {
    nonNegativeNumber(
      costByMode[mode],
      `experiment attributedModeCostUsd ${mode}`,
    );
  }
  const physical = objectValue(
    summary.physicalExecutions,
    "experiment physicalExecutions",
  );
  expectEqual(
    nonNegativeInteger(physical.scanners, "physical scanner executions"),
    fixtureCount,
    "physical scanner executions",
  );
  const agentExecutions = nonNegativeInteger(
    physical.agents,
    "physical agent executions",
  );
  const derivedHybridExecutions = nonNegativeInteger(
    physical.derivedHybrids,
    "derived hybrid executions",
  );
  const expectedAgentExecutions = fixtureCount * 3;
  if (execution === "live") {
    if (agentExecutions > expectedAgentExecutions) {
      throw new SummaryError(
        "physical agent executions exceed the complete live matrix.",
      );
    }
    expectEqual(
      derivedHybridExecutions,
      agentExecutions,
      "live fail-fast derived/agent execution binding",
    );
  } else {
    expectEqual(
      agentExecutions,
      expectedAgentExecutions,
      "physical agent executions",
    );
    expectEqual(
      derivedHybridExecutions,
      expectedAgentExecutions,
      "derived hybrid executions",
    );
  }
  for (const mode of MODES) {
    if (!cellsByMode.has(mode)) {
      throw new SummaryError(`experiment is missing mode ${mode}.`);
    }
  }
}

function validateBoundPhysicalExecutionTotals(input) {
  if (input.execution !== "live") {
    return;
  }
  const cells = [...input.cellsByMode.values()].flat();
  validateLiveFailFastSchedulingCausality(input, cells);
  const failFastAgentPlaceholders = cells.filter((cell) => {
    if (!cell.physical || cell.mode === "scanner-only") {
      return false;
    }
    const binding = input.manifestBindings.get(
      `${cell.runId}\u0000${cell.mode}`,
    );
    if (!binding) {
      throw new SummaryError(
        "physical agent execution totals found an unbound manifest.",
      );
    }
    return binding.failFastPlaceholder === true;
  });
  let failFastHybridPlaceholders = 0;
  for (const agentCell of failFastAgentPlaceholders) {
    const hybridMode = Object.entries(HYBRID_SOURCES).find(
      ([, sources]) => sources[1] === agentCell.mode,
    )?.[0];
    const hybridCell = hybridMode
      ? cells.find(
          (candidate) =>
            candidate.fixtureId === agentCell.fixtureId &&
            candidate.mode === hybridMode,
        )
      : undefined;
    if (
      !hybridCell ||
      hybridCell.physical ||
      hybridCell.status !== "canceled" ||
      !zeroCellCost(hybridCell.cost)
    ) {
      throw new SummaryError(
        `${agentCell.mode}/${agentCell.fixtureId} validated fail-fast placeholder lacks its canceled zero-cost hybrid placeholder.`,
      );
    }
    failFastHybridPlaceholders += 1;
  }
  const expectedExecutions = input.fixtureCount * 3;
  const physical = objectValue(
    input.experimentSummary.physicalExecutions,
    "experiment physicalExecutions",
  );
  expectEqual(
    nonNegativeInteger(
      physical.agents,
      "physical agent executions",
    ),
    expectedExecutions - failFastAgentPlaceholders.length,
    "manifest-bound physical agent executions",
  );
  expectEqual(
    nonNegativeInteger(
      physical.derivedHybrids,
      "derived hybrid executions",
    ),
    expectedExecutions - failFastHybridPlaceholders,
    "manifest-bound derived hybrid executions",
  );
}

function validateLiveFailFastSchedulingCausality(input, cells) {
  const agentModes = ["single-agent", "moa-low", "moa-high"];
  let trigger;
  let strictReason;
  const findCell = (fixtureId, mode) => {
    const cell = cells.find(
      (candidate) =>
        candidate.fixtureId === fixtureId &&
        candidate.mode === mode,
    );
    if (!cell) {
      throw new SummaryError(
        `live fail-fast schedule is missing ${mode}/${fixtureId}.`,
      );
    }
    return cell;
  };
  const bindingFor = (cell) => {
    const binding = input.manifestBindings.get(
      `${cell.runId}\u0000${cell.mode}`,
    );
    if (!binding) {
      throw new SummaryError(
        `live fail-fast schedule has no manifest binding for ${cell.mode}/${cell.fixtureId}.`,
      );
    }
    return binding;
  };

  for (const fixtureId of input.fixtureIds) {
    const scanner = findCell(fixtureId, "scanner-only");
    const scannerBinding = bindingFor(scanner);
    if (scannerBinding.strictLiveGateReasons.length !== 0) {
      throw new SummaryError(
        `${scanner.mode}/${fixtureId} cannot be a paid-gate scheduling placeholder.`,
      );
    }
    if (!trigger && scanner.status !== "success") {
      trigger = {
        fixtureId,
        mode: scanner.mode,
        expectedReason: [
          "Strict live paid gate stopped physical agent scheduling",
          `after ${fixtureId}/${scanner.mode}`,
          `cell status ${scanner.status}`,
        ].join(": "),
      };
    }

    for (const mode of agentModes) {
      const agent = findCell(fixtureId, mode);
      const agentBinding = bindingFor(agent);
      const hybridMode = Object.entries(HYBRID_SOURCES).find(
        ([, sources]) => sources[1] === mode,
      )?.[0];
      const hybrid = findCell(fixtureId, hybridMode);
      const hybridBinding = bindingFor(hybrid);

      if (trigger) {
        if (
          agentBinding.failFastPlaceholder !== true ||
          agent.status !== "canceled" ||
          !zeroCellCost(agent.cost) ||
          hybrid.physical ||
          hybrid.status !== "canceled" ||
          !zeroCellCost(hybrid.cost)
        ) {
          throw new SummaryError(
            `${mode}/${fixtureId} must be a validated agent/hybrid placeholder after the reconstructed live paid-gate trigger.`,
          );
        }
        const reason = agentBinding.failFastReason;
        if (
          typeof reason !== "string" ||
          reason !== trigger.expectedReason ||
          hybridBinding.strictLiveGateReasons.length !== 1 ||
          hybridBinding.strictLiveGateReasons[0] !== reason
        ) {
          throw new SummaryError(
            `${mode}/${fixtureId} fail-fast reason does not bind the reconstructed trigger ${trigger.fixtureId}/${trigger.mode}.`,
          );
        }
        strictReason ??= reason;
        if (reason !== strictReason) {
          throw new SummaryError(
            "live fail-fast placeholders do not share one immutable trigger reason.",
          );
        }
        continue;
      }

      if (
        agentBinding.failFastPlaceholder === true ||
        !agent.physical ||
        hybrid.physical ||
        agentBinding.strictLiveGateReasons.length !== 0 ||
        hybridBinding.strictLiveGateReasons.length !== 0
      ) {
        throw new SummaryError(
          `${mode}/${fixtureId} is a fail-fast placeholder before any canonical scheduling trigger.`,
        );
      }
      const trace = agentBinding.modelCallTrace;
      if (
        agent.status !== "success" ||
        trace.detectorStatus !== "completed" ||
        trace.calls.some(
          (call) => call.terminalState !== "succeeded",
        )
      ) {
        trigger = {
          fixtureId,
          mode,
          expectedReason: reconstructedAgentGateReason(
            agent,
            agentBinding,
          ),
        };
      }
    }
  }
}

function reconstructedAgentGateReason(cell, binding) {
  const failures = [];
  const detectorStatus = binding.hasAgentEvidence
    ? binding.modelCallTrace.detectorStatus
    : "unavailable";
  if (detectorStatus !== "completed") {
    failures.push(`detector status ${detectorStatus}`);
  }
  if (cell.status !== "success") {
    failures.push(`cell status ${cell.status}`);
  }
  const nonSucceededCalls = binding.modelCalls.filter(
    (call) => call.terminalState !== "succeeded",
  );
  if (nonSucceededCalls.length > 0) {
    failures.push(
      `${nonSucceededCalls.length} physical model call(s) did not succeed`,
    );
  }
  if (failures.length === 0) {
    throw new SummaryError(
      `${cell.mode}/${cell.fixtureId} was selected as a live paid-gate trigger without a canonical failure.`,
    );
  }
  return [
    "Strict live paid gate stopped additional physical agent scheduling",
    `after ${cell.fixtureId}/${cell.mode}`,
    failures.join("; "),
  ].join(": ");
}

function validateCanonicalCellCosts(cellsByMode, experimentSummary) {
  let actualPhysicalNanoUsd = 0;
  let committedPhysicalNanoUsd = 0;
  for (const mode of MODES) {
    const modeLimitNanoUsd = usdToNanoUsd(
      MODE_BUDGET_USD[mode],
      `${mode} canonical budget`,
    );
    for (const cell of cellsByMode.get(mode)) {
      const cost = cell.cost;
      const actualNanoUsd = usdToNanoUsd(
        cost.actualPhysicalSpendUsd,
        `${mode} actual physical spend`,
      );
      const committedNanoUsd = usdToNanoUsd(
        cost.conservativeCommittedUsd,
        `${mode} conservative committed spend`,
      );
      const attributedNanoUsd = usdToNanoUsd(
        cost.attributedCostUsd,
        `${mode} attributed spend`,
      );
      for (const [label, amount] of [
        ["actual physical", actualNanoUsd],
        ["conservative committed", committedNanoUsd],
        ["attributed", attributedNanoUsd],
      ]) {
        if (amount > modeLimitNanoUsd) {
          throw new SummaryError(
            `${mode} ${label} spend exceeds the canonical USD ${MODE_BUDGET_USD[mode]} per-cell ceiling.`,
          );
        }
      }
      if (cell.physical) {
        actualPhysicalNanoUsd += actualNanoUsd;
        committedPhysicalNanoUsd += committedNanoUsd;
        if (mode === "scanner-only") {
          for (const [label, value] of Object.entries(cost)) {
            expectEqual(value, 0, `scanner-only ${label}`);
          }
        } else {
          expectEqual(
            attributedNanoUsd,
            Math.max(actualNanoUsd, committedNanoUsd),
            `${mode} physical attributed cost`,
          );
          expectEqual(
            cost.attributedModelCalls,
            cost.physicalModelCalls,
            `${mode} physical attributed calls`,
          );
          expectEqual(
            cost.attributedTokens,
            cost.physicalTokens,
            `${mode} physical attributed tokens`,
          );
        }
        continue;
      }
      const sourceMode = HYBRID_SOURCES[mode]?.[1];
      const sourceCell = cellsByMode
        .get(sourceMode)
        .find((candidate) => candidate.fixtureId === cell.fixtureId);
      if (!sourceCell) {
        throw new SummaryError(
          `${mode} cannot resolve its physical agent cost source.`,
        );
      }
      expectEqual(
        attributedNanoUsd,
        usdToNanoUsd(
          sourceCell.cost.attributedCostUsd,
          `${sourceMode} source attributed spend`,
        ),
        `${mode} hybrid attributed cost`,
      );
      expectEqual(
        cost.attributedModelCalls,
        sourceCell.cost.attributedModelCalls,
        `${mode} hybrid attributed calls`,
      );
      expectEqual(
        cost.attributedTokens,
        sourceCell.cost.attributedTokens,
        `${mode} hybrid attributed tokens`,
      );
    }
  }
  if (
    actualPhysicalNanoUsd > GLOBAL_BUDGET_NANO_USD ||
    committedPhysicalNanoUsd > GLOBAL_BUDGET_NANO_USD
  ) {
    throw new SummaryError(
      `physical suite spend exceeds the canonical global USD ${GLOBAL_BUDGET_USD} ceiling.`,
    );
  }
  expectEqual(
    actualPhysicalNanoUsd,
    usdToNanoUsd(
      experimentSummary.actualPhysicalSpendUsd,
      "experiment actual physical spend",
    ),
    "canonical experiment actual physical spend",
  );
  expectEqual(
    committedPhysicalNanoUsd,
    usdToNanoUsd(
      experimentSummary.conservativeCommittedUsd,
      "experiment conservative committed spend",
    ),
    "canonical experiment conservative committed spend",
  );
}

function readCellCost(value, label) {
  const cost = objectValue(value, label);
  return {
    actualPhysicalSpendUsd: nonNegativeNumber(
      cost.actualPhysicalSpendUsd,
      `${label} actualPhysicalSpendUsd`,
    ),
    conservativeCommittedUsd: nonNegativeNumber(
      cost.conservativeCommittedUsd,
      `${label} conservativeCommittedUsd`,
    ),
    attributedCostUsd: nonNegativeNumber(
      cost.attributedCostUsd,
      `${label} attributedCostUsd`,
    ),
    physicalModelCalls: nonNegativeInteger(
      cost.physicalModelCalls,
      `${label} physicalModelCalls`,
    ),
    attributedModelCalls: nonNegativeInteger(
      cost.attributedModelCalls,
      `${label} attributedModelCalls`,
    ),
    physicalTokens: nonNegativeInteger(
      cost.physicalTokens,
      `${label} physicalTokens`,
    ),
    attributedTokens: nonNegativeInteger(
      cost.attributedTokens,
      `${label} attributedTokens`,
    ),
  };
}

function aggregateCellCosts(cells) {
  return cells.reduce(
    (output, cell) => {
      output.actualPhysicalSpendUsd += cell.cost.actualPhysicalSpendUsd;
      output.conservativeCommittedUsd +=
        cell.cost.conservativeCommittedUsd;
      output.attributedCostUsd += cell.cost.attributedCostUsd;
      output.physicalModelCalls += cell.cost.physicalModelCalls;
      output.attributedModelCalls += cell.cost.attributedModelCalls;
      output.physicalTokens += cell.cost.physicalTokens;
      output.attributedTokens += cell.cost.attributedTokens;
      output.physicalCellCount += cell.physical ? 1 : 0;
      output.derivedCellCount += cell.physical ? 0 : 1;
      return output;
    },
    {
      actualPhysicalSpendUsd: 0,
      conservativeCommittedUsd: 0,
      attributedCostUsd: 0,
      physicalModelCalls: 0,
      attributedModelCalls: 0,
      physicalTokens: 0,
      attributedTokens: 0,
      physicalCellCount: 0,
      derivedCellCount: 0,
    },
  );
}

function readEvaluationTruth(value, fixtureId, label) {
  const truth = objectValue(value, label);
  expectEqual(truth.schemaVersion, "2.0", `${label} schemaVersion`);
  expectEqual(truth.fixtureId, fixtureId, `${label} fixtureId`);
  const findings = arrayValue(truth.findings, `${label} findings`).map(
    (finding, index) =>
      readClassifiableFinding(
        finding,
        `${label} finding ${index}`,
        "ground-truth",
      ),
  );
  assertUniqueValues(
    findings.map((finding) => finding.id),
    `${label} finding IDs`,
  );
  return { raw: truth, findings };
}

function readMatchResult(value, label) {
  const result = objectValue(value, label);
  const matches = arrayValue(result.matches, `${label} matches`).map(
    (candidate, index) =>
      readMatchCandidate(candidate, `${label} match ${index}`, true),
  );
  const rejectedCandidates = arrayValue(
    result.rejectedCandidates,
    `${label} rejectedCandidates`,
  ).map((candidate, index) =>
    readMatchCandidate(
      candidate,
      `${label} rejectedCandidate ${index}`,
      false,
    ),
  );
  const falsePositives = arrayValue(
    result.falsePositives,
    `${label} falsePositives`,
  ).map((finding, index) =>
    readClassifiableFinding(
      finding,
      `${label} falsePositive ${index}`,
      "actual",
    ),
  );
  const falseNegatives = arrayValue(
    result.falseNegatives,
    `${label} falseNegatives`,
  ).map((finding, index) =>
    readClassifiableFinding(
      finding,
      `${label} falseNegative ${index}`,
      "ground-truth",
    ),
  );
  const ignoredActual = arrayValue(
    result.ignoredActual,
    `${label} ignoredActual`,
  ).map((candidate, index) => {
    const ignored = objectValue(
      candidate,
      `${label} ignoredActual ${index}`,
    );
    expectEqual(
      ignored.reason,
      "duplicate",
      `${label} ignoredActual ${index} reason`,
    );
    return {
      raw: ignored,
      id: requiredString(
        ignored.id,
        `${label} ignoredActual ${index} id`,
      ),
      fingerprint: requiredString(
        ignored.fingerprint,
        `${label} ignoredActual ${index} fingerprint`,
      ),
      category: oneOf(
        ignored.category,
        EVAL_CATEGORIES,
        `${label} ignoredActual ${index} category`,
      ),
      duplicateOfId: requiredString(
        ignored.duplicateOfId,
        `${label} ignoredActual ${index} duplicateOfId`,
      ),
      duplicateOfFingerprint: requiredString(
        ignored.duplicateOfFingerprint,
        `${label} ignoredActual ${index} duplicateOfFingerprint`,
      ),
      noiseKey: requiredString(
        ignored.noiseKey,
        `${label} ignoredActual ${index} noiseKey`,
      ),
    };
  });
  const thresholds = objectValue(result.thresholds, `${label} thresholds`);
  nonNegativeNumber(
    thresholds.minMatchScore,
    `${label} thresholds minMatchScore`,
  );
  nonNegativeInteger(
    thresholds.defaultLineTolerance,
    `${label} thresholds defaultLineTolerance`,
  );
  oneOf(
    thresholds.severityTolerance,
    ["exact", "one-step", "category-only"],
    `${label} thresholds severityTolerance`,
  );
  oneOf(
    thresholds.cweTolerance,
    ["exact", "alias", "weakness-family"],
    `${label} thresholds cweTolerance`,
  );
  const trueNegative = booleanValue(
    result.trueNegative,
    `${label} trueNegative`,
  );
  expectEqual(
    trueNegative,
    matches.length === 0 &&
      falsePositives.length === 0 &&
      falseNegatives.length === 0,
    `${label} trueNegative evidence`,
  );
  assertUniqueValues(
    matches.map((match) => match.expectedId),
    `${label} matched expected IDs`,
  );
  assertUniqueValues(
    matches.map((match) => match.actualId),
    `${label} matched actual IDs`,
  );
  assertUniqueValues(
    falsePositives.map((finding) => finding.id),
    `${label} false-positive IDs`,
  );
  assertUniqueValues(
    falseNegatives.map((finding) => finding.id),
    `${label} false-negative IDs`,
  );
  assertUniqueValues(
    ignoredActual.map((finding) => finding.id),
    `${label} ignored actual IDs`,
  );
  return {
    raw: result,
    matches,
    rejectedCandidates,
    falsePositives,
    falseNegatives,
    ignoredActual,
    trueNegative,
  };
}

function readMatchCandidate(value, label, accepted) {
  const candidate = objectValue(value, label);
  if (accepted) {
    expectEqual(candidate.accepted, true, `${label} accepted`);
  } else if (candidate.accepted !== undefined) {
    throw new SummaryError(
      `${label} must not be marked as an accepted match.`,
    );
  }
  const expectedVulnerabilityClass = optionalVulnerabilityClass(
    candidate.expectedVulnerabilityClass,
    `${label} expectedVulnerabilityClass`,
  );
  const actualVulnerabilityClass = optionalVulnerabilityClass(
    candidate.actualVulnerabilityClass,
    `${label} actualVulnerabilityClass`,
  );
  const actualDisposition =
    candidate.actualDisposition === undefined
      ? undefined
      : oneOf(
          candidate.actualDisposition,
          ["accepted", "rejected", "needs-review"],
          `${label} actualDisposition`,
        );
  const signals = arrayValue(candidate.signals, `${label} signals`);
  for (const [index, signalCandidate] of signals.entries()) {
    const signal = objectValue(signalCandidate, `${label} signal ${index}`);
    requiredString(signal.name, `${label} signal ${index} name`);
    nonNegativeNumber(signal.points, `${label} signal ${index} points`);
    requiredString(
      signal.explanation,
      `${label} signal ${index} explanation`,
    );
  }
  const score = nonNegativeNumber(candidate.score, `${label} score`);
  const evidenceScore = nonNegativeNumber(
    candidate.evidenceScore,
    `${label} evidenceScore`,
  );
  const eligible = booleanValue(candidate.eligible, `${label} eligible`);
  const rejectionReasons = stringArray(
    candidate.rejectionReasons,
    `${label} rejectionReasons`,
  );
  if (accepted) {
    expectEqual(eligible, true, `${label} accepted eligibility`);
    expectEqual(
      rejectionReasons.length,
      0,
      `${label} accepted rejection reason count`,
    );
    nearlyEqual(score, evidenceScore, `${label} accepted score`);
  }
  return {
    raw: candidate,
    expectedId: requiredString(candidate.expectedId, `${label} expectedId`),
    actualId: requiredString(candidate.actualId, `${label} actualId`),
    actualFingerprint: requiredString(
      candidate.actualFingerprint,
      `${label} actualFingerprint`,
    ),
    expectedCategory: oneOf(
      candidate.expectedCategory,
      EVAL_CATEGORIES,
      `${label} expectedCategory`,
    ),
    actualCategory: oneOf(
      candidate.actualCategory,
      EVAL_CATEGORIES,
      `${label} actualCategory`,
    ),
    expectedVulnerabilityClass,
    actualVulnerabilityClass,
    actualDisposition,
    score,
    evidenceScore,
    eligible,
    rejectionReasons,
  };
}

function readClassifiableFinding(value, label, kind) {
  const finding = objectValue(value, label);
  const identifiers = objectValue(
    finding.identifiers,
    `${label} identifiers`,
  );
  stringArray(identifiers.cve, `${label} identifiers cve`);
  stringArray(identifiers.ghsa, `${label} identifiers ghsa`);
  stringArray(identifiers.osv, `${label} identifiers osv`);
  const category = oneOf(
    finding.category,
    EVAL_CATEGORIES,
    `${label} category`,
  );
  const vulnerabilityClass = optionalVulnerabilityClass(
    finding.vulnerabilityClass,
    `${label} vulnerabilityClass`,
  );
  const output = {
    raw: finding,
    id: requiredString(finding.id, `${label} id`),
    category,
    vulnerabilityClass,
    title: requiredString(finding.title, `${label} title`),
    cwe: stringArray(finding.cwe, `${label} cwe`),
    ruleIds:
      finding.ruleIds === undefined && kind !== "actual"
        ? []
        : stringArray(finding.ruleIds, `${label} ruleIds`),
  };
  if (kind === "actual") {
    output.fingerprint = requiredString(
      finding.fingerprint,
      `${label} fingerprint`,
    );
  }
  return output;
}

function optionalVulnerabilityClass(value, label) {
  if (value === undefined) {
    return undefined;
  }
  const vulnerabilityClass = requiredString(value, label);
  const normalized = normalizeVulnerabilityClass(vulnerabilityClass);
  if (normalized !== vulnerabilityClass) {
    throw new SummaryError(`${label} must be normalized.`);
  }
  return vulnerabilityClass;
}

function validateTruthMatchBinding(truthFindings, matchResult, label) {
  const truthById = new Map(
    truthFindings.map((finding) => [finding.id, finding]),
  );
  const representedExpectedIds = [
    ...matchResult.matches.map((match) => match.expectedId),
    ...matchResult.falseNegatives.map((finding) => finding.id),
  ];
  assertUniqueValues(representedExpectedIds, `${label} represented truth IDs`);
  expectStringArraysEqual(
    [...representedExpectedIds].sort(compareText),
    [...truthById.keys()].sort(compareText),
    `${label} truth/match partition`,
  );
  for (const match of matchResult.matches) {
    const truth = truthById.get(match.expectedId);
    if (!truth) {
      throw new SummaryError(
        `${label} accepted match references unknown ground truth.`,
      );
    }
    expectEqual(
      match.expectedCategory,
      truth.category,
      `${label} accepted match category`,
    );
    expectEqual(
      match.expectedVulnerabilityClass,
      inferPrimaryVulnerabilityClass(truth),
      `${label} accepted match vulnerability class`,
    );
  }
  for (const falseNegative of matchResult.falseNegatives) {
    const truth = truthById.get(falseNegative.id);
    if (!truth) {
      throw new SummaryError(
        `${label} false negative references unknown ground truth.`,
      );
    }
    canonicalEqual(
      falseNegative.raw,
      truth.raw,
      `${label} false-negative truth finding`,
    );
  }
}

function deriveEvaluationMetrics(matchResults) {
  const truePositive = matchResults.reduce(
    (total, result) => total + result.matches.length,
    0,
  );
  const falsePositive = matchResults.reduce(
    (total, result) => total + result.falsePositives.length,
    0,
  );
  const falseNegative = matchResults.reduce(
    (total, result) => total + result.falseNegatives.length,
    0,
  );
  const classCounts = new Map();
  for (const result of matchResults) {
    for (const match of result.matches) {
      if (match.expectedVulnerabilityClass) {
        ensureClassCounts(
          classCounts,
          match.expectedVulnerabilityClass,
        ).truePositive += 1;
      }
      if (match.actualVulnerabilityClass) {
        ensureClassCounts(classCounts, match.actualVulnerabilityClass);
      }
    }
    for (const finding of result.falseNegatives) {
      const vulnerabilityClass =
        inferPrimaryVulnerabilityClass(finding) ??
        UNCLASSIFIED_VULNERABILITY_CLASS;
      ensureClassCounts(
        classCounts,
        vulnerabilityClass,
      ).falseNegative += 1;
    }
    for (const finding of result.falsePositives) {
      const vulnerabilityClass =
        inferPrimaryVulnerabilityClass(finding) ??
        UNCLASSIFIED_VULNERABILITY_CLASS;
      ensureClassCounts(
        classCounts,
        vulnerabilityClass,
      ).falsePositive += 1;
    }
  }
  const classMetrics = [...classCounts.entries()]
    .sort(([left], [right]) => compareText(left, right))
    .map(([vulnerabilityClass, counts]) => ({
      vulnerabilityClass,
      ...metricsFromCounts(
        counts.truePositive,
        counts.falsePositive,
        counts.falseNegative,
        true,
      ),
    }));
  const supported = classMetrics.filter(
    (metric) => metric.categorySupport > 0,
  );
  const truthSupport = supported.reduce(
    (total, metric) => total + metric.categorySupport,
    0,
  );
  const classSummary = {
    supportedMacroF1:
      supported.length === 0
        ? 0
        : supported.reduce((total, metric) => total + metric.f1, 0) /
          supported.length,
    supportedWeightedF1:
      truthSupport === 0
        ? 0
        : supported.reduce(
            (total, metric) =>
              total + metric.f1 * metric.categorySupport,
            0,
          ) / truthSupport,
    supportedGroupCount: supported.length,
    truthSupport,
  };
  return {
    metrics: {
      ...metricsFromCounts(
        truePositive,
        falsePositive,
        falseNegative,
        false,
      ),
      classMacroF1: classSummary.supportedMacroF1,
      classWeightedF1: classSummary.supportedWeightedF1,
    },
    classMetrics,
    classSummary,
  };
}

function ensureClassCounts(counts, vulnerabilityClass) {
  const existing = counts.get(vulnerabilityClass);
  if (existing) {
    return existing;
  }
  const created = {
    truePositive: 0,
    falsePositive: 0,
    falseNegative: 0,
  };
  counts.set(vulnerabilityClass, created);
  return created;
}

function metricsFromCounts(
  truePositive,
  falsePositive,
  falseNegative,
  grouped,
) {
  const precision = ratio(truePositive, truePositive + falsePositive);
  const recall = ratio(truePositive, truePositive + falseNegative);
  const f1 =
    precision + recall === 0
      ? 0
      : (2 * precision * recall) / (precision + recall);
  return {
    totalExpected: truePositive + falseNegative,
    totalActual: truePositive + falsePositive,
    precision,
    recall,
    f1,
    truePositive,
    falsePositive,
    falseNegative,
    ...(grouped
      ? { categorySupport: truePositive + falseNegative }
      : {}),
  };
}

function validateDerivedMetricClaims(
  claimedMetrics,
  claimedClassMetrics,
  claimedClassSummary,
  derived,
  label,
) {
  validateMetricClaim(claimedMetrics, derived.metrics, `${label} metrics`);
  expectEqual(
    claimedClassMetrics.length,
    derived.classMetrics.length,
    `${label} class metric count`,
  );
  for (const [index, claimed] of claimedClassMetrics.entries()) {
    const expected = derived.classMetrics[index];
    expectEqual(
      claimed.vulnerabilityClass,
      expected.vulnerabilityClass,
      `${label} class metric name`,
    );
    validateMetricClaim(
      claimed,
      expected,
      `${label} class ${expected.vulnerabilityClass}`,
    );
    expectEqual(
      claimed.categorySupport,
      expected.categorySupport,
      `${label} class ${expected.vulnerabilityClass} categorySupport`,
    );
  }
  for (const key of [
    "supportedGroupCount",
    "truthSupport",
  ]) {
    expectEqual(
      claimedClassSummary[key],
      derived.classSummary[key],
      `${label} class summary ${key}`,
    );
  }
  for (const key of [
    "supportedMacroF1",
    "supportedWeightedF1",
  ]) {
    nearlyEqual(
      claimedClassSummary[key],
      derived.classSummary[key],
      `${label} class summary ${key}`,
    );
  }
  nearlyEqual(
    claimedMetrics.classMacroF1,
    derived.classSummary.supportedMacroF1,
    `${label} class macro F1`,
  );
  nearlyEqual(
    claimedMetrics.classWeightedF1,
    derived.classSummary.supportedWeightedF1,
    `${label} class weighted F1`,
  );
}

function validateMetricClaim(claimed, derived, label) {
  for (const key of [
    "truePositive",
    "falsePositive",
    "falseNegative",
    "totalExpected",
    "totalActual",
  ]) {
    expectEqual(claimed[key], derived[key], `${label} ${key}`);
  }
  for (const key of ["precision", "recall", "f1"]) {
    nearlyEqual(claimed[key], derived[key], `${label} ${key}`);
  }
}

function readOverallMetrics(value, label) {
  const metrics = objectValue(value, label);
  const output = {
    precision: probability(metrics.precision, `${label} precision`),
    recall: probability(metrics.recall, `${label} recall`),
    f1: probability(metrics.f1, `${label} f1`),
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
    classMacroF1: probability(metrics.macroF1, `${label} macroF1`),
    classWeightedF1: probability(
      metrics.weightedF1,
      `${label} weightedF1`,
    ),
    totalExpected: nonNegativeInteger(
      metrics.totalExpected,
      `${label} totalExpected`,
    ),
    totalActual: nonNegativeInteger(
      metrics.totalActual,
      `${label} totalActual`,
    ),
  };
  validateMetricArithmetic(output, label);
  return output;
}

function readClassMetrics(value, label) {
  const metrics = objectValue(value, label);
  return Object.keys(metrics)
    .sort(compareText)
    .map((name) => {
      const safeName = safeOutputString(name, `${label} class name`);
      const classMetric = objectValue(metrics[name], `${label} ${safeName}`);
      const output = {
        vulnerabilityClass: safeName,
        precision: probability(
          classMetric.precision,
          `${label} ${safeName} precision`,
        ),
        recall: probability(
          classMetric.recall,
          `${label} ${safeName} recall`,
        ),
        f1: probability(classMetric.f1, `${label} ${safeName} f1`),
        truePositive: nonNegativeInteger(
          classMetric.truePositive,
          `${label} ${safeName} truePositive`,
        ),
        falsePositive: nonNegativeInteger(
          classMetric.falsePositive,
          `${label} ${safeName} falsePositive`,
        ),
        falseNegative: nonNegativeInteger(
          classMetric.falseNegative,
          `${label} ${safeName} falseNegative`,
        ),
        totalExpected: nonNegativeInteger(
          classMetric.totalExpected,
          `${label} ${safeName} totalExpected`,
        ),
        totalActual: nonNegativeInteger(
          classMetric.totalActual,
          `${label} ${safeName} totalActual`,
        ),
        categorySupport: nonNegativeInteger(
          classMetric.categorySupport,
          `${label} ${safeName} categorySupport`,
        ),
      };
      validateMetricArithmetic(output, `${label} ${safeName}`);
      expectEqual(
        output.categorySupport,
        output.truePositive + output.falseNegative,
        `${label} ${safeName} categorySupport`,
      );
      return output;
    });
}

function readClassSummary(value, label) {
  const summary = objectValue(value, label);
  return {
    supportedMacroF1: probability(
      summary.supportedMacroF1,
      `${label} supportedMacroF1`,
    ),
    supportedWeightedF1: probability(
      summary.supportedWeightedF1,
      `${label} supportedWeightedF1`,
    ),
    supportedGroupCount: nonNegativeInteger(
      summary.supportedGroupCount,
      `${label} supportedGroupCount`,
    ),
    truthSupport: nonNegativeInteger(
      summary.truthSupport,
      `${label} truthSupport`,
    ),
  };
}

function validateMetricArithmetic(metric, label) {
  expectEqual(
    metric.totalExpected,
    metric.truePositive + metric.falseNegative,
    `${label} totalExpected`,
  );
  expectEqual(
    metric.totalActual,
    metric.truePositive + metric.falsePositive,
    `${label} totalActual`,
  );
  const expectedPrecision = ratio(
    metric.truePositive,
    metric.truePositive + metric.falsePositive,
  );
  const expectedRecall = ratio(
    metric.truePositive,
    metric.truePositive + metric.falseNegative,
  );
  const expectedF1 =
    expectedPrecision + expectedRecall === 0
      ? 0
      : (2 * expectedPrecision * expectedRecall) /
        (expectedPrecision + expectedRecall);
  nearlyEqual(metric.precision, expectedPrecision, `${label} precision`);
  nearlyEqual(metric.recall, expectedRecall, `${label} recall`);
  nearlyEqual(metric.f1, expectedF1, `${label} F1`);
}

function ratio(numerator, denominator) {
  return denominator === 0 ? 0 : numerator / denominator;
}

function inferPrimaryVulnerabilityClass(finding) {
  const classes = resolveVulnerabilityClasses(finding);
  if (finding.vulnerabilityClass) {
    const explicit = normalizeVulnerabilityClass(
      finding.vulnerabilityClass,
    );
    if (classes.includes(explicit)) {
      return explicit;
    }
  }
  if (classes.length === 0) {
    return undefined;
  }
  if (
    finding.category === "secret" &&
    classes.includes("hardcoded-secret")
  ) {
    return "hardcoded-secret";
  }
  const parentClasses = new Set(Object.values(CLASS_PARENTS));
  return (
    classes.find((entry) => !parentClasses.has(entry)) ?? classes[0]
  );
}

function resolveVulnerabilityClasses(finding) {
  const classes = new Set();
  if (finding.vulnerabilityClass) {
    addClassWithParent(classes, finding.vulnerabilityClass);
  }
  for (const value of finding.cwe ?? []) {
    const match = value.trim().match(/cwe[-_\s:]*(\d+)/iu);
    const numeric = match?.[1]
      ? Number.parseInt(match[1], 10)
      : Number.NaN;
    if (Number.isFinite(numeric) && numeric > 0) {
      const mapped = CWE_CLASSES[`CWE-${numeric}`];
      if (mapped) {
        addClassWithParent(classes, mapped);
      }
    }
  }
  const searchable = [
    finding.title,
    ...(finding.ruleIds ?? []),
  ].join(" ");
  for (const [pattern, vulnerabilityClass] of CLASS_TEXT_PATTERNS) {
    if (pattern.test(searchable)) {
      addClassWithParent(classes, vulnerabilityClass);
    }
  }
  if (finding.category === "dependency") {
    classes.add("known-vulnerable-dependency");
  }
  return [...classes].sort(compareText);
}

function addClassWithParent(classes, value) {
  const normalized = normalizeVulnerabilityClass(value);
  if (!normalized) {
    return;
  }
  classes.add(normalized);
  const parent = CLASS_PARENTS[normalized];
  if (parent) {
    classes.add(parent);
  }
}

function normalizeVulnerabilityClass(value) {
  return value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/gu, "-")
    .replace(/^-+|-+$/gu, "");
}

function readCompleteness(value, label) {
  const completeness = objectValue(value, label);
  const plannedComponentCount = nonNegativeInteger(
    completeness.plannedComponentCount,
    `${label} plannedComponentCount`,
  );
  const completedComponentCount = nonNegativeInteger(
    completeness.completedComponentCount,
    `${label} completedComponentCount`,
  );
  if (completedComponentCount > plannedComponentCount) {
    throw new SummaryError(
      `${label} completedComponentCount exceeds plannedComponentCount.`,
    );
  }
  const failedComponents = stringArray(
    completeness.failedComponents,
    `${label} failedComponents`,
  );
  const skippedComponents = stringArray(
    completeness.skippedComponents,
    `${label} skippedComponents`,
  );
  const unsupportedLanguages = stringArray(
    completeness.unsupportedLanguages,
    `${label} unsupportedLanguages`,
  );
  const degradedReasons = stringArray(
    completeness.degradedReasons,
    `${label} degradedReasons`,
  );
  return {
    status: oneOf(
      completeness.status,
      COMPLETENESS_STATUSES,
      `${label} status`,
    ),
    plannedComponentCount,
    completedComponentCount,
    failedComponents,
    failedComponentCount: failedComponents.length,
    skippedComponents,
    skippedComponentCount: skippedComponents.length,
    componentCompletionRate: probability(
      completeness.componentCompletionRate,
      `${label} componentCompletionRate`,
    ),
    eligibleFiles: nullableNonNegativeInteger(
      completeness.eligibleFiles,
      `${label} eligibleFiles`,
    ),
    inspectedFiles: nullableNonNegativeInteger(
      completeness.inspectedFiles,
      `${label} inspectedFiles`,
    ),
    fileCoverage: nullableProbability(
      completeness.fileCoverage,
      `${label} fileCoverage`,
    ),
    inspectedBytes: nonNegativeInteger(
      completeness.inspectedBytes,
      `${label} inspectedBytes`,
    ),
    unsupportedLanguages,
    unsupportedLanguageCount: unsupportedLanguages.length,
    degradedReasons,
    degradedReasonCount: degradedReasons.length,
  };
}

function readCompletenessInput(value, label, defaultEligibleFiles) {
  const input = objectValue(value, label);
  const output = {
    plannedComponents: stringArray(
      input.plannedComponents,
      `${label} plannedComponents`,
    ),
    completedComponents: stringArray(
      input.completedComponents,
      `${label} completedComponents`,
    ),
    ...(input.failedComponents === undefined
      ? {}
      : {
          failedComponents: stringArray(
            input.failedComponents,
            `${label} failedComponents`,
          ),
        }),
    ...(input.skippedComponents === undefined
      ? {}
      : {
          skippedComponents: stringArray(
            input.skippedComponents,
            `${label} skippedComponents`,
          ),
        }),
    eligibleFiles:
      input.eligibleFiles === undefined
        ? defaultEligibleFiles
        : nonNegativeInteger(input.eligibleFiles, `${label} eligibleFiles`),
    ...(input.inspectedFiles === undefined
      ? {}
      : {
          inspectedFiles: nonNegativeInteger(
            input.inspectedFiles,
            `${label} inspectedFiles`,
          ),
        }),
    ...(input.inspectedBytes === undefined
      ? {}
      : {
          inspectedBytes: nonNegativeInteger(
            input.inspectedBytes,
            `${label} inspectedBytes`,
          ),
        }),
    ...(input.unsupportedLanguages === undefined
      ? {}
      : {
          unsupportedLanguages: stringArray(
            input.unsupportedLanguages,
            `${label} unsupportedLanguages`,
          ),
        }),
    ...(input.degradedReasons === undefined
      ? {}
      : {
          degradedReasons: stringArray(
            input.degradedReasons,
            `${label} degradedReasons`,
          ),
        }),
  };
  return output;
}

function validateComputedCompleteness(input, computed, label) {
  const expected = deriveCompleteness(input);
  expectEqual(computed.status, expected.status, `${label} computed status`);
  expectEqual(
    computed.plannedComponentCount,
    expected.plannedComponentCount,
    `${label} planned component count`,
  );
  expectEqual(
    computed.completedComponentCount,
    expected.completedComponentCount,
    `${label} completed component count`,
  );
  expectEqual(
    computed.failedComponentCount,
    expected.failedComponentCount,
    `${label} failed component count`,
  );
  expectStringArraysEqual(
    computed.failedComponents,
    expected.failedComponents,
    `${label} failed components`,
  );
  expectEqual(
    computed.skippedComponentCount,
    expected.skippedComponentCount,
    `${label} skipped component count`,
  );
  expectStringArraysEqual(
    computed.skippedComponents,
    expected.skippedComponents,
    `${label} skipped components`,
  );
  nearlyEqual(
    computed.componentCompletionRate,
    expected.componentCompletionRate,
    `${label} component completion rate`,
  );
  expectEqual(
    computed.eligibleFiles,
    expected.eligibleFiles,
    `${label} eligible files`,
  );
  expectEqual(
    computed.inspectedFiles,
    expected.inspectedFiles,
    `${label} inspected files`,
  );
  if (
    computed.fileCoverage === null ||
    expected.fileCoverage === null
  ) {
    expectEqual(
      computed.fileCoverage,
      expected.fileCoverage,
      `${label} file coverage`,
    );
  } else {
    nearlyEqual(
      computed.fileCoverage,
      expected.fileCoverage,
      `${label} file coverage`,
    );
  }
  expectEqual(
    computed.inspectedBytes,
    expected.inspectedBytes,
    `${label} inspected bytes`,
  );
  expectEqual(
    computed.unsupportedLanguageCount,
    expected.unsupportedLanguageCount,
    `${label} unsupported language count`,
  );
  expectStringArraysEqual(
    computed.unsupportedLanguages,
    expected.unsupportedLanguages,
    `${label} unsupported languages`,
  );
  expectEqual(
    computed.degradedReasonCount,
    expected.degradedReasonCount,
    `${label} degradation reason count`,
  );
  expectStringArraysEqual(
    computed.degradedReasons,
    expected.degradedReasons,
    `${label} degraded reasons`,
  );
}

function deriveCompleteness(input) {
  const planned = uniqueSorted(input.plannedComponents);
  const completed = new Set(uniqueSorted(input.completedComponents));
  const failed = uniqueSorted(input.failedComponents ?? []);
  const skipped = uniqueSorted(input.skippedComponents ?? []);
  const unsupported = uniqueSorted(input.unsupportedLanguages ?? []);
  const degradedReasons = uniqueSorted(input.degradedReasons ?? []);
  const completedCount = planned.filter((entry) => completed.has(entry)).length;
  const eligibleFiles = input.eligibleFiles ?? null;
  const inspectedFiles = input.inspectedFiles ?? null;
  const fileCoverage =
    eligibleFiles !== null &&
    eligibleFiles > 0 &&
    inspectedFiles !== null
      ? Math.min(1, inspectedFiles / eligibleFiles)
      : eligibleFiles === 0 && inspectedFiles === 0
        ? 1
        : null;
  const completionRate =
    planned.length > 0 ? completedCount / planned.length : 1;
  const degraded =
    failed.length > 0 ||
    unsupported.length > 0 ||
    degradedReasons.length > 0;
  const partial =
    skipped.length > 0 ||
    completionRate < 1 ||
    (fileCoverage !== null && fileCoverage < 1);
  const status = degraded ? "degraded" : partial ? "partial" : "complete";
  return {
    status,
    plannedComponentCount: planned.length,
    completedComponentCount: completedCount,
    failedComponents: failed,
    failedComponentCount: failed.length,
    skippedComponents: skipped,
    skippedComponentCount: skipped.length,
    componentCompletionRate: completionRate,
    eligibleFiles,
    inspectedFiles,
    fileCoverage,
    inspectedBytes:
      (input.inspectedBytes ?? 0) > 0 ? input.inspectedBytes : 0,
    unsupportedLanguages: unsupported,
    unsupportedLanguageCount: unsupported.length,
    degradedReasons,
    degradedReasonCount: degradedReasons.length,
  };
}

function validateAggregateCompleteness(cases, computed, mode) {
  const prefix = (fixtureId, values) =>
    values.map((value) => `${fixtureId}:${value}`);
  const inspectedFiles = cases.every(
    (entry) =>
      typeof entry.completenessInput.inspectedFiles === "number",
  )
    ? cases.reduce(
        (total, entry) =>
          total + (entry.completenessInput.inspectedFiles ?? 0),
        0,
      )
    : undefined;
  const aggregateInput = {
    plannedComponents: cases.flatMap((entry) =>
      prefix(
        entry.fixtureId,
        entry.completenessInput.plannedComponents,
      ),
    ),
    completedComponents: cases.flatMap((entry) =>
      prefix(
        entry.fixtureId,
        entry.completenessInput.completedComponents,
      ),
    ),
    failedComponents: cases.flatMap((entry) =>
      prefix(
        entry.fixtureId,
        entry.completenessInput.failedComponents ?? [],
      ),
    ),
    skippedComponents: cases.flatMap((entry) =>
      prefix(
        entry.fixtureId,
        entry.completenessInput.skippedComponents ?? [],
      ),
    ),
    eligibleFiles: cases.reduce(
      (total, entry) =>
        total + (entry.completenessInput.eligibleFiles ?? 0),
      0,
    ),
    ...(typeof inspectedFiles === "number" ? { inspectedFiles } : {}),
    inspectedBytes: cases.reduce(
      (total, entry) =>
        total + (entry.completenessInput.inspectedBytes ?? 0),
      0,
    ),
    unsupportedLanguages: uniqueSorted(
      cases.flatMap(
        (entry) =>
          entry.completenessInput.unsupportedLanguages ?? [],
      ),
    ),
    degradedReasons: cases
      .flatMap((entry) =>
        (entry.completenessInput.degradedReasons ?? []).map(
          (reason) => `${entry.fixtureId}:${reason}`,
        ),
      )
      .sort(compareText),
  };
  validateComputedCompleteness(
    aggregateInput,
    computed,
    `${mode} aggregate`,
  );
}

function uniqueSorted(values) {
  return [...new Set(values)].sort(compareText);
}

function validateStatusCompleteness(mode, cells, cases, runCompleteness) {
  const caseByFixture = new Map(
    cases.map((entry) => [entry.fixtureId, entry.completeness]),
  );
  for (const cell of cells) {
    const completeness = caseByFixture.get(cell.fixtureId);
    if (!completeness) {
      throw new SummaryError(
        `${mode}/${cell.fixtureId} has no evaluation completeness record.`,
      );
    }
    if (
      cell.status !== "success" &&
      completeness.status === "complete"
    ) {
      throw new SummaryError(
        `${mode}/${cell.fixtureId} is ${cell.status} but evaluation completeness is complete.`,
      );
    }
    if (
      (cell.status === "failed" ||
        cell.status === "canceled" ||
        cell.status === "degraded") &&
      completeness.status !== "degraded"
    ) {
      throw new SummaryError(
        `${mode}/${cell.fixtureId} status is not reflected by degraded completeness.`,
      );
    }
  }
  const statusCounts = countStatuses(cells);
  const incompleteCells =
    statusCounts.partial +
    statusCounts.degraded +
    statusCounts.canceled +
    statusCounts.failed;
  const incompleteCases = cases.filter(
    (entry) => entry.completeness.status !== "complete",
  ).length;
  if (
    (incompleteCells > 0 || incompleteCases > 0) &&
    runCompleteness.status === "complete"
  ) {
    throw new SummaryError(
      `${mode} aggregate completeness hides incomplete evidence.`,
    );
  }
  if (incompleteCells === 0 && incompleteCases === 0) {
    return "Complete evidence";
  }
  const parts = CELL_STATUSES.filter(
    (status) => status !== "success" && statusCounts[status] > 0,
  ).map((status) => `${status}:${statusCounts[status]}`);
  parts.push(`completeness:${runCompleteness.status}`);
  parts.push(`affected-cases:${incompleteCases}`);
  return `CAVEAT ${parts.join("; ")}`;
}

function countStatuses(cells) {
  const counts = emptyStatusCounts();
  for (const cell of cells) {
    counts[cell.status] += 1;
  }
  return counts;
}

function emptyStatusCounts() {
  return {
    success: 0,
    partial: 0,
    degraded: 0,
    canceled: 0,
    failed: 0,
  };
}

async function validateSuiteEvidence(input) {
  let suiteRoot;
  try {
    suiteRoot = await fs.realpath(input.suiteDirectory);
  } catch {
    throw new SummaryError("Unable to resolve the experiment suite directory.");
  }
  const indexPath = await resolveConfinedRegularFile(
    suiteRoot,
    SUITE_INDEX_FILE,
    "suite index",
  );
  const indexContent = await readFileBuffer(indexPath, "suite-index.json");
  const index = parseJsonBuffer(indexContent, "suite-index.json");
  const indexObject = objectValue(index, "suite index");
  if (indexObject.schemaVersion !== 3) {
    throw new SummaryError(
      "This summarizer requires the fresh suite-index.json v3 evidence contract. Regenerate the suite so the producer hashes evaluation.json, source-index.json, experiment-summary.json, cost-ledger.jsonl, canonical truth evidence, and per-physical-agent model-calls.json traces.",
    );
  }
  expectEqual(indexObject.suiteId, input.suiteId, "suite index suiteId");
  validTimestamp(indexObject.createdAt, "suite index createdAt");
  assertIntegrityNotice(indexObject.integrity, "suite index integrity");
  const indexHash = sha256Hex(
    canonicalJson(withoutProperty(indexObject, "indexSha256")),
  );
  expectDigest(indexObject.indexSha256, "suite index indexSha256");
  expectEqual(indexObject.indexSha256, indexHash, "suite index hash");
  const suiteEvidence = await validateSuiteLevelArtifacts({
    suiteRoot,
    suiteId: input.suiteId,
    indexObject,
    evaluation: input.evaluation,
    experimentSummary: input.experimentSummary,
  });

  const cells = MODES.flatMap((mode) => input.cellsByMode.get(mode));
  const cellByManifestPath = new Map(
    cells.map((cell) => [cell.manifestPath, cell]),
  );
  const indexRuns = arrayValue(indexObject.runs, "suite index runs");
  if (indexRuns.length !== cells.length) {
    throw new SummaryError(
      "suite index must bind exactly one manifest for every experiment cell.",
    );
  }
  const seenPaths = new Set();
  const seenRunIds = new Set();
  const manifestBindings = new Map();
  for (const [indexEntry, candidate] of indexRuns.entries()) {
    const entry = objectValue(candidate, `suite index run ${indexEntry}`);
    const runId = requiredString(
      entry.runId,
      `suite index run ${indexEntry} runId`,
    );
    const manifestPath = safeRelativeArtifactPath(
      entry.path,
      `suite index run ${indexEntry} path`,
    );
    expectDigest(
      entry.manifestSha256,
      `suite index run ${indexEntry} manifestSha256`,
    );
    if (seenPaths.has(manifestPath) || seenRunIds.has(runId)) {
      throw new SummaryError(
        "suite index contains a duplicate run or manifest binding.",
      );
    }
    seenPaths.add(manifestPath);
    seenRunIds.add(runId);
    const cell = cellByManifestPath.get(manifestPath);
    if (!cell || cell.runId !== runId) {
      throw new SummaryError(
        "suite index run binding does not match experiment-summary.json.",
      );
    }
    const binding = await validateBoundManifest({
      suiteRoot,
      suiteId: input.suiteId,
      execution: input.execution,
      entry,
      cell,
      evaluationRun: input.runsByMode.get(cell.mode),
      sourceState: suiteEvidence.sourceStatesByFixture.get(
        cell.fixtureId,
      ),
      truthEvidence: suiteEvidence.truthByFixture.get(cell.fixtureId),
      evaluationEngine: input.evaluationEngine,
    });
    manifestBindings.set(`${cell.runId}\u0000${cell.mode}`, binding);
  }
  if (
    seenPaths.size !== cellByManifestPath.size ||
    [...cellByManifestPath.keys()].some((entry) => !seenPaths.has(entry))
  ) {
    throw new SummaryError(
      "suite index omits one or more experiment cell manifests.",
    );
  }
  validateDerivedManifestModels(cells, manifestBindings);
  const runManifests = cells
    .map((cell) => {
      const binding = manifestBindings.get(
        `${cell.runId}\u0000${cell.mode}`,
      );
      if (!binding) {
        throw new SummaryError(
          "receipt construction found an unbound run manifest.",
        );
      }
      return {
        runId: safeOutputString(cell.runId, "receipt runId"),
        fixtureId: safeOutputString(
          cell.fixtureId,
          "receipt fixtureId",
        ),
        mode: cell.mode,
        path: cell.manifestPath,
        bytes: binding.manifestBytes,
        sha256: binding.manifestFileSha256,
        manifestSha256: binding.manifestSha256,
        durationMs: binding.durationMs,
      };
    })
    .sort(
      (left, right) =>
        compareText(left.mode, right.mode) ||
        compareText(left.fixtureId, right.fixtureId),
    );
  return {
    manifestBindings,
    receiptEvidence: {
      suiteIndex: {
        path: SUITE_INDEX_FILE,
        bytes: indexContent.byteLength,
        sha256: sha256Hex(indexContent),
        indexSha256: indexObject.indexSha256,
      },
      suiteArtifacts: suiteEvidence.artifactRecords,
      runManifests,
      sourceTruth: suiteEvidence.sourceTruthRecords,
    },
  };
}

function validateDerivedManifestModels(cells, bindings) {
  for (const cell of cells.filter((candidate) => !candidate.physical)) {
    const sourceMode = HYBRID_SOURCES[cell.mode][1];
    const sourceCell = cells.find(
      (candidate) =>
        candidate.fixtureId === cell.fixtureId &&
        candidate.mode === sourceMode,
    );
    if (!sourceCell) {
      throw new SummaryError(
        `${cell.mode} cannot resolve its physical model provenance source.`,
      );
    }
    const derivedBinding = bindings.get(
      `${cell.runId}\u0000${cell.mode}`,
    );
    const sourceBinding = bindings.get(
      `${sourceCell.runId}\u0000${sourceCell.mode}`,
    );
    if (!derivedBinding || !sourceBinding) {
      throw new SummaryError(
        `${cell.mode} has an incomplete manifest provenance binding.`,
      );
    }
    canonicalEqual(
      derivedBinding.declaredModels,
      sourceBinding.declaredModels,
      `${cell.mode} derived manifest model declarations`,
    );
  }
}

async function validateSuiteLevelArtifacts(input) {
  const expectedFixtureIds = uniqueSafeStrings(
    input.experimentSummary.fixtureIds,
    "suite artifact fixtureIds",
  );
  const fixtureBindings = new Map();
  for (const [bindingIndex, candidate] of arrayValue(
    input.indexObject.fixtureTruth,
    "suite index fixtureTruth",
  ).entries()) {
    const binding = objectValue(
      candidate,
      `suite index fixtureTruth ${bindingIndex}`,
    );
    assertExactObjectKeys(
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
      `suite index fixtureTruth ${bindingIndex}`,
    );
    const fixtureId = requiredString(
      binding.fixtureId,
      `suite index fixtureTruth ${bindingIndex} fixtureId`,
    );
    if (
      !expectedFixtureIds.includes(fixtureId) ||
      fixtureBindings.has(fixtureId)
    ) {
      throw new SummaryError(
        "suite index v3 has an unknown or repeated fixture truth binding.",
      );
    }
    const relativePath = safeRelativeArtifactPath(
      binding.path,
      `suite index fixtureTruth ${bindingIndex} path`,
    );
    if (
      !relativePath.startsWith("truth/") ||
      path.posix.basename(relativePath) !== "truth-evidence.json"
    ) {
      throw new SummaryError(
        "suite index v3 fixture truth paths must name confined truth-evidence.json artifacts.",
      );
    }
    expectEqual(
      binding.projectRoot,
      FIXTURE_PROJECT_ROOT,
      `suite index fixtureTruth ${bindingIndex} projectRoot`,
    );
    fixtureBindings.set(fixtureId, {
      fixtureId,
      pairId: requiredString(
        binding.pairId,
        `suite index fixtureTruth ${bindingIndex} pairId`,
      ),
      variant: oneOf(
        binding.variant,
        ["vulnerable", "clean"],
        `suite index fixtureTruth ${bindingIndex} variant`,
      ),
      path: relativePath,
      artifactSha256: expectDigest(
        binding.artifactSha256,
        `suite index fixtureTruth ${bindingIndex} artifactSha256`,
      ),
      fixtureDigestSha256: expectDigest(
        binding.fixtureDigestSha256,
        `suite index fixtureTruth ${bindingIndex} fixtureDigestSha256`,
      ),
      projectRoot: FIXTURE_PROJECT_ROOT,
      projectDigestSha256: expectDigest(
        binding.projectDigestSha256,
        `suite index fixtureTruth ${bindingIndex} projectDigestSha256`,
      ),
      evaluatorDigestSha256: expectDigest(
        binding.evaluatorDigestSha256,
        `suite index fixtureTruth ${bindingIndex} evaluatorDigestSha256`,
      ),
      layoutBindingSha256: expectDigest(
        binding.layoutBindingSha256,
        `suite index fixtureTruth ${bindingIndex} layoutBindingSha256`,
      ),
    });
  }
  expectStringArraysEqual(
    [...fixtureBindings.keys()].sort(compareText),
    expectedFixtureIds,
    "suite index fixture truth coverage",
  );
  const expectedArtifactPaths = [
    ...REQUIRED_SUITE_ARTIFACTS,
    ...[...fixtureBindings.values()].map((binding) => binding.path),
  ].sort(compareText);
  const records = arrayValue(
    input.indexObject.artifacts,
    "suite index artifacts",
  );
  if (records.length !== expectedArtifactPaths.length) {
    throw new SummaryError(
      "suite index v3 must bind the four canonical suite files and every fixture truth artifact.",
    );
  }
  const paths = new Set();
  const dataByPath = new Map();
  const artifactRecords = [];
  for (const [recordIndex, candidate] of records.entries()) {
    const record = objectValue(
      candidate,
      `suite index artifact ${recordIndex}`,
    );
    const relativePath = safeRelativeArtifactPath(
      record.path,
      `suite index artifact ${recordIndex} path`,
    );
    if (
      !expectedArtifactPaths.includes(relativePath) ||
      paths.has(relativePath)
    ) {
      throw new SummaryError(
        "suite index v3 contains an unknown or duplicate suite-level artifact.",
      );
    }
    paths.add(relativePath);
    const bytes = nonNegativeInteger(
      record.bytes,
      `suite index artifact ${recordIndex} bytes`,
    );
    const digest = expectDigest(
      record.sha256,
      `suite index artifact ${recordIndex} sha256`,
    );
    const artifactPath = await resolveConfinedRegularFile(
      input.suiteRoot,
      relativePath,
      `suite artifact ${relativePath}`,
    );
    const content = await readFileBuffer(artifactPath, relativePath);
    expectEqual(content.byteLength, bytes, `${relativePath} byte count`);
    expectEqual(
      sha256Hex(content),
      digest,
      `${relativePath} suite artifact hash`,
    );
    artifactRecords.push({ path: relativePath, bytes, sha256: digest });
    if (relativePath !== COST_LEDGER_FILE) {
      dataByPath.set(
        relativePath,
        readArtifactWrapper(
          parseJsonBuffer(content, relativePath),
          relativePath,
        ),
      );
    }
  }
  expectStringArraysEqual(
    [...paths].sort(compareText),
    expectedArtifactPaths,
    "suite index v3 artifact set",
  );
  canonicalEqual(
    dataByPath.get("evaluation.json"),
    input.evaluation,
    "suite-index evaluation binding",
  );
  canonicalEqual(
    dataByPath.get("experiment-summary.json"),
    input.experimentSummary,
    "suite-index experiment summary binding",
  );
  const sourceIndex = objectValue(
    dataByPath.get("source-index.json"),
    "source index data",
  );
  assertExactObjectKeys(
    sourceIndex,
    ["fixtures", "schemaVersion", "suiteId"],
    "source index data",
  );
  expectEqual(sourceIndex.schemaVersion, "1.0", "source index schemaVersion");
  expectEqual(sourceIndex.suiteId, input.suiteId, "source index suiteId");
  const sourceStatesByFixture = new Map();
  const sourceTruthLinks = new Map();
  for (const [fixtureIndex, candidate] of arrayValue(
    sourceIndex.fixtures,
    "source index fixtures",
  ).entries()) {
    const state = objectValue(
      candidate,
      `source index fixture ${fixtureIndex}`,
    );
    const fixtureId = requiredString(
      state.fixtureId,
      `source index fixture ${fixtureIndex} fixtureId`,
    );
    if (
      !expectedFixtureIds.includes(fixtureId) ||
      sourceStatesByFixture.has(fixtureId)
    ) {
      throw new SummaryError("source index has an unknown or repeated fixture.");
    }
    assertStructuralSourceStateVersion(state, fixtureId);
    assertExactObjectKeys(
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
        "truthArtifact",
        "variant",
      ],
      `source index ${fixtureId}`,
    );
    const truthArtifact = objectValue(
      state.truthArtifact,
      `source index ${fixtureId} truthArtifact`,
    );
    assertExactObjectKeys(
      truthArtifact,
      [
        "evaluatorDigestSha256",
        "fixtureDigestSha256",
        "layoutBindingSha256",
        "path",
        "projectDigestSha256",
      ],
      `source index ${fixtureId} truthArtifact`,
    );
    sourceTruthLinks.set(fixtureId, {
      path: safeRelativeArtifactPath(
        truthArtifact.path,
        `source index ${fixtureId} truthArtifact path`,
      ),
      fixtureDigestSha256: expectDigest(
        truthArtifact.fixtureDigestSha256,
        `source index ${fixtureId} truthArtifact fixtureDigestSha256`,
      ),
      projectDigestSha256: expectDigest(
        truthArtifact.projectDigestSha256,
        `source index ${fixtureId} truthArtifact projectDigestSha256`,
      ),
      evaluatorDigestSha256: expectDigest(
        truthArtifact.evaluatorDigestSha256,
        `source index ${fixtureId} truthArtifact evaluatorDigestSha256`,
      ),
      layoutBindingSha256: expectDigest(
        truthArtifact.layoutBindingSha256,
        `source index ${fixtureId} truthArtifact layoutBindingSha256`,
      ),
    });
    const normalizedState = readStructuralSourceState(
      withoutProperty(state, "truthArtifact"),
      fixtureId,
    );
    sourceStatesByFixture.set(fixtureId, normalizedState);
  }
  expectStringArraysEqual(
    [...sourceStatesByFixture.keys()].sort(compareText),
    expectedFixtureIds,
    "source index fixture coverage",
  );
  const truthByFixture = new Map();
  const sourceTruthRecords = [];
  for (const fixtureId of expectedFixtureIds) {
    const binding = fixtureBindings.get(fixtureId);
    const sourceState = sourceStatesByFixture.get(fixtureId);
    const sourceLink = sourceTruthLinks.get(fixtureId);
    if (!binding || !sourceState || !sourceLink) {
      throw new SummaryError(
        "suite v3 source/truth evidence is incomplete.",
      );
    }
    expectEqual(
      sourceLink.path,
      binding.path,
      `${fixtureId} source-index truth path binding`,
    );
    expectEqual(
      sourceLink.fixtureDigestSha256,
      binding.fixtureDigestSha256,
      `${fixtureId} source-index truth digest binding`,
    );
    for (const [actual, expected, label] of [
      [
        sourceLink.projectDigestSha256,
        binding.projectDigestSha256,
        `${fixtureId} source-index project digest binding`,
      ],
      [
        sourceLink.evaluatorDigestSha256,
        binding.evaluatorDigestSha256,
        `${fixtureId} source-index evaluator digest binding`,
      ],
      [
        sourceLink.layoutBindingSha256,
        binding.layoutBindingSha256,
        `${fixtureId} source-index layout digest binding`,
      ],
      [
        sourceState.project.projectDigestSha256,
        binding.projectDigestSha256,
        `${fixtureId} source-state project digest binding`,
      ],
      [
        sourceState.evaluator.evaluatorDigestSha256,
        binding.evaluatorDigestSha256,
        `${fixtureId} source-state evaluator digest binding`,
      ],
      [
        sourceState.layoutBindingSha256,
        binding.layoutBindingSha256,
        `${fixtureId} source-state layout digest binding`,
      ],
    ]) {
      expectEqual(actual, expected, label);
    }
    expectEqual(
      sourceState.fixtureDigestSha256,
      binding.fixtureDigestSha256,
      `${fixtureId} source-state fixture digest binding`,
    );
    const artifactRecord = artifactRecords.find(
      (record) => record.path === binding.path,
    );
    expectEqual(
      artifactRecord?.sha256,
      binding.artifactSha256,
      `${fixtureId} truth artifact index digest binding`,
    );
    const evidence = objectValue(
      dataByPath.get(binding.path),
      `${fixtureId} truth evidence`,
    );
    expectEqual(
      evidence.schemaVersion,
      "1.0",
      `${fixtureId} truth evidence schemaVersion`,
    );
    expectEqual(evidence.fixtureId, fixtureId, `${fixtureId} truth identity`);
    expectEqual(evidence.pairId, binding.pairId, `${fixtureId} truth pairId`);
    expectEqual(
      evidence.variant,
      binding.variant,
      `${fixtureId} truth variant`,
    );
    const manifest = objectValue(
      evidence.manifest,
      `${fixtureId} truth manifest`,
    );
    const truth = objectValue(evidence.truth, `${fixtureId} truth data`);
    const evidenceSourceState = objectValue(
      evidence.sourceState,
      `${fixtureId} truth sourceState`,
    );
    expectEqual(
      sourceState.pairId,
      binding.pairId,
      `${fixtureId} source-state pairId`,
    );
    expectEqual(
      sourceState.variant,
      binding.variant,
      `${fixtureId} source-state variant`,
    );
    expectEqual(
      sourceState.language,
      manifest.language,
      `${fixtureId} source-state language`,
    );
    validateStructuralFixtureManifest(
      manifest,
      sourceState,
      fixtureId,
    );
    canonicalEqual(
      evidenceSourceState,
      sourceState,
      `${fixtureId} truth/source-index sourceState`,
    );
    const internalBinding = objectValue(
      evidence.binding,
      `${fixtureId} truth internal binding`,
    );
    assertExactObjectKeys(
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
      `${fixtureId} truth internal binding`,
    );
    const manifestSha256 = expectDigest(
      internalBinding.manifestSha256,
      `${fixtureId} truth manifestSha256`,
    );
    const truthSha256 = expectDigest(
      internalBinding.truthSha256,
      `${fixtureId} truth truthSha256`,
    );
    const sourceStateSha256 = expectDigest(
      internalBinding.sourceStateSha256,
      `${fixtureId} truth sourceStateSha256`,
    );
    expectEqual(
      internalBinding.projectRoot,
      FIXTURE_PROJECT_ROOT,
      `${fixtureId} truth projectRoot`,
    );
    const projectDigestSha256 = expectDigest(
      internalBinding.projectDigestSha256,
      `${fixtureId} truth projectDigestSha256`,
    );
    const evaluatorDigestSha256 = expectDigest(
      internalBinding.evaluatorDigestSha256,
      `${fixtureId} truth evaluatorDigestSha256`,
    );
    const layoutBindingSha256 = expectDigest(
      internalBinding.layoutBindingSha256,
      `${fixtureId} truth layoutBindingSha256`,
    );
    const subjectDigestSha256 = expectDigest(
      internalBinding.subjectDigestSha256,
      `${fixtureId} truth subjectDigestSha256`,
    );
    const subjectFixtureBindingSha256 = expectDigest(
      internalBinding.subjectFixtureBindingSha256,
      `${fixtureId} truth subjectFixtureBindingSha256`,
    );
    expectEqual(
      manifestSha256,
      sha256Hex(canonicalJson(manifest)),
      `${fixtureId} canonical fixture manifest hash`,
    );
    expectEqual(
      truthSha256,
      sha256Hex(canonicalJson(truth)),
      `${fixtureId} canonical truth hash`,
    );
    expectEqual(
      sourceStateSha256,
      sha256Hex(canonicalJson(sourceState)),
      `${fixtureId} canonical source-state hash`,
    );
    expectEqual(
      internalBinding.fixtureDigestSha256,
      binding.fixtureDigestSha256,
      `${fixtureId} truth fixture digest`,
    );
    for (const [actual, expected, label] of [
      [
        projectDigestSha256,
        binding.projectDigestSha256,
        `${fixtureId} truth project digest`,
      ],
      [
        evaluatorDigestSha256,
        binding.evaluatorDigestSha256,
        `${fixtureId} truth evaluator digest`,
      ],
      [
        layoutBindingSha256,
        binding.layoutBindingSha256,
        `${fixtureId} truth structural layout binding`,
      ],
    ]) {
      expectEqual(actual, expected, label);
    }
    expectEqual(
      subjectDigestSha256,
      sourceState.project.projectDigestSha256,
      `${fixtureId} truth structural project digest alias`,
    );
    expectEqual(
      subjectFixtureBindingSha256,
      sourceState.layoutBindingSha256,
      `${fixtureId} truth structural layout compatibility binding`,
    );
    expectEqual(manifest.id, fixtureId, `${fixtureId} manifest identity`);
    expectEqual(truth.fixtureId, fixtureId, `${fixtureId} truth identity`);
    expectEqual(
      nonNegativeInteger(
        manifest.expectedFindingCount,
        `${fixtureId} expectedFindingCount`,
      ),
      arrayValue(truth.findings, `${fixtureId} truth findings`).length,
      `${fixtureId} truth finding count`,
    );
    truthByFixture.set(fixtureId, {
      binding,
      manifest,
      truth,
      manifestSha256,
      truthSha256,
      sourceStateSha256,
      projectDigestSha256,
      evaluatorDigestSha256,
      layoutBindingSha256,
      subjectDigestSha256,
      subjectFixtureBindingSha256,
    });
    sourceTruthRecords.push({
      fixtureId: safeOutputString(fixtureId, "receipt truth fixtureId"),
      path: binding.path,
      artifactSha256: binding.artifactSha256,
      fixtureDigestSha256: binding.fixtureDigestSha256,
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
  return {
    sourceStatesByFixture,
    truthByFixture,
    artifactRecords: artifactRecords.sort((left, right) =>
      compareText(left.path, right.path),
    ),
    sourceTruthRecords,
  };
}

function readStructuralSourceState(value, fixtureId) {
  const state = objectValue(value, `source index ${fixtureId} source state`);
  assertStructuralSourceStateVersion(state, fixtureId);
  assertExactObjectKeys(
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
    `source index ${fixtureId} structural source state`,
  );
  expectEqual(
    state.fixtureId,
    fixtureId,
    `source index ${fixtureId} identity`,
  );
  const pairId = requiredString(
    state.pairId,
    `source index ${fixtureId} pairId`,
  );
  const variant = oneOf(
    state.variant,
    ["vulnerable", "clean"],
    `source index ${fixtureId} variant`,
  );
  const language = requiredString(
    state.language,
    `source index ${fixtureId} language`,
  );
  const fullFiles = readStructuralFileRecords(
    state.files,
    `source index ${fixtureId} fixture files`,
    { forbiddenCaseFoldedPaths: [FIXTURE_PROJECT_ROOT] },
  );
  if (fullFiles.length === 0) {
    throw new SummaryError(
      `source index ${fixtureId} structural fixture inventory is empty.`,
    );
  }

  const project = objectValue(
    state.project,
    `source index ${fixtureId} project`,
  );
  assertExactObjectKeys(
    project,
    ["files", "projectDigestSha256", "root"],
    `source index ${fixtureId} project`,
  );
  expectEqual(
    project.root,
    FIXTURE_PROJECT_ROOT,
    `source index ${fixtureId} project root`,
  );
  const projectFiles = readStructuralFileRecords(
    project.files,
    `source index ${fixtureId} project files`,
  );
  if (projectFiles.length === 0) {
    throw new SummaryError(
      `source index ${fixtureId} structural project/ subtree is empty.`,
    );
  }

  const evaluator = objectValue(
    state.evaluator,
    `source index ${fixtureId} evaluator`,
  );
  assertExactObjectKeys(
    evaluator,
    ["evaluatorDigestSha256", "files"],
    `source index ${fixtureId} evaluator`,
  );
  const evaluatorFiles = readStructuralFileRecords(
    evaluator.files,
    `source index ${fixtureId} evaluator files`,
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
    throw new SummaryError(
      `source index ${fixtureId} contains an unclassified or misplaced path outside, or colliding with, the explicit project/ subtree.`,
    );
  }
  canonicalEqual(
    projectFiles,
    expectedProjectFiles,
    `source index ${fixtureId} exact project-relative project inventory`,
  );
  canonicalEqual(
    evaluatorFiles,
    expectedEvaluatorFiles,
    `source index ${fixtureId} exact evaluator inventory`,
  );
  if (
    !evaluatorFiles.some((file) => file.path === "fixture.json") ||
    !evaluatorFiles.some((file) => file.path === "truth.json")
  ) {
    throw new SummaryError(
      `source index ${fixtureId} evaluator inventory must contain fixture.json and truth.json outside project/.`,
    );
  }

  const fixtureDigestSha256 = sha256Hex(
    prettyCanonicalJson(fullFiles),
  );
  const projectDigestSha256 = sha256Hex(
    prettyCanonicalJson(projectFiles),
  );
  const evaluatorDigestSha256 = sha256Hex(
    prettyCanonicalJson(evaluatorFiles),
  );
  const layoutBindingSha256 = sha256Hex(
    canonicalJson({
      projectRoot: FIXTURE_PROJECT_ROOT,
      fixtureDigestSha256,
      projectDigestSha256,
      evaluatorDigestSha256,
    }),
  );
  for (const [actual, expected, label] of [
    [
      expectDigest(
        state.fixtureDigestSha256,
        `source index ${fixtureId} fixtureDigestSha256`,
      ),
      fixtureDigestSha256,
      `source index ${fixtureId} recomputed fixture digest`,
    ],
    [
      expectDigest(
        project.projectDigestSha256,
        `source index ${fixtureId} projectDigestSha256`,
      ),
      projectDigestSha256,
      `source index ${fixtureId} recomputed project digest`,
    ],
    [
      expectDigest(
        evaluator.evaluatorDigestSha256,
        `source index ${fixtureId} evaluatorDigestSha256`,
      ),
      evaluatorDigestSha256,
      `source index ${fixtureId} recomputed evaluator digest`,
    ],
    [
      expectDigest(
        state.layoutBindingSha256,
        `source index ${fixtureId} layoutBindingSha256`,
      ),
      layoutBindingSha256,
      `source index ${fixtureId} structural layout binding`,
    ],
  ]) {
    expectEqual(actual, expected, label);
  }

  const subject = objectValue(
    state.subject,
    `source index ${fixtureId} structural compatibility subject`,
  );
  assertExactObjectKeys(
    subject,
    [
      "excludedControlFiles",
      "files",
      "fixtureBindingSha256",
      "subjectDigestSha256",
    ],
    `source index ${fixtureId} structural compatibility subject`,
  );
  const subjectFiles = readStructuralFileRecords(
    subject.files,
    `source index ${fixtureId} compatibility subject files`,
  );
  const excludedControlFiles = stringArray(
    subject.excludedControlFiles,
    `source index ${fixtureId} compatibility excluded evaluator files`,
  ).map((entry, index) =>
    safeRelativeArtifactPath(
      entry,
      `source index ${fixtureId} excluded evaluator file ${index}`,
    ),
  );
  expectStringArraysEqual(
    excludedControlFiles,
    evaluatorFiles.map((file) => file.path),
    `source index ${fixtureId} evaluator exclusion inventory`,
  );
  canonicalEqual(
    subjectFiles,
    projectFiles,
    `source index ${fixtureId} project/subject compatibility inventory`,
  );
  expectEqual(
    subject.subjectDigestSha256,
    projectDigestSha256,
    `source index ${fixtureId} project/subject digest binding`,
  );
  expectEqual(
    subject.fixtureBindingSha256,
    layoutBindingSha256,
    `source index ${fixtureId} project/subject layout binding`,
  );

  const normalized = {
    schemaVersion: "2.0",
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
    `source index ${fixtureId} exact structural source-state schema`,
  );
  return normalized;
}

function assertStructuralSourceStateVersion(state, fixtureId) {
  if (state.schemaVersion !== "2.0") {
    throw new SummaryError(
      `source index ${fixtureId} uses legacy source-state schema ${String(
        state.schemaVersion,
      )}. Regenerate the suite with structural source-state schema 2.0 (an explicit project/ subtree and evaluator inventory).`,
    );
  }
}

function readStructuralFileRecords(value, label, options = {}) {
  const records = arrayValue(value, label).map((candidate, index) => {
    const record = objectValue(candidate, `${label} ${index}`);
    assertExactObjectKeys(
      record,
      ["bytes", "path", "sha256"],
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
      throw new SummaryError(
        `${label} contains a path colliding with the explicit ${FIXTURE_PROJECT_ROOT}/ subtree.`,
      );
    }
    return {
      path: relativePath,
      bytes: nonNegativeInteger(
        record.bytes,
        `${label} ${index} bytes`,
      ),
      sha256: expectDigest(
        record.sha256,
        `${label} ${index} sha256`,
      ),
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
    throw new SummaryError(`${label} contains case-folded path aliases.`);
  }
  expectStringArraysEqual(
    records.map((record) => record.path),
    [...records.map((record) => record.path)].sort((left, right) =>
      left.localeCompare(right),
    ),
    `${label} canonical ordering`,
  );
  canonicalEqual(value, records, `${label} exact record schema`);
  return records;
}

function validateStructuralFixtureManifest(manifest, sourceState, fixtureId) {
  assertExactObjectKeys(
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
    `${fixtureId} structural fixture manifest`,
  );
  expectEqual(
    manifest.schemaVersion,
    "2.0",
    `${fixtureId} fixture manifest schemaVersion`,
  );
  expectEqual(manifest.id, fixtureId, `${fixtureId} manifest identity`);
  expectEqual(
    manifest.pairId,
    sourceState.pairId,
    `${fixtureId} manifest pairId`,
  );
  expectEqual(
    manifest.variant,
    sourceState.variant,
    `${fixtureId} manifest variant`,
  );
  expectEqual(
    manifest.language,
    sourceState.language,
    `${fixtureId} manifest language`,
  );
  expectEqual(
    manifest.projectRoot,
    FIXTURE_PROJECT_ROOT,
    `${fixtureId} manifest projectRoot`,
  );
  requiredString(
    manifest.pairedFixtureId,
    `${fixtureId} pairedFixtureId`,
  );

  const evaluatorFiles = nonEmptyStringArray(
    manifest.evaluatorFiles,
    `${fixtureId} evaluatorFiles`,
  ).map((entry, index) => {
    const relativePath = safeRelativeArtifactPath(
      entry,
      `${fixtureId} evaluatorFiles ${index}`,
    );
    if (relativePath.includes("/")) {
      throw new SummaryError(
        `${fixtureId} evaluatorFiles must name root-level files outside project/.`,
      );
    }
    return relativePath;
  });
  assertUniqueValues(evaluatorFiles, `${fixtureId} evaluatorFiles`);
  if (
    new Set(evaluatorFiles.map((entry) => entry.toLowerCase())).size !==
    evaluatorFiles.length
  ) {
    throw new SummaryError(
      `${fixtureId} evaluatorFiles contains case-folded path aliases.`,
    );
  }
  expectStringArraysEqual(
    evaluatorFiles,
    [...evaluatorFiles].sort(compareText),
    `${fixtureId} canonical evaluatorFiles ordering`,
  );
  if (
    !evaluatorFiles.includes("truth.json") ||
    evaluatorFiles.includes("fixture.json")
  ) {
    throw new SummaryError(
      `${fixtureId} evaluatorFiles must include truth.json and omit fixture.json.`,
    );
  }
  expectStringArraysEqual(
    sourceState.evaluator.files.map((file) => file.path),
    ["fixture.json", ...evaluatorFiles].sort((left, right) =>
      left.localeCompare(right),
    ),
    `${fixtureId} manifest-declared evaluator inventory`,
  );

  const sourceFiles = nonEmptyStringArray(
    manifest.sourceFiles,
    `${fixtureId} sourceFiles`,
  ).map((entry, index) =>
    safeRelativeArtifactPath(
      entry,
      `${fixtureId} sourceFiles ${index}`,
    ),
  );
  const entrypoints = nonEmptyStringArray(
    manifest.entrypoints,
    `${fixtureId} entrypoints`,
  ).map((entry, index) =>
    safeRelativeArtifactPath(
      entry,
      `${fixtureId} entrypoints ${index}`,
    ),
  );
  for (const [values, label] of [
    [sourceFiles, `${fixtureId} sourceFiles`],
    [entrypoints, `${fixtureId} entrypoints`],
  ]) {
    assertUniqueValues(values, label);
    if (
      new Set(values.map((entry) => entry.toLowerCase())).size !==
      values.length
    ) {
      throw new SummaryError(`${label} contains case-folded path aliases.`);
    }
  }
  const projectPaths = new Set(
    sourceState.project.files.map((file) => file.path),
  );
  if (sourceFiles.some((entry) => !projectPaths.has(entry))) {
    throw new SummaryError(
      `${fixtureId} manifest sourceFiles escape or are missing from project/.`,
    );
  }
  if (entrypoints.some((entry) => !sourceFiles.includes(entry))) {
    throw new SummaryError(
      `${fixtureId} manifest entrypoints must be included in sourceFiles.`,
    );
  }
  nonEmptyStringArray(
    manifest.supportedVulnerabilityClasses,
    `${fixtureId} supportedVulnerabilityClasses`,
  );
  const safety = objectValue(
    manifest.safety,
    `${fixtureId} fixture safety`,
  );
  assertExactObjectKeys(
    safety,
    [
      "containsRealSecrets",
      "executionPolicy",
      "executionRequired",
      "networkPolicy",
      "networkRequired",
    ],
    `${fixtureId} fixture safety`,
  );
  canonicalEqual(
    safety,
    {
      networkRequired: false,
      executionRequired: false,
      containsRealSecrets: false,
      executionPolicy: "never",
      networkPolicy: "deny",
    },
    `${fixtureId} inert fixture safety contract`,
  );
}

function nonEmptyStringArray(value, label) {
  const entries = stringArray(value, label);
  if (
    entries.length === 0 ||
    entries.some((entry) => entry.trim().length === 0)
  ) {
    throw new SummaryError(`${label} must be a non-empty string array.`);
  }
  return entries;
}

async function validateBoundManifest(input) {
  const manifestPath = await resolveConfinedRegularFile(
    input.suiteRoot,
    input.cell.manifestPath,
    "run manifest",
  );
  const manifestContent = await readFileBuffer(
    manifestPath,
    "run manifest",
  );
  const manifest = objectValue(
    parseJsonBuffer(manifestContent, "run manifest"),
    "run manifest",
  );
  expectEqual(manifest.schemaVersion, 2, "run manifest schemaVersion");
  expectEqual(manifest.runId, input.cell.runId, "run manifest runId");
  expectEqual(manifest.suite, input.suiteId, "run manifest suite");
  expectEqual(manifest.mode, input.cell.mode, "run manifest mode");
  expectEqual(manifest.execution, input.execution, "run manifest execution");
  expectEqual(manifest.status, input.cell.status, "run manifest status");
  validTimestamp(manifest.startedAt, "run manifest startedAt");
  validTimestamp(manifest.finishedAt, "run manifest finishedAt");
  if (Date.parse(manifest.finishedAt) < Date.parse(manifest.startedAt)) {
    throw new SummaryError(
      "run manifest finishedAt precedes its startedAt.",
    );
  }
  const harnessVersion = requiredString(
    manifest.harnessVersion,
    "run manifest harnessVersion",
  );
  const promptVersion = requiredString(
    manifest.promptVersion,
    "run manifest promptVersion",
  );
  const limits = objectValue(manifest.limits, "run manifest limits");
  expectEqual(
    limits.noModelFallback,
    true,
    "run manifest noModelFallback",
  );
  expectEqual(
    usdToNanoUsd(
      nonNegativeNumber(
        limits.globalBudgetUsd,
        "run manifest globalBudgetUsd",
      ),
      "run manifest globalBudgetUsd",
    ),
    GLOBAL_BUDGET_NANO_USD,
    "run manifest canonical global budget",
  );
  expectEqual(
    usdToNanoUsd(
      nonNegativeNumber(
        limits.modeBudgetUsd,
        "run manifest modeBudgetUsd",
      ),
      "run manifest modeBudgetUsd",
    ),
    usdToNanoUsd(
      MODE_BUDGET_USD[input.cell.mode],
      `${input.cell.mode} canonical mode budget`,
    ),
    "run manifest canonical mode budget",
  );
  const declaredModels = readManifestModels(
    manifest.models,
    input.cell.mode,
    "run manifest models",
  );
  stringArray(manifest.redactionMarkers, "run manifest redactionMarkers");
  assertIntegrityNotice(manifest.integrity, "run manifest integrity");
  expectDigest(manifest.manifestSha256, "run manifest manifestSha256");
  const expectedManifestHash = sha256Hex(
    canonicalJson(withoutProperty(manifest, "manifestSha256")),
  );
  expectEqual(
    manifest.manifestSha256,
    expectedManifestHash,
    "run manifest integrity hash",
  );
  expectEqual(
    input.entry.manifestSha256,
    manifest.manifestSha256,
    "suite index manifest hash binding",
  );

  const metadata = objectValue(manifest.metadata, "run manifest metadata");
  expectEqual(
    metadata.fixtureId,
    input.cell.fixtureId,
    "manifest fixture binding",
  );
  expectEqual(
    metadata.physical,
    input.cell.physical,
    "manifest physical binding",
  );
  canonicalEqual(
    metadata.derivedFrom,
    input.cell.derivedFrom,
    "manifest derivedFrom binding",
  );
  canonicalEqual(metadata.cost, input.cell.cost, "manifest cost binding");
  expectEqual(
    metadata.modelCallTraceSchemaVersion,
    MODEL_CALL_TRACE_SCHEMA_VERSION,
    "manifest model-call trace schema version",
  );
  expectEqual(
    metadata.modelCallTraceRolePlanVersion,
    MODEL_CALL_TRACE_ROLE_PLAN_VERSION,
    "manifest model-call role-plan version",
  );
  const manifestCassettePolicy = oneOf(
    metadata.modelCallTraceCassettePolicy,
    ["none", "recorded", "replay"],
    "manifest model-call cassette policy",
  );
  expectEqual(
    metadata.subjectSnapshotSchemaVersion,
    "2.0",
    "manifest structural subject snapshot schema version",
  );
  expectEqual(
    metadata.projectSnapshotSchemaVersion,
    "1.0",
    "manifest structural project snapshot binding version",
  );
  if (!input.sourceState) {
    throw new SummaryError(
      "run manifest is missing its indexed structural project/evaluator snapshot binding.",
    );
  }
  canonicalEqual(
    objectValue(
      metadata.projectSnapshot,
      "manifest metadata projectSnapshot",
    ),
    {
      root: FIXTURE_PROJECT_ROOT,
      projectDigestSha256:
        input.sourceState.project.projectDigestSha256,
      evaluatorDigestSha256:
        input.sourceState.evaluator.evaluatorDigestSha256,
      layoutBindingSha256:
        input.sourceState.layoutBindingSha256,
    },
    "manifest structural project/evaluator snapshot binding",
  );
  canonicalEqual(
    objectValue(
      metadata.subjectSnapshot,
      "manifest metadata subjectSnapshot",
    ),
    {
      subjectDigestSha256:
        input.sourceState.project.projectDigestSha256,
      fixtureBindingSha256:
        input.sourceState.layoutBindingSha256,
    },
    "manifest structural project compatibility binding",
  );

  const artifacts = arrayValue(manifest.artifacts, "run manifest artifacts");
  if (artifacts.length !== CELL_ARTIFACTS.length) {
    throw new SummaryError(
      "fresh run manifests must bind the six canonical artifacts, including model-calls.json.",
    );
  }
  const runDirectory = path.dirname(manifestPath);
  const artifactData = new Map();
  const artifactPaths = new Set();
  for (const [artifactIndex, candidate] of artifacts.entries()) {
    const artifact = objectValue(
      candidate,
      `run manifest artifact ${artifactIndex}`,
    );
    const relativePath = safeRelativeArtifactPath(
      artifact.path,
      `run manifest artifact ${artifactIndex} path`,
    );
    const bytes = nonNegativeInteger(
      artifact.bytes,
      `run manifest artifact ${artifactIndex} bytes`,
    );
    expectDigest(
      artifact.sha256,
      `run manifest artifact ${artifactIndex} sha256`,
    );
    if (
      !CELL_ARTIFACTS.includes(relativePath) ||
      artifactPaths.has(relativePath)
    ) {
      throw new SummaryError(
        "run manifest has an unknown or duplicate raw artifact.",
      );
    }
    artifactPaths.add(relativePath);
    const filePath = await resolveConfinedRegularFile(
      runDirectory,
      relativePath,
      `run artifact ${relativePath}`,
    );
    const content = await readFileBuffer(filePath, relativePath);
    expectEqual(content.byteLength, bytes, `${relativePath} byte count`);
    expectEqual(
      sha256Hex(content),
      artifact.sha256,
      `${relativePath} artifact hash`,
    );
    const wrapped = parseJsonBuffer(content, relativePath);
    artifactData.set(
      relativePath,
      readArtifactWrapper(wrapped, relativePath),
    );
  }
  expectStringArraysEqual(
    [...artifactPaths].sort(compareText),
    [...CELL_ARTIFACTS],
    "run manifest artifact set",
  );
  const actualFiles = await listRegularFiles(runDirectory);
  expectStringArraysEqual(
    actualFiles,
    [...CELL_ARTIFACTS, RUN_MANIFEST_FILE].sort(compareText),
    "run directory artifact inventory",
  );
  const modelCallTrace = readModelCallsArtifact(
    artifactData.get(MODEL_CALLS_FILE),
    input.cell,
    input.execution,
    manifestCassettePolicy,
    sha256Hex(
      `hermsec-replay-scope\u0000${[
        input.cell.fixtureId,
        input.sourceState.fixtureDigestSha256,
        harnessVersion,
        promptVersion,
        input.cell.mode,
      ].join("\u0000")}`,
    ),
  );
  const failFastPlaceholder = validateManifestModelTrace(
    input.cell,
    declaredModels,
    modelCallTrace,
    input.evaluationRun,
    artifactData.get("detector-evidence.json"),
    input.execution,
  );
  const detectorEvidence = objectValue(
    artifactData.get("detector-evidence.json"),
    `${input.cell.mode}/${input.cell.fixtureId} detector evidence`,
  );
  const strictLiveGateReasons = liveGateReasonsForCase(
    input.evaluationRun,
    input.cell,
  );
  const metadataDegradationReasons = stringArray(
    metadata.degradationReasons,
    `${input.cell.mode}/${input.cell.fixtureId} manifest degradation reasons`,
  );
  const metadataStrictLiveGateReasons =
    metadataDegradationReasons.filter((reason) =>
      reason.startsWith("Strict live paid gate stopped "),
    );
  expectStringArraysEqual(
    metadataStrictLiveGateReasons,
    strictLiveGateReasons,
    `${input.cell.mode}/${input.cell.fixtureId} manifest/evaluation strict paid-gate reasons`,
  );
  if (
    strictLiveGateReasons.length > 0 &&
    metadataDegradationReasons.length !==
      strictLiveGateReasons.length
  ) {
    throw new SummaryError(
      `${input.cell.mode}/${input.cell.fixtureId} fail-fast placeholder mixes its strict paid-gate reason with unrelated degradation reasons.`,
    );
  }
  bindArtifactData({
    manifest,
    metadata,
    cell: input.cell,
    evaluationRun: input.evaluationRun,
    artifactData,
    sourceState: input.sourceState,
    truthEvidence: input.truthEvidence,
    evaluationEngine: input.evaluationEngine,
  });
  return {
    declaredModels,
    modelCalls: modelCallTrace.calls,
    modelCallTrace,
    failFastPlaceholder,
    hasAgentEvidence: Object.prototype.hasOwnProperty.call(
      detectorEvidence,
      "agentEvidence",
    ),
    strictLiveGateReasons,
    ...(failFastPlaceholder
      ? {
          failFastReason: requireSingleStrictLiveGateReason(
            strictLiveGateReasons,
            input.cell,
          ),
        }
      : {}),
    mode: input.cell.mode,
    manifestBytes: manifestContent.byteLength,
    manifestFileSha256: sha256Hex(manifestContent),
    manifestSha256: manifest.manifestSha256,
    durationMs:
      Date.parse(manifest.finishedAt) - Date.parse(manifest.startedAt),
  };
}

function liveGateReasonsForCase(evaluationRun, cell) {
  const evaluationCase = evaluationRun.cases.find(
    (candidate) => candidate.fixtureId === cell.fixtureId,
  );
  return (
    evaluationCase?.completenessInput?.degradedReasons ?? []
  ).filter(
    (reason) =>
      typeof reason === "string" &&
      reason.startsWith("Strict live paid gate stopped "),
  );
}

function requireSingleStrictLiveGateReason(reasons, cell) {
  if (reasons.length !== 1) {
    throw new SummaryError(
      `${cell.mode}/${cell.fixtureId} fail-fast placeholder must carry exactly one strict paid-gate reason.`,
    );
  }
  return reasons[0];
}

function readManifestModels(value, mode, label) {
  const declarations = arrayValue(value, label).map((candidate, index) => {
    const declaration = objectValue(candidate, `${label} ${index}`);
    const provider = requiredString(
      declaration.provider,
      `${label} ${index} provider`,
    );
    const model = requiredString(
      declaration.model,
      `${label} ${index} model`,
    );
    expectEqual(provider, "openrouter", `${label} ${index} provider`);
    if (!EXACT_MODEL_ALLOWLIST.includes(model)) {
      throw new SummaryError(
        `${label} ${index} model is outside the exact research allowlist.`,
      );
    }
    if (
      model === MINIMAX_AGGREGATOR &&
      mode !== "moa-low" &&
      mode !== "moa-high" &&
      mode !== "scanner-moa-low" &&
      mode !== "scanner-moa-high"
    ) {
      throw new SummaryError(
        "Minimax may be declared only for MoA aggregation modes.",
      );
    }
    return { provider, model };
  });
  const keys = declarations.map(
    (entry) => `${entry.provider}\u0000${entry.model}`,
  );
  if (new Set(keys).size !== keys.length) {
    throw new SummaryError(`${label} contains duplicate declarations.`);
  }
  return declarations;
}

function readModelCallsArtifact(
  value,
  cell,
  execution,
  manifestCassettePolicy,
  expectedScopeIdSha256,
) {
  const trace = objectValue(
    value,
    `${cell.mode} model-calls.json data`,
  );
  assertExactObjectKeys(
    trace,
    [
      "aggregationDisposition",
      "cassettePolicy",
      "calls",
      "candidateCount",
      "derivedFrom",
      "detectorStatus",
      "execution",
      "mode",
      "physical",
      "producerValidation",
      "rolePlan",
      "runId",
      "schemaVersion",
      "traceCompleteness",
    ],
    `${cell.mode} model-calls.json data`,
  );
  expectEqual(
    trace.schemaVersion,
    MODEL_CALL_TRACE_SCHEMA_VERSION,
    `${cell.mode} model-calls schemaVersion`,
  );
  expectEqual(trace.runId, cell.runId, `${cell.mode} model-calls runId`);
  expectEqual(trace.mode, cell.mode, `${cell.mode} model-calls mode`);
  expectEqual(
    trace.execution,
    execution,
    `${cell.mode} model-calls execution`,
  );
  const cassettePolicy = oneOf(
    trace.cassettePolicy,
    ["none", "recorded", "replay"],
    `${cell.mode} model-calls cassettePolicy`,
  );
  expectEqual(
    cassettePolicy,
    manifestCassettePolicy,
    `${cell.mode} manifest/model-call cassette policy binding`,
  );
  expectEqual(
    booleanValue(trace.physical, `${cell.mode} model-calls physical`),
    cell.physical,
    `${cell.mode} model-calls physical binding`,
  );
  const derivedFrom = arrayValue(
    trace.derivedFrom,
    `${cell.mode} model-calls derivedFrom`,
  ).map((candidate, index) =>
    canonicalMode(
      candidate,
      `${cell.mode} model-calls derivedFrom ${index}`,
    ),
  );
  expectStringArraysEqual(
    derivedFrom,
    cell.derivedFrom,
    `${cell.mode} model-calls derivedFrom`,
  );
  const detectorStatus = oneOf(
    trace.detectorStatus,
    [
      "completed",
      "partial",
      "degraded",
      "failed",
      "canceled",
      "not-applicable",
    ],
    `${cell.mode} model-calls detectorStatus`,
  );
  const candidateCount = nonNegativeInteger(
    trace.candidateCount,
    `${cell.mode} model-calls candidateCount`,
  );
  const aggregationDisposition = oneOf(
    trace.aggregationDisposition,
    [
      "not-applicable",
      "required",
      "not-required-no-candidates",
    ],
    `${cell.mode} model-calls aggregationDisposition`,
  );
  const rolePlanValue = objectValue(
    trace.rolePlan,
    `${cell.mode} model-calls rolePlan`,
  );
  assertExactObjectKeys(
    rolePlanValue,
    ["requiredSpecialistRoles", "status"],
    `${cell.mode} model-calls rolePlan`,
  );
  const rolePlan = {
    status: oneOf(
      rolePlanValue.status,
      ["complete", "unavailable", "not-applicable"],
      `${cell.mode} model-calls rolePlan status`,
    ),
    requiredSpecialistRoles: arrayValue(
      rolePlanValue.requiredSpecialistRoles,
      `${cell.mode} model-calls requiredSpecialistRoles`,
    ).map((role, roleIndex) =>
      oneOf(
        role,
        ["single-agent-inspector", ...MOA_SPECIALIST_ROLES],
        `${cell.mode} model-calls requiredSpecialistRoles ${roleIndex}`,
      ),
    ),
  };
  assertUniqueValues(
    rolePlan.requiredSpecialistRoles,
    `${cell.mode} model-calls requiredSpecialistRoles`,
  );
  const traceCompleteness = oneOf(
    trace.traceCompleteness,
    ["complete", "incomplete"],
    `${cell.mode} model-calls traceCompleteness`,
  );
  const calls = arrayValue(trace.calls, `${cell.mode} model-calls calls`).map(
    (candidate, index) => {
      const call = objectValue(
        candidate,
        `${cell.mode} model call ${index}`,
      );
      const terminalState = oneOf(
        call.terminalState,
        MODEL_CALL_TERMINAL_STATES,
        `${cell.mode} model call ${index} terminalState`,
      );
      const hasCassetteReference =
        Object.prototype.hasOwnProperty.call(
          call,
          "cassetteReference",
        );
      const hasProviderError =
        Object.prototype.hasOwnProperty.call(
          call,
          "providerError",
        );
      assertExactObjectKeys(
        call,
        terminalState === "succeeded"
          ? [
              ...(hasCassetteReference
                ? ["cassetteReference"]
                : []),
              "fingerprintSource",
              "gapFill",
              "model",
              "ordinal",
              "provider",
              "requestFingerprint",
              "responseModel",
              "responseProvider",
              "role",
              "terminalState",
            ]
          : [
              "errorCategory",
              "fingerprintSource",
              "gapFill",
              "model",
              "ordinal",
              "provider",
              ...(hasProviderError ? ["providerError"] : []),
              "requestFingerprint",
              "role",
              "terminalState",
            ],
        `${cell.mode} model call ${index}`,
      );
      const ordinal = nonNegativeInteger(
        call.ordinal,
        `${cell.mode} model call ${index} ordinal`,
      );
      const role = oneOf(
        call.role,
        Object.keys(EXACT_ROLE_MODELS),
        `${cell.mode} model call ${index} role`,
      );
      const gapFill = booleanValue(
        call.gapFill,
        `${cell.mode} model call ${index} gapFill`,
      );
      const provider = requiredString(
        call.provider,
        `${cell.mode} model call ${index} provider`,
      );
      expectEqual(
        provider,
        "openrouter",
        `${cell.mode} model call ${index} provider`,
      );
      const model = requiredString(
        call.model,
        `${cell.mode} model call ${index} model`,
      );
      const requestFingerprint = expectDigest(
        call.requestFingerprint,
        `${cell.mode} model call ${index} requestFingerprint`,
      );
      const fingerprintSource = oneOf(
        call.fingerprintSource,
        ["metered-replay", "pre-metering-rejection"],
        `${cell.mode} model call ${index} fingerprintSource`,
      );
      let errorCategory;
      let providerError;
      let responseProvider;
      let responseModel;
      let cassetteReference;
      if (terminalState === "succeeded") {
        responseProvider = requiredString(
          call.responseProvider,
          `${cell.mode} model call ${index} responseProvider`,
        );
        responseModel = requiredString(
          call.responseModel,
          `${cell.mode} model call ${index} responseModel`,
        );
        if (hasCassetteReference) {
          const reference = objectValue(
            call.cassetteReference,
            `${cell.mode} model call ${index} cassetteReference`,
          );
          assertExactObjectKeys(
            reference,
            [
              "integritySha256",
              "occurrence",
              "relativePath",
              "requestFingerprint",
              "scopeIdSha256",
            ],
            `${cell.mode} model call ${index} cassetteReference`,
          );
          const referenceFingerprint = expectDigest(
            reference.requestFingerprint,
            `${cell.mode} model call ${index} cassette requestFingerprint`,
          );
          const occurrence = nonNegativeInteger(
            reference.occurrence,
            `${cell.mode} model call ${index} cassette occurrence`,
          );
          const relativePath = requiredString(
            reference.relativePath,
            `${cell.mode} model call ${index} cassette relativePath`,
          );
          const integritySha256 = expectDigest(
            reference.integritySha256,
            `${cell.mode} model call ${index} cassette integritySha256`,
          );
          const scopeIdSha256 = expectDigest(
            reference.scopeIdSha256,
            `${cell.mode} model call ${index} cassette scopeIdSha256`,
          );
          expectEqual(
            scopeIdSha256,
            expectedScopeIdSha256,
            `${cell.mode} model call ${index} cassette scope binding`,
          );
          if (
            occurrence < 1 ||
            !/^[a-f0-9]{64}\.[0-9]{6,}\.json$/u.test(
              relativePath,
            )
          ) {
            throw new SummaryError(
              `${cell.mode} model call ${index} has an invalid cassette reference.`,
            );
          }
          cassetteReference = {
            requestFingerprint: referenceFingerprint,
            occurrence,
            relativePath,
            integritySha256,
            scopeIdSha256,
          };
        }
      } else {
        errorCategory = oneOf(
          call.errorCategory,
          MODEL_CALL_ERROR_CATEGORIES,
          `${cell.mode} model call ${index} errorCategory`,
        );
        if (hasProviderError) {
          const details = objectValue(
            call.providerError,
            `${cell.mode} model call ${index} providerError`,
          );
          const detailKeys = [
            ...(Object.prototype.hasOwnProperty.call(details, "status")
              ? ["status"]
              : []),
            ...(Object.prototype.hasOwnProperty.call(details, "errorType")
              ? ["errorType"]
              : []),
            ...(Object.prototype.hasOwnProperty.call(details, "providerCode")
              ? ["providerCode"]
              : []),
          ];
          if (detailKeys.length === 0) {
            throw new SummaryError(
              `${cell.mode} model call ${index} providerError must contain at least one detail.`,
            );
          }
          assertExactObjectKeys(
            details,
            detailKeys,
            `${cell.mode} model call ${index} providerError`,
          );
          const status = detailKeys.includes("status")
            ? nonNegativeInteger(
                details.status,
                `${cell.mode} model call ${index} providerError status`,
              )
            : undefined;
          if (
            status !== undefined &&
            (status < 400 || status > 599)
          ) {
            throw new SummaryError(
              `${cell.mode} model call ${index} providerError status is invalid.`,
            );
          }
          const errorType = detailKeys.includes("errorType")
            ? providerErrorToken(
                details.errorType,
                `${cell.mode} model call ${index} providerError errorType`,
              )
            : undefined;
          const providerCode = detailKeys.includes("providerCode")
            ? providerErrorToken(
                details.providerCode,
                `${cell.mode} model call ${index} providerError providerCode`,
              )
            : undefined;
          providerError = {
            ...(status !== undefined ? { status } : {}),
            ...(errorType ? { errorType } : {}),
            ...(providerCode ? { providerCode } : {}),
          };
        }
      }
      return {
        ordinal,
        role,
        gapFill,
        provider,
        model,
        requestFingerprint,
        fingerprintSource,
        terminalState,
        ...(responseProvider ? { responseProvider } : {}),
        ...(responseModel ? { responseModel } : {}),
        ...(errorCategory ? { errorCategory } : {}),
        ...(providerError ? { providerError } : {}),
        ...(cassetteReference ? { cassetteReference } : {}),
      };
    },
  );
  assertUniqueValues(
    calls.map((call) => call.requestFingerprint),
    `${cell.mode} model-call request fingerprints`,
  );
  const producerValidation = objectValue(
    trace.producerValidation,
    `${cell.mode} model-calls producerValidation`,
  );
  assertExactObjectKeys(
    producerValidation,
    ["errors", "valid"],
    `${cell.mode} model-calls producerValidation`,
  );
  const recordedValidation = {
    valid: booleanValue(
      producerValidation.valid,
      `${cell.mode} model-calls producerValidation valid`,
    ),
    errors: stringArray(
      producerValidation.errors,
      `${cell.mode} model-calls producerValidation errors`,
    ),
  };
  expectStringArraysEqual(
    recordedValidation.errors,
    uniqueSorted(recordedValidation.errors),
    `${cell.mode} model-call producer error ordering`,
  );
  const normalizedTrace = {
    schemaVersion: MODEL_CALL_TRACE_SCHEMA_VERSION,
    runId: cell.runId,
    mode: cell.mode,
    execution,
    cassettePolicy,
    physical: cell.physical,
    derivedFrom,
    detectorStatus,
    candidateCount,
    aggregationDisposition,
    rolePlan,
    traceCompleteness,
    calls,
  };
  const recomputedErrors =
    recomputeModelCallTraceValidation(normalizedTrace);
  if (
    recordedValidation.valid !== (recomputedErrors.length === 0) ||
    canonicalJson(recordedValidation.errors) !==
      canonicalJson(recomputedErrors)
  ) {
    throw new SummaryError(
      `${cell.mode} producerValidation does not match independently recomputed trace validity${
        recomputedErrors.length > 0
          ? `: ${recomputedErrors.join(", ")}`
          : ""
      }.`,
    );
  }
  return {
    ...normalizedTrace,
    producerValidation: recordedValidation,
    validationErrors: recomputedErrors,
  };
}

function validateManifestModelTrace(
  cell,
  declaredModels,
  trace,
  evaluationRun,
  detectorEvidenceValue,
  execution,
) {
  const calls = trace.calls;
  const evaluationCase = evaluationRun.cases.find(
    (candidate) => candidate.fixtureId === cell.fixtureId,
  );
  if (!evaluationCase) {
    throw new SummaryError(
      `${cell.mode}/${cell.fixtureId} has no fixture-specific evaluation evidence for model-call validation.`,
    );
  }
  const strictCompleteCell =
    cell.status === "success" &&
    evaluationCase.completeness.status === "complete";
  if (trace.validationErrors.length > 0) {
    throw new SummaryError(
      `${cell.mode}/${cell.fixtureId} has an invalid independently recomputed model-call trace: ${trace.validationErrors.join(", ")}.`,
    );
  }
  expectEqual(
    trace.traceCompleteness,
    "complete",
    `${cell.mode}/${cell.fixtureId} model-call trace completeness`,
  );
  if (!cell.physical || cell.mode === "scanner-only") {
    if (calls.length !== 0) {
      throw new SummaryError(
        "derived and scanner-only runs cannot trace physical model calls.",
      );
    }
    if (cell.mode === "scanner-only" && declaredModels.length !== 0) {
      throw new SummaryError("scanner-only runs cannot declare models.");
    }
    canonicalEqual(
      trace.rolePlan,
      {
        status: "not-applicable",
        requiredSpecialistRoles: [],
      },
      `${cell.mode}/${cell.fixtureId} non-agent role plan`,
    );
    return false;
  }
  expectEqual(
    trace.detectorStatus,
    cell.status === "success" ? "completed" : cell.status,
    `${cell.mode} model-call detector status binding`,
  );
  const usedModels = uniqueSorted(
    calls.map((call) => `${call.provider}\u0000${call.model}`),
  );
  const declared = uniqueSorted(
    declaredModels.map(
      (entry) => `${entry.provider}\u0000${entry.model}`,
    ),
  );
  expectStringArraysEqual(
    usedModels,
    declared,
    `${cell.mode} manifest/model-call declaration binding`,
  );
  expectEqual(
    calls.length,
    cell.cost.physicalModelCalls,
    `${cell.mode} model-call count`,
  );
  const detectorEvidence = objectValue(
    detectorEvidenceValue,
    `${cell.mode}/${cell.fixtureId} detector evidence`,
  );
  if (
    !Object.prototype.hasOwnProperty.call(
      detectorEvidence,
      "agentEvidence",
    ) &&
    validateAbsentFailFastAgentEvidence(
      cell,
      declaredModels,
      trace,
      execution,
      detectorEvidence,
      evaluationCase,
    )
  ) {
    return true;
  }
  const agentEvidence = objectValue(
    detectorEvidence.agentEvidence,
    `${cell.mode}/${cell.fixtureId} agent evidence`,
  );
  expectEqual(
    agentEvidence.runId,
    cell.runId,
    `${cell.mode}/${cell.fixtureId} agent evidence runId`,
  );
  expectEqual(
    agentEvidence.mode,
    cell.mode === "single-agent" ? "single" : cell.mode,
    `${cell.mode}/${cell.fixtureId} agent evidence mode`,
  );
  expectEqual(
    agentEvidence.status,
    trace.detectorStatus,
    `${cell.mode}/${cell.fixtureId} agent evidence status`,
  );
  const candidates = arrayValue(
    agentEvidence.candidates,
    `${cell.mode}/${cell.fixtureId} agent candidates`,
  );
  expectEqual(
    candidates.length,
    trace.candidateCount,
    `${cell.mode}/${cell.fixtureId} candidate-count evidence binding`,
  );
  const roleExecutions = arrayValue(
    agentEvidence.roles,
    `${cell.mode}/${cell.fixtureId} agent role executions`,
  ).map((candidate, roleIndex) => {
    const roleExecution = objectValue(
      candidate,
      `${cell.mode}/${cell.fixtureId} role execution ${roleIndex}`,
    );
    return {
      role: oneOf(
        roleExecution.role,
        ["single-agent-inspector", ...MOA_SPECIALIST_ROLES],
        `${cell.mode}/${cell.fixtureId} role execution ${roleIndex} role`,
      ),
      gapFill: booleanValue(
        roleExecution.gapFill,
        `${cell.mode}/${cell.fixtureId} role execution ${roleIndex} gapFill`,
      ),
      status: oneOf(
        roleExecution.status,
        [
          "completed",
          "partial",
          "degraded",
          "failed",
          "canceled",
          "skipped",
        ],
        `${cell.mode}/${cell.fixtureId} role execution ${roleIndex} status`,
      ),
    };
  });
  const initialRoleExecutions = roleExecutions.filter(
    (entry) => !entry.gapFill,
  );
  const gapFillRoleExecutions = roleExecutions.filter(
    (entry) => entry.gapFill,
  );
  if (gapFillRoleExecutions.length > 1) {
    throw new SummaryError(
      `${cell.mode}/${cell.fixtureId} records more than one bounded gap-fill role execution.`,
    );
  }
  canonicalEqual(
    initialRoleExecutions.map((entry) => entry.role),
    trace.rolePlan.requiredSpecialistRoles,
    `${cell.mode}/${cell.fixtureId} role-plan/agent-evidence binding`,
  );
  for (const call of calls) {
    if (
      call.role !== "moa-judge" &&
      call.role !== "moa-aggregator" &&
      !roleExecutions.some(
        (entry) =>
          entry.role === call.role && entry.gapFill === call.gapFill,
      )
    ) {
      throw new SummaryError(
        `${cell.mode}/${cell.fixtureId} traces a specialist call without a matching role execution.`,
      );
    }
  }
  if (cell.mode === "single-agent") {
    canonicalEqual(
      trace.rolePlan,
      {
        status: "complete",
        requiredSpecialistRoles: ["single-agent-inspector"],
      },
      `${cell.mode}/${cell.fixtureId} role plan`,
    );
    if (
      calls.some(
        (call) =>
          call.role !== "single-agent-inspector" || call.gapFill,
      )
    ) {
      throw new SummaryError(
        "single-agent model calls must carry the single-agent-inspector role.",
      );
    }
    if (
      calls.some((call) => call.model === MINIMAX_AGGREGATOR)
    ) {
      throw new SummaryError(
        "Minimax is prohibited outside explicit moa-aggregator calls.",
      );
    }
    if (
      strictCompleteCell &&
      !calls.some((call) => call.terminalState === "succeeded")
    ) {
      throw new SummaryError(
        "a successful complete single-agent cell must trace a successful inspector call.",
      );
    }
    return false;
  }
  if (trace.rolePlan.status !== "complete") {
    throw new SummaryError(
      `${cell.mode}/${cell.fixtureId} must carry a complete explicit specialist role plan.`,
    );
  }
  if (
    cell.mode === "moa-low" &&
    (trace.rolePlan.requiredSpecialistRoles.length !== 3 ||
      trace.rolePlan.requiredSpecialistRoles.some(
        (role) => !MOA_SPECIALIST_ROLES.includes(role),
      ))
  ) {
    throw new SummaryError(
      `${cell.mode}/${cell.fixtureId} must bind the exact three specialists selected by the producer.`,
    );
  }
  if (
    cell.mode === "moa-high" &&
    canonicalJson(trace.rolePlan.requiredSpecialistRoles) !==
      canonicalJson(MOA_SPECIALIST_ROLES)
  ) {
    throw new SummaryError(
      `${cell.mode}/${cell.fixtureId} must bind the canonical five-specialist MoA High plan.`,
    );
  }
  if (calls.some((call) => !MOA_ROLES.includes(call.role))) {
    throw new SummaryError(
      `${cell.mode} model calls must use explicit canonical MoA roles.`,
    );
  }
  if (
    calls.some(
      (call) =>
        (call.role === "moa-judge" ||
          call.role === "moa-aggregator") &&
        call.gapFill,
    )
  ) {
    throw new SummaryError(
      `${cell.mode}/${cell.fixtureId} judge and aggregator calls cannot be marked as gap-fill.`,
    );
  }
  const initialSpecialistCalls = calls.filter(
    (call) =>
      MOA_SPECIALIST_ROLES.includes(call.role) && !call.gapFill,
  );
  const gapFillCalls = calls.filter(
    (call) =>
      MOA_SPECIALIST_ROLES.includes(call.role) && call.gapFill,
  );
  const initialCallRoles = uniqueSorted(
    initialSpecialistCalls.map((call) => call.role),
  );
  const requiredInitialRoles = uniqueSorted(
    trace.rolePlan.requiredSpecialistRoles,
  );
  const missingInitialRoles = requiredInitialRoles.filter(
    (role) => !initialCallRoles.includes(role),
  );
  if (
    canonicalJson(initialCallRoles) !==
      canonicalJson(requiredInitialRoles) &&
    !validLiveFailFastInitialSpecialistSubset({
      cell,
      trace,
      execution,
      calls,
      initialCallRoles,
      requiredInitialRoles,
      missingInitialRoles,
      initialRoleExecutions,
      gapFillCalls,
    })
  ) {
    throw new SummaryError(
      `${cell.mode}/${cell.fixtureId} exact initial specialist-call set does not match its role plan or a strictly contained live fail-fast subset.`,
    );
  }
  if (
    strictCompleteCell &&
    trace.rolePlan.requiredSpecialistRoles.some(
      (role) =>
        !initialSpecialistCalls.some(
          (call) =>
            call.role === role &&
            call.terminalState === "succeeded",
        ),
    )
  ) {
    throw new SummaryError(
      `${cell.mode}/${cell.fixtureId} completed cell is under-provisioned for its planned specialists.`,
    );
  }
  if (
    gapFillCalls.length > 4 ||
    new Set(gapFillCalls.map((call) => call.role)).size > 1
  ) {
    throw new SummaryError(
      `${cell.mode}/${cell.fixtureId} exceeds the single bounded MoA gap-fill pass.`,
    );
  }
  if (
    gapFillCalls.length > 0 &&
    (gapFillRoleExecutions.length !== 1 ||
      gapFillRoleExecutions[0].role !== gapFillCalls[0].role)
  ) {
    throw new SummaryError(
      `${cell.mode}/${cell.fixtureId} gap-fill calls do not match the recorded gap-fill role execution.`,
    );
  }
  const coverage = objectValue(
    agentEvidence.coverage,
    `${cell.mode}/${cell.fixtureId} MoA coverage`,
  );
  expectEqual(
    coverage.kind,
    "moa",
    `${cell.mode}/${cell.fixtureId} MoA coverage kind`,
  );
  expectEqual(
    booleanValue(
      coverage.gapFillExecuted,
      `${cell.mode}/${cell.fixtureId} MoA gapFillExecuted`,
    ),
    gapFillRoleExecutions.length === 1,
    `${cell.mode}/${cell.fixtureId} MoA gap-fill execution binding`,
  );
  const lastInitialSpecialistOrdinal = Math.max(
    0,
    ...initialSpecialistCalls.map((call) => call.ordinal),
  );
  const firstAdjudicationOrdinal = Math.min(
    Number.POSITIVE_INFINITY,
    ...calls
      .filter(
        (call) =>
          call.role === "moa-judge" ||
          call.role === "moa-aggregator",
      )
      .map((call) => call.ordinal),
  );
  if (
    gapFillCalls.some(
      (call) =>
        call.ordinal <= lastInitialSpecialistOrdinal ||
        call.ordinal >= firstAdjudicationOrdinal,
    )
  ) {
    throw new SummaryError(
      `${cell.mode}/${cell.fixtureId} gap-fill calls must follow all initial specialists and precede adjudication.`,
    );
  }
  const aggregators = calls.filter(
    (call) => call.role === "moa-aggregator",
  );
  const judges = calls.filter((call) => call.role === "moa-judge");
  if (aggregators.length > 1) {
    throw new SummaryError(
      `${cell.mode} contains multiple Minimax aggregator calls.`,
    );
  }
  if (trace.candidateCount === 0) {
    if (judges.length > 0 || aggregators.length > 0) {
      throw new SummaryError(
        `${cell.mode}/${cell.fixtureId} zero-candidate runs cannot call the judge or aggregator.`,
      );
    }
  } else {
    if (
      strictCompleteCell &&
      (judges.length !== 1 ||
        judges[0].terminalState !== "succeeded")
    ) {
      throw new SummaryError(
        `${cell.mode}/${cell.fixtureId} candidate-bearing completed cell requires one successful judge call.`,
      );
    }
    if (
      strictCompleteCell &&
      (aggregators.length !== 1 ||
        aggregators[0].terminalState !== "succeeded")
    ) {
      throw new SummaryError(
        `${cell.mode}/${cell.fixtureId} candidate-bearing completed cell requires exactly one successful terminal Minimax aggregator call.`,
      );
    }
  }
  if (aggregators.length === 1) {
    const aggregator = aggregators[0];
    expectEqual(
      aggregator.model,
      MINIMAX_AGGREGATOR,
      `${cell.mode} aggregator model`,
    );
    expectEqual(
      aggregator.ordinal,
      calls.length,
      `${cell.mode} terminal aggregator ordinal`,
    );
    if (
      !calls
        .slice(0, -1)
        .some((call) => call.role !== "moa-aggregator")
    ) {
      throw new SummaryError(
        `${cell.mode} aggregation requires preceding explicitly attributed specialist or judge evidence.`,
      );
    }
  }
  for (const call of calls) {
    if (
      call.model === MINIMAX_AGGREGATOR &&
      call.role !== "moa-aggregator"
    ) {
      throw new SummaryError(
        "Minimax is permitted only for the explicit moa-aggregator role.",
      );
    }
  }
  return false;
}

function validLiveFailFastInitialSpecialistSubset(input) {
  if (
    input.execution !== "live" ||
    input.cell.status !== "canceled" ||
    input.trace.detectorStatus !== "canceled" ||
    input.initialCallRoles.length === 0 ||
    input.missingInitialRoles.length === 0 ||
    input.initialCallRoles.some(
      (role) => !input.requiredInitialRoles.includes(role),
    ) ||
    canonicalJson(input.initialCallRoles) !==
      canonicalJson(
        uniqueSorted(
          input.trace.rolePlan.requiredSpecialistRoles.slice(
            0,
            input.initialCallRoles.length,
          ),
        ),
      ) ||
    input.gapFillCalls.length !== 0 ||
    input.calls.some(
      (call) =>
        call.role === "moa-judge" ||
        call.role === "moa-aggregator",
    )
  ) {
    return false;
  }
  const failedCalls = input.calls.filter(
    (call) => call.terminalState === "failed",
  );
  if (
    failedCalls.length !== 1 ||
    !input.initialCallRoles.includes(failedCalls[0].role)
  ) {
    return false;
  }
  return input.missingInitialRoles.every((role) =>
    input.initialRoleExecutions.some(
      (execution) =>
        execution.role === role &&
        (execution.status === "canceled" ||
          execution.status === "skipped"),
    ),
  );
}

function validateAbsentFailFastAgentEvidence(
  cell,
  declaredModels,
  trace,
  execution,
  detectorEvidence,
  evaluationCase,
) {
  if (
    execution !== "live" ||
    !cell.physical ||
    cell.mode === "scanner-only" ||
    cell.status !== "canceled"
  ) {
    return false;
  }
  expectEqual(
    trace.detectorStatus,
    "canceled",
    `${cell.mode}/${cell.fixtureId} fail-fast detector status`,
  );
  expectEqual(
    trace.candidateCount,
    0,
    `${cell.mode}/${cell.fixtureId} fail-fast candidate count`,
  );
  if (!["none", "recorded"].includes(trace.cassettePolicy)) {
    throw new SummaryError(
      `${cell.mode}/${cell.fixtureId} fail-fast cassette policy is not valid for live execution.`,
    );
  }
  expectEqual(
    trace.calls.length,
    0,
    `${cell.mode}/${cell.fixtureId} fail-fast model calls`,
  );
  expectEqual(
    trace.calls.filter(
      (call) => call.cassetteReference !== undefined,
    ).length,
    0,
    `${cell.mode}/${cell.fixtureId} fail-fast cassette references`,
  );
  expectEqual(
    declaredModels.length,
    0,
    `${cell.mode}/${cell.fixtureId} fail-fast declared models`,
  );
  for (const [field, value] of Object.entries(cell.cost)) {
    expectEqual(
      value,
      0,
      `${cell.mode}/${cell.fixtureId} fail-fast ${field}`,
    );
  }
  assertExactObjectKeys(
    detectorEvidence,
    [
      "finalFindings",
      "rawAgentFindings",
      "rawScannerFindings",
      "schemaVersion",
    ],
    `${cell.mode}/${cell.fixtureId} fail-fast detector evidence`,
  );
  expectEqual(
    detectorEvidence.schemaVersion,
    "1.0",
    `${cell.mode}/${cell.fixtureId} fail-fast detector evidence schema`,
  );
  for (const [field, value] of [
    ["finalFindings", detectorEvidence.finalFindings],
    ["rawAgentFindings", detectorEvidence.rawAgentFindings],
    ["rawScannerFindings", detectorEvidence.rawScannerFindings],
  ]) {
    expectEqual(
      arrayValue(
        value,
        `${cell.mode}/${cell.fixtureId} fail-fast ${field}`,
      ).length,
      0,
      `${cell.mode}/${cell.fixtureId} fail-fast ${field}`,
    );
  }
  expectEqual(
    evaluationCase.completeness.status,
    "degraded",
    `${cell.mode}/${cell.fixtureId} fail-fast completeness status`,
  );
  const completenessInput = evaluationCase.completenessInput;
  if (
    !(completenessInput.degradedReasons ?? []).some((reason) =>
      reason.startsWith("Strict live paid gate stopped "),
    )
  ) {
    throw new SummaryError(
      `${cell.mode}/${cell.fixtureId} fail-fast completeness lacks the strict paid-gate reason.`,
    );
  }
  expectEqual(
    completenessInput.completedComponents.length,
    0,
    `${cell.mode}/${cell.fixtureId} fail-fast completed components`,
  );
  expectEqual(
    (completenessInput.failedComponents ?? []).length,
    0,
    `${cell.mode}/${cell.fixtureId} fail-fast failed components`,
  );
  expectStringArraysEqual(
    uniqueSorted(completenessInput.skippedComponents ?? []),
    uniqueSorted(completenessInput.plannedComponents),
    `${cell.mode}/${cell.fixtureId} fail-fast skipped components`,
  );
  expectEqual(
    completenessInput.inspectedFiles ?? 0,
    0,
    `${cell.mode}/${cell.fixtureId} fail-fast inspected files`,
  );
  expectEqual(
    completenessInput.inspectedBytes ?? 0,
    0,
    `${cell.mode}/${cell.fixtureId} fail-fast inspected bytes`,
  );
  if (cell.mode === "single-agent") {
    canonicalEqual(
      trace.rolePlan,
      {
        status: "complete",
        requiredSpecialistRoles: ["single-agent-inspector"],
      },
      `${cell.mode}/${cell.fixtureId} fail-fast role plan`,
    );
    return true;
  }
  if (
    trace.rolePlan.status !== "complete" ||
    (cell.mode === "moa-low" &&
      (trace.rolePlan.requiredSpecialistRoles.length !== 3 ||
        trace.rolePlan.requiredSpecialistRoles.some(
          (role) => !MOA_SPECIALIST_ROLES.includes(role),
        ))) ||
    (cell.mode === "moa-high" &&
      canonicalJson(trace.rolePlan.requiredSpecialistRoles) !==
        canonicalJson(MOA_SPECIALIST_ROLES))
  ) {
    throw new SummaryError(
      `${cell.mode}/${cell.fixtureId} fail-fast placeholder lacks its valid explicit role plan.`,
    );
  }
  return true;
}

function recomputeModelCallTraceValidation(trace) {
  const errors = recomputeModelCallTraceSemanticErrors(trace);
  const expectedCompleteness =
    errors.length === 0 ? "complete" : "incomplete";
  if (trace.traceCompleteness !== expectedCompleteness) {
    errors.push("model-call-trace-completeness-invalid");
  }
  return uniqueSorted(errors);
}

function recomputeModelCallTraceSemanticErrors(trace) {
  const errors = [];
  const calls = trace.calls;
  const derivedFrom = trace.derivedFrom;
  const rolePlan = trace.rolePlan;
  if (
    trace.schemaVersion !== MODEL_CALL_TRACE_SCHEMA_VERSION ||
    typeof trace.runId !== "string" ||
    !trace.runId.trim() ||
    typeof trace.mode !== "string" ||
    !trace.mode.trim() ||
    !["mock", "replay", "live"].includes(trace.execution) ||
    !["none", "recorded", "replay"].includes(
      trace.cassettePolicy,
    ) ||
    ![
      "completed",
      "partial",
      "degraded",
      "failed",
      "canceled",
      "not-applicable",
    ].includes(trace.detectorStatus) ||
    !Number.isSafeInteger(trace.candidateCount) ||
    trace.candidateCount < 0 ||
    !Array.isArray(calls) ||
    !Array.isArray(derivedFrom) ||
    !validModelCallRolePlanShape(rolePlan)
  ) {
    errors.push("model-call-trace-schema-invalid");
  }
  const expectedAggregationDisposition =
    trace.mode === "moa-low" || trace.mode === "moa-high"
      ? trace.candidateCount > 0
        ? "required"
        : "not-required-no-candidates"
      : "not-applicable";
  if (trace.aggregationDisposition !== expectedAggregationDisposition) {
    errors.push("model-call-aggregation-disposition-invalid");
  }
  if (!trace.physical) {
    if (trace.cassettePolicy !== "none") {
      errors.push("derived-run-cassette-policy-invalid");
    }
    if (calls.length > 0) {
      errors.push("derived-run-has-physical-model-calls");
    }
    if (derivedFrom.length === 0) {
      errors.push("derived-run-missing-derivation");
    }
    if (
      rolePlan.status !== "not-applicable" ||
      rolePlan.requiredSpecialistRoles.length !== 0
    ) {
      errors.push("derived-run-role-plan-invalid");
    }
    return uniqueSorted(errors);
  }
  if (derivedFrom.length > 0) {
    errors.push("physical-run-declares-derivation");
  }
  const isAgentMode = [
    "single-agent",
    "moa-low",
    "moa-high",
  ].includes(trace.mode);
  if (!isAgentMode && trace.cassettePolicy !== "none") {
    errors.push("non-agent-run-cassette-policy-invalid");
  }
  if (
    trace.cassettePolicy === "replay" &&
    trace.execution !== "replay"
  ) {
    errors.push("replay-cassette-policy-execution-invalid");
  }
  if (
    trace.cassettePolicy === "recorded" &&
    !["mock", "live"].includes(trace.execution)
  ) {
    errors.push("recorded-cassette-policy-execution-invalid");
  }
  if (
    trace.execution === "replay" &&
    isAgentMode &&
    trace.cassettePolicy !== "replay"
  ) {
    errors.push("replay-agent-cassette-policy-missing");
  }
  if (!isAgentMode && calls.length > 0) {
    errors.push("non-agent-run-has-model-calls");
  }
  if (
    !isAgentMode &&
    (rolePlan.status !== "not-applicable" ||
      rolePlan.requiredSpecialistRoles.length !== 0)
  ) {
    errors.push("non-agent-run-role-plan-invalid");
  }
  if (
    isAgentMode &&
    trace.detectorStatus === "completed" &&
    calls.length === 0
  ) {
    errors.push("successful-agent-run-has-zero-model-calls");
  }
  const seenOrdinals = new Set();
  for (const [index, call] of calls.entries()) {
    if (
      !Number.isSafeInteger(call.ordinal) ||
      call.ordinal !== index + 1 ||
      seenOrdinals.has(call.ordinal)
    ) {
      errors.push("model-call-ordinal-invalid");
    }
    seenOrdinals.add(call.ordinal);
    if (
      call.provider !== "openrouter" ||
      !/^[a-f0-9]{64}$/u.test(call.requestFingerprint) ||
      !["metered-replay", "pre-metering-rejection"].includes(
        call.fingerprintSource,
      ) ||
      !MODEL_CALL_TERMINAL_STATES.includes(call.terminalState)
    ) {
      errors.push("model-call-entry-invalid");
    }
    if (
      call.fingerprintSource === "pre-metering-rejection" &&
      call.terminalState !== "failed"
    ) {
      errors.push("pre-metering-rejection-terminal-invalid");
    }
    if (
      call.cassetteReference !== undefined &&
      (!validReplayReference(call.cassetteReference) ||
        call.cassetteReference.requestFingerprint !==
          call.requestFingerprint ||
        !call.cassetteReference.scopeIdSha256 ||
        trace.cassettePolicy === "none" ||
        call.fingerprintSource !== "metered-replay")
    ) {
      errors.push("model-call-cassette-reference-invalid");
    }
    if (
      trace.cassettePolicy !== "none" &&
      call.terminalState === "succeeded" &&
      !call.cassetteReference
    ) {
      errors.push("successful-replay-call-missing-cassette-reference");
    }
    if (
      !(call.role in EXACT_ROLE_MODELS) ||
      call.model !== EXACT_ROLE_MODELS[call.role]
    ) {
      errors.push("model-call-role-model-mismatch");
    }
    if (
      call.terminalState === "succeeded" &&
      (call.responseProvider !== call.provider ||
        call.responseModel !== call.model)
    ) {
      errors.push("model-call-response-binding-mismatch");
    }
    if (
      call.terminalState !== "succeeded" &&
      !MODEL_CALL_ERROR_CATEGORIES.includes(call.errorCategory)
    ) {
      errors.push("failed-model-call-error-category-invalid");
    }
    if (
      (call.terminalState === "canceled" &&
        call.errorCategory !== "aborted") ||
      (call.terminalState === "failed" &&
        call.errorCategory === "aborted")
    ) {
      errors.push("model-call-terminal-error-category-mismatch");
    }
    if (
      call.terminalState === "succeeded" &&
      (call.errorCategory !== undefined ||
        call.providerError !== undefined)
    ) {
      errors.push("successful-model-call-has-error");
    }
    if (
      call.terminalState !== "succeeded" &&
      (call.responseProvider !== undefined ||
        call.responseModel !== undefined)
    ) {
      errors.push("failed-model-call-has-response-binding");
    }
    if (call.providerError !== undefined) {
      if (
        call.terminalState !== "failed" ||
        call.fingerprintSource !== "metered-replay" ||
        !validProviderErrorDetails(call.providerError)
      ) {
        errors.push("model-call-provider-error-invalid");
      } else if (
        call.errorCategory !==
        classifyProviderErrorDetails(call.providerError)
      ) {
        errors.push("model-call-provider-error-category-mismatch");
      }
    } else if (
      call.errorCategory === "rate-limit" ||
      call.errorCategory === "provider-unavailable"
    ) {
      errors.push("transient-model-call-missing-provider-error");
    }
  }
  const aggregators = calls.filter(
    (call) => call.role === "moa-aggregator",
  );
  const judges = calls.filter((call) => call.role === "moa-judge");
  const specialistCalls = calls.filter((call) =>
    MOA_SPECIALIST_ROLES.includes(call.role),
  );
  const minimaxCalls = calls.filter(
    (call) => call.model === MINIMAX_AGGREGATOR,
  );
  if (
    aggregators.some(
      (call) => call.model !== MINIMAX_AGGREGATOR,
    ) ||
    minimaxCalls.some((call) => call.role !== "moa-aggregator")
  ) {
    errors.push("minimax-aggregator-role-invalid");
  }
  if (aggregators.length > 1 || minimaxCalls.length > 1) {
    errors.push("multiple-moa-aggregator-calls");
  }
  if (
    aggregators.length === 1 &&
    aggregators[0].ordinal !== calls.length
  ) {
    errors.push("moa-aggregator-not-terminal");
  }
  if (trace.mode === "single-agent") {
    if (
      rolePlan.status !== "complete" ||
      canonicalJson(rolePlan.requiredSpecialistRoles) !==
        canonicalJson(["single-agent-inspector"])
    ) {
      errors.push("single-agent-role-plan-invalid");
    }
    if (
      calls.some(
        (call) => call.role !== "single-agent-inspector",
      )
    ) {
      errors.push("single-agent-role-invalid");
    }
    if (
      trace.detectorStatus === "completed" &&
      !calls.some(
        (call) =>
          call.role === "single-agent-inspector" &&
          call.terminalState === "succeeded",
      )
    ) {
      errors.push("successful-single-agent-call-missing");
    }
  } else if (trace.mode === "moa-low" || trace.mode === "moa-high") {
    const requiredRoles =
      rolePlan.status === "complete"
        ? rolePlan.requiredSpecialistRoles
        : [];
    if (rolePlan.status !== "complete") {
      errors.push("moa-role-plan-unavailable");
    } else if (
      trace.mode === "moa-low" &&
      (requiredRoles.length !== 3 ||
        requiredRoles.some(
          (role) => !MOA_SPECIALIST_ROLES.includes(role),
        ))
    ) {
      errors.push("moa-low-role-plan-invalid");
    } else if (
      trace.mode === "moa-high" &&
      canonicalJson(requiredRoles) !== canonicalJson(MOA_SPECIALIST_ROLES)
    ) {
      errors.push("moa-high-role-plan-invalid");
    }
    if (
      calls.some(
        (call) => call.role === "single-agent-inspector",
      )
    ) {
      errors.push("moa-single-agent-role-invalid");
    }
    if (
      specialistCalls.some(
        (call) => !requiredRoles.includes(call.role),
      )
    ) {
      errors.push("moa-unplanned-specialist-call");
    }
    if (
      trace.detectorStatus === "completed" &&
      requiredRoles.some(
        (role) =>
          !specialistCalls.some(
            (call) =>
              call.role === role &&
              call.terminalState === "succeeded",
          ),
      )
    ) {
      errors.push("successful-moa-role-plan-under-provisioned");
    }
    if (trace.candidateCount > 0) {
      if (
        trace.detectorStatus === "completed" &&
        (judges.length !== 1 ||
          judges[0]?.terminalState !== "succeeded")
      ) {
        errors.push("candidate-bearing-moa-judge-incomplete");
      }
      if (
        trace.detectorStatus === "completed" &&
        (aggregators.length !== 1 ||
          aggregators[0]?.terminalState !== "succeeded")
      ) {
        errors.push("candidate-bearing-moa-aggregator-incomplete");
      }
      const judgeOrdinal = judges[0]?.ordinal;
      const aggregatorOrdinal = aggregators[0]?.ordinal;
      const lastSpecialistOrdinal = Math.max(
        0,
        ...specialistCalls.map((call) => call.ordinal),
      );
      if (
        judgeOrdinal !== undefined &&
        judgeOrdinal <= lastSpecialistOrdinal
      ) {
        errors.push("moa-judge-before-specialists-complete");
      }
      if (
        aggregatorOrdinal !== undefined &&
        (aggregatorOrdinal <= (judgeOrdinal ?? 0) ||
          aggregatorOrdinal <= lastSpecialistOrdinal)
      ) {
        errors.push("moa-aggregator-order-invalid");
      }
    } else if (judges.length > 0 || aggregators.length > 0) {
      errors.push("zero-candidate-moa-has-adjudication-calls");
    }
  }
  return uniqueSorted(errors);
}

function validReplayReference(value) {
  return (
    value &&
    typeof value === "object" &&
    /^[a-f0-9]{64}$/u.test(value.requestFingerprint) &&
    Number.isSafeInteger(value.occurrence) &&
    value.occurrence > 0 &&
    typeof value.relativePath === "string" &&
    /^[a-f0-9]{64}\.[0-9]{6,}\.json$/u.test(value.relativePath) &&
    /^[a-f0-9]{64}$/u.test(value.integritySha256) &&
    (value.scopeIdSha256 === undefined ||
      /^[a-f0-9]{64}$/u.test(value.scopeIdSha256))
  );
}

function zeroCellCost(cost) {
  return [
    cost.actualPhysicalSpendUsd,
    cost.conservativeCommittedUsd,
    cost.attributedCostUsd,
    cost.physicalModelCalls,
    cost.attributedModelCalls,
    cost.physicalTokens,
    cost.attributedTokens,
  ].every((value) => value === 0);
}

function providerErrorToken(value, label) {
  const token = requiredString(value, label);
  if (
    !/^[a-z0-9][a-z0-9._-]{0,99}$/u.test(token) ||
    !redactionStableProviderErrorToken(token)
  ) {
    throw new SummaryError(`${label} is invalid.`);
  }
  return token;
}

function validProviderErrorDetails(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const keys = Object.keys(value);
  if (
    keys.length === 0 ||
    keys.some(
      (key) =>
        key !== "status" &&
        key !== "errorType" &&
        key !== "providerCode",
    )
  ) {
    return false;
  }
  return (
    (value.status === undefined ||
      (Number.isSafeInteger(value.status) &&
        value.status >= 400 &&
        value.status <= 599)) &&
    (value.errorType === undefined ||
      (typeof value.errorType === "string" &&
        /^[a-z0-9][a-z0-9._-]{0,99}$/u.test(value.errorType) &&
        redactionStableProviderErrorToken(value.errorType))) &&
    (value.providerCode === undefined ||
      (typeof value.providerCode === "string" &&
        /^[a-z0-9][a-z0-9._-]{0,99}$/u.test(value.providerCode) &&
        redactionStableProviderErrorToken(value.providerCode)))
  );
}

function classifyProviderErrorDetails(details) {
  const status = details.status;
  const errorType = details.errorType;
  if (errorType === "rate_limit_exceeded") {
    return status === undefined || status === 429
      ? "rate-limit"
      : "provider";
  }
  if (
    errorType === "provider_overloaded" ||
    errorType === "provider_unavailable"
  ) {
    const allowedStatuses =
      errorType === "provider_overloaded"
        ? [502, 503, 529]
        : [404, 502, 503, 529];
    return status === undefined || allowedStatuses.includes(status)
      ? "provider-unavailable"
      : "provider";
  }
  if (errorType === "server") {
    return status === undefined || [500, 502, 503].includes(status)
      ? "provider-unavailable"
      : "provider";
  }
  if (errorType === "timeout") {
    return status === undefined || status === 408 || status === 504
      ? "timeout"
      : "provider";
  }
  if (
    errorType === "content_policy_violation" ||
    errorType === "refusal"
  ) {
    return status === undefined || status === 400 || status === 403
      ? "unsafe-request"
      : "provider";
  }
  if (errorType !== undefined) {
    return "provider";
  }
  if (status === 429) {
    return "rate-limit";
  }
  if (status === 502 || status === 503 || status === 529) {
    return "provider-unavailable";
  }
  if (status === 408 || status === 504) {
    return "timeout";
  }
  return "provider";
}

function redactionStableProviderErrorToken(value) {
  return ![
    /\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[a-z0-9_]{20,}\b/u,
    /\bglpat-[a-z0-9_-]{20,}\b/u,
    /\bsk-[a-z0-9_-]{16,}\b/u,
    /\bxox[baprs]-[a-z0-9-]{16,}\b/u,
    /\b(?:sk|rk)_(?:live|test)_[a-z0-9]{16,}\b/u,
  ].some((pattern) => pattern.test(value));
}

function validModelCallRolePlanShape(value) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    ["complete", "unavailable", "not-applicable"].includes(
      value.status,
    ) &&
    Array.isArray(value.requiredSpecialistRoles) &&
    value.requiredSpecialistRoles.every(
      (role) =>
        role === "single-agent-inspector" ||
        MOA_SPECIALIST_ROLES.includes(role),
    ) &&
    new Set(value.requiredSpecialistRoles).size ===
      value.requiredSpecialistRoles.length
  );
}

function bindArtifactData(input) {
  const result = objectValue(
    input.artifactData.get("result.json"),
    "result artifact data",
  );
  expectEqual(result.schemaVersion, "1.0", "result artifact schemaVersion");
  for (const [label, actual, expected] of [
    ["runId", result.runId, input.cell.runId],
    ["fixtureId", result.fixtureId, input.cell.fixtureId],
    ["mode", result.mode, input.cell.mode],
    ["execution", result.execution, input.manifest.execution],
    ["physical", result.physical, input.cell.physical],
    ["status", result.status, input.cell.status],
  ]) {
    expectEqual(actual, expected, `result artifact ${label}`);
  }
  canonicalEqual(
    result.derivedFrom,
    input.cell.derivedFrom,
    "result artifact derivedFrom",
  );
  expectEqual(
    result.startedAt,
    input.manifest.startedAt,
    "result artifact startedAt",
  );
  expectEqual(
    result.finishedAt,
    input.manifest.finishedAt,
    "result artifact finishedAt",
  );
  const resultFindings = arrayValue(
    result.findings,
    "result artifact findings",
  );
  const resultDegradation = stringArray(
    result.degradationReasons,
    "result artifact degradationReasons",
  );
  canonicalEqual(
    resultDegradation,
    input.metadata.degradationReasons,
    "manifest degradation reason binding",
  );

  const evidence = objectValue(
    input.artifactData.get("detector-evidence.json"),
    "detector evidence artifact data",
  );
  expectEqual(
    evidence.schemaVersion,
    "1.0",
    "detector evidence artifact schemaVersion",
  );
  arrayValue(evidence.rawScannerFindings, "raw scanner findings");
  arrayValue(evidence.rawAgentFindings, "raw agent findings");
  canonicalEqual(
    evidence.finalFindings,
    resultFindings,
    "detector evidence final findings",
  );

  const cost = objectValue(
    input.artifactData.get("cost.json"),
    "cost artifact data",
  );
  canonicalEqual(cost, input.cell.cost, "cost artifact cell binding");

  const sourceState = objectValue(
    input.artifactData.get("source-state.json"),
    "source-state artifact data",
  );
  canonicalEqual(
    sourceState,
    input.manifest.sourceState,
    "source-state manifest binding",
  );
  if (!input.sourceState || !input.truthEvidence) {
    throw new SummaryError(
      "suite-index v3 is missing canonical source/truth evidence for a run fixture.",
    );
  }
  canonicalEqual(
    sourceState,
    input.sourceState,
    "source-state suite source-index binding",
  );

  const evaluationCase = input.evaluationRun.cases.find(
    (candidate) => candidate.fixtureId === input.cell.fixtureId,
  );
  if (!evaluationCase) {
    throw new SummaryError(
      "run manifest has no matching evaluation fixture case.",
    );
  }
  canonicalEqual(
    evaluationCase.manifest,
    input.truthEvidence.manifest,
    "evaluation/canonical fixture manifest binding",
  );
  canonicalEqual(
    evaluationCase.truth.raw,
    input.truthEvidence.truth,
    "evaluation/canonical truth binding",
  );
  expectEqual(
    sha256Hex(canonicalJson(evaluationCase.truth.raw)),
    input.truthEvidence.truthSha256,
    "evaluation canonical truth hash",
  );
  expectEqual(
    evaluationCase.fixtureRoot,
    `fixture://${encodeURIComponent(input.cell.fixtureId)}`,
    "evaluation fixture URI binding",
  );
  canonicalEqual(
    evaluationCase.truthArtifact,
    {
      fixtureId: input.cell.fixtureId,
      path: input.truthEvidence.binding.path,
      sha256: input.truthEvidence.binding.artifactSha256,
      fixtureDigestSha256:
        input.truthEvidence.binding.fixtureDigestSha256,
    },
    "evaluation canonical truth artifact binding",
  );
  canonicalEqual(
    objectValue(
      input.metadata.truthArtifact,
      "manifest metadata truthArtifact",
    ),
    {
      fixtureId: input.cell.fixtureId,
      path: input.truthEvidence.binding.path,
      fixtureDigestSha256:
        input.truthEvidence.binding.fixtureDigestSha256,
      projectRoot: FIXTURE_PROJECT_ROOT,
      projectDigestSha256:
        input.truthEvidence.binding.projectDigestSha256,
      evaluatorDigestSha256:
        input.truthEvidence.binding.evaluatorDigestSha256,
      layoutBindingSha256:
        input.truthEvidence.binding.layoutBindingSha256,
    },
    "manifest canonical truth artifact binding",
  );
  expectEqual(
    input.manifest.sourceState.fixtureDigestSha256,
    input.truthEvidence.binding.fixtureDigestSha256,
    "manifest source/canonical truth fixture digest",
  );
  const sourceFiles = arrayValue(
    sourceState.files,
    "source-state files",
  );
  const truthSourceState = sourceFiles.find(
    (candidate) =>
      objectValue(candidate, "source-state file").path === "truth.json",
  );
  if (!truthSourceState) {
    throw new SummaryError(
      "source-state evidence must contain the immutable truth.json digest.",
    );
  }
  const truthSourceRecord = objectValue(
    truthSourceState,
    "source-state truth.json",
  );
  nonNegativeInteger(
    truthSourceRecord.bytes,
    "source-state truth.json bytes",
  );
  expectDigest(
    truthSourceRecord.sha256,
    "source-state truth.json sha256",
  );
  let recomputedMatch;
  try {
    const projected = input.evaluationEngine.projectFindings(
      resultFindings,
      { fixtureRoot: "$FIXTURE_ROOT" },
    );
    recomputedMatch = input.evaluationEngine.matchFindings(
      evaluationCase.truth.raw.findings,
      projected,
    );
  } catch {
    throw new SummaryError(
      `${input.cell.mode}/${input.cell.fixtureId} immutable finding evidence cannot be replayed by the canonical evaluator.`,
    );
  }
  canonicalEqual(
    recomputedMatch,
    evaluationCase.matchResult.raw,
    `${input.cell.mode}/${input.cell.fixtureId} recomputed full match semantics`,
  );
  const immutableFindings = resultFindings.map((candidate, index) => {
    const finding = objectValue(
      candidate,
      `result artifact finding ${index}`,
    );
    return {
      id: requiredString(
        finding.id,
        `result artifact finding ${index} id`,
      ),
      category: oneOf(
        finding.category,
        EVAL_CATEGORIES,
        `result artifact finding ${index} category`,
      ),
    };
  });
  assertUniqueValues(
    immutableFindings.map((finding) => finding.id),
    "result artifact finding IDs",
  );
  const immutableById = new Map(
    immutableFindings.map((finding) => [finding.id, finding]),
  );
  const representedActual = [
    ...evaluationCase.matchResult.matches.map((match) => ({
      id: match.actualId,
      category: match.actualCategory,
    })),
    ...evaluationCase.matchResult.falsePositives.map((finding) => ({
      id: finding.id,
      category: finding.category,
    })),
    ...evaluationCase.matchResult.ignoredActual.map((finding) => ({
      id: finding.id,
      category: finding.category,
    })),
  ];
  assertUniqueValues(
    representedActual.map((finding) => finding.id),
    "evaluation represented actual finding IDs",
  );
  expectStringArraysEqual(
    representedActual.map((finding) => finding.id).sort(compareText),
    [...immutableById.keys()].sort(compareText),
    "evaluation/result finding partition",
  );
  for (const finding of representedActual) {
    expectEqual(
      finding.category,
      immutableById.get(finding.id)?.category,
      `evaluation/result finding ${finding.id} category`,
    );
  }
  const completenessInput = readCompletenessInput(
    input.artifactData.get("completeness.json"),
    "completeness artifact data",
    evaluationCase.sourceFileCount,
  );
  canonicalEqual(
    completenessInput,
    evaluationCase.completenessInput,
    "completeness artifact evaluation binding",
  );
}

async function validateCostLedger(input) {
  let suiteRoot;
  try {
    suiteRoot = await fs.realpath(input.suiteDirectory);
  } catch {
    throw new SummaryError("Unable to resolve the cost ledger suite.");
  }
  const ledgerPath = await resolveConfinedRegularFile(
    suiteRoot,
    COST_LEDGER_FILE,
    "cost ledger",
  );
  const content = await readFileBuffer(ledgerPath, COST_LEDGER_FILE);
  const cells = MODES.flatMap((mode) => input.cellsByMode.get(mode));
  if (input.execution !== "live") {
    if (content.byteLength !== 0) {
      throw new SummaryError(
        "mock and replay suites require a real empty cost-ledger.jsonl.",
      );
    }
    for (const cell of cells) {
      expectEqual(
        cell.cost.actualPhysicalSpendUsd,
        0,
        `${cell.mode} non-live physical spend`,
      );
      expectEqual(
        cell.cost.conservativeCommittedUsd,
        0,
        `${cell.mode} non-live committed spend`,
      );
      expectEqual(
        cell.cost.attributedCostUsd,
        0,
        `${cell.mode} non-live attributed spend`,
      );
    }
    return;
  }
  const ledger = parseCostLedger(content);
  const physicalAgentCells = cells.filter(
    (cell) => cell.physical && cell.mode !== "scanner-only",
  );
  for (const scannerCell of cells.filter(
    (cell) => cell.mode === "scanner-only",
  )) {
    expectEqual(
      scannerCell.cost.actualPhysicalSpendUsd,
      0,
      "scanner-only physical spend",
    );
    expectEqual(
      scannerCell.cost.conservativeCommittedUsd,
      0,
      "scanner-only committed spend",
    );
    expectEqual(
      scannerCell.cost.physicalTokens,
      0,
      "scanner-only physical tokens",
    );
    expectEqual(
      scannerCell.cost.physicalModelCalls,
      0,
      "scanner-only physical calls",
    );
  }
  const knownRuns = new Map(
    physicalAgentCells.map((cell) => [
      `${cell.runId}\u0000${cell.mode}`,
      cell,
    ]),
  );
  const authoritative = new Map();
  for (const state of ledger.reservations) {
    const key = `${state.runId}\u0000${state.mode}`;
    if (!knownRuns.has(key)) {
      throw new SummaryError(
        "cost ledger contains a reservation outside the physical agent cells.",
      );
    }
    const manifestBinding = input.manifestBindings.get(key);
    if (!manifestBinding) {
      throw new SummaryError(
        "cost ledger run has no immutable manifest model declaration.",
      );
    }
    if (!EXACT_MODEL_ALLOWLIST.includes(state.model)) {
      throw new SummaryError(
        "cost ledger model is outside the exact research allowlist.",
      );
    }
    if (state.provider !== "openrouter") {
      throw new SummaryError(
        "cost ledger provider is not the declared OpenRouter research provider.",
      );
    }
    if (
      !manifestBinding.declaredModels.some(
        (entry) =>
          entry.provider === state.provider && entry.model === state.model,
      )
    ) {
      throw new SummaryError(
        "cost ledger provider/model is undeclared by the bound run manifest.",
      );
    }
    const aggregate = authoritative.get(key) ?? {
      actualNanoUsd: 0,
      committedNanoUsd: 0,
      tokens: 0,
      calls: 0,
    };
    aggregate.committedNanoUsd += state.amountNanoUsd;
    aggregate.calls += 1;
    if (state.action === "settled" || state.action === "overage") {
      aggregate.actualNanoUsd += state.amountNanoUsd;
      aggregate.tokens += state.promptTokens + state.completionTokens;
    }
    authoritative.set(key, aggregate);
  }
  validateLedgerModelCalls(
    ledger.reservations,
    physicalAgentCells,
    input.manifestBindings,
  );
  for (const cell of physicalAgentCells) {
    const cellBindingKey = `${cell.runId}\u0000${cell.mode}`;
    const aggregate = authoritative.get(
      cellBindingKey,
    ) ?? {
      actualNanoUsd: 0,
      committedNanoUsd: 0,
      tokens: 0,
      calls: 0,
    };
    const binding = input.manifestBindings.get(cellBindingKey);
    if (!binding) {
      throw new SummaryError(
        "physical agent cell has no manifest model binding.",
      );
    }
    const meteredCallCount = binding.modelCalls.filter(
      (call) => call.fingerprintSource === "metered-replay",
    ).length;
    expectEqual(
      usdToNanoUsd(
        cell.cost.actualPhysicalSpendUsd,
        `${cell.mode} physical spend`,
      ),
      aggregate.actualNanoUsd,
      `${cell.mode} ledger physical spend`,
    );
    expectEqual(
      usdToNanoUsd(
        cell.cost.conservativeCommittedUsd,
        `${cell.mode} committed spend`,
      ),
      aggregate.committedNanoUsd,
      `${cell.mode} ledger committed spend`,
    );
    expectEqual(
      cell.cost.physicalTokens,
      aggregate.tokens,
      `${cell.mode} ledger physical tokens`,
    );
    expectEqual(
      meteredCallCount,
      aggregate.calls,
      `${cell.mode} ledger physical calls`,
    );
    nearlyEqual(
      cell.cost.attributedCostUsd,
      Math.max(
        cell.cost.actualPhysicalSpendUsd,
        cell.cost.conservativeCommittedUsd,
      ),
      `${cell.mode} attributed physical cost`,
    );
  }
  expectEqual(
    ledger.actualNanoUsd,
    usdToNanoUsd(
      input.experimentSummary.actualPhysicalSpendUsd,
      "experiment physical spend",
    ),
    "cost ledger experiment physical spend",
  );
  expectEqual(
    ledger.committedNanoUsd,
    usdToNanoUsd(
      input.experimentSummary.conservativeCommittedUsd,
      "experiment committed spend",
    ),
    "cost ledger experiment committed spend",
  );
}

function parseCostLedger(content) {
  if (content.byteLength === 0) {
    return {
      reservations: [],
      actualNanoUsd: 0,
      committedNanoUsd: 0,
    };
  }
  const source = content.toString("utf8");
  if (!source.endsWith("\n")) {
    throw new SummaryError("cost ledger is truncated.");
  }
  const lines = source.trimEnd().split("\n");
  const states = new Map();
  const eventIds = new Set();
  let previousHash = null;
  for (const [index, line] of lines.entries()) {
    let parsed;
    try {
      parsed = JSON.parse(line);
    } catch {
      throw new SummaryError(`cost ledger event ${index + 1} is invalid JSON.`);
    }
    const event = objectValue(parsed, `cost ledger event ${index + 1}`);
    expectEqual(event.schemaVersion, 2, `cost ledger event ${index + 1} schema`);
    expectEqual(event.sequence, index + 1, `cost ledger event ${index + 1} sequence`);
    const eventId = requiredString(
      event.eventId,
      `cost ledger event ${index + 1} eventId`,
    );
    if (eventIds.has(eventId)) {
      throw new SummaryError("cost ledger repeats an eventId.");
    }
    eventIds.add(eventId);
    const reservationId = requiredString(
      event.reservationId,
      `cost ledger event ${index + 1} reservationId`,
    );
    const action = oneOf(
      event.action,
      ["reserved", "settled", "failed", "unknown", "overage"],
      `cost ledger event ${index + 1} action`,
    );
    assertExactLedgerEventKeys(event, action, index + 1);
    const runId = requiredString(
      event.runId,
      `cost ledger event ${index + 1} runId`,
    );
    const mode = canonicalMode(
      event.mode,
      `cost ledger event ${index + 1} mode`,
    );
    const provider = requiredString(
      event.provider,
      `cost ledger event ${index + 1} provider`,
    );
    const model = requiredString(
      event.model,
      `cost ledger event ${index + 1} model`,
    );
    const amountNanoUsd = nonNegativeInteger(
      event.amountNanoUsd,
      `cost ledger event ${index + 1} amountNanoUsd`,
    );
    expectEqual(
      usdToNanoUsd(
        nonNegativeNumber(
          event.amountUsd,
          `cost ledger event ${index + 1} amountUsd`,
        ),
        `cost ledger event ${index + 1} amountUsd`,
      ),
      amountNanoUsd,
      `cost ledger event ${index + 1} USD amount`,
    );
    validTimestamp(
      event.timestamp,
      `cost ledger event ${index + 1} timestamp`,
    );
    expectEqual(
      event.previousHash,
      previousHash,
      `cost ledger event ${index + 1} previousHash`,
    );
    expectDigest(event.hash, `cost ledger event ${index + 1} hash`);
    expectEqual(
      event.hash,
      sha256Hex(canonicalJson(withoutProperty(event, "hash"))),
      `cost ledger event ${index + 1} integrity hash`,
    );
    previousHash = event.hash;

    const current = states.get(reservationId);
    if (action === "reserved") {
      if (current) {
        throw new SummaryError("cost ledger repeats a reservation.");
      }
      const globalLimitNanoUsd = nonNegativeInteger(
        event.globalLimitNanoUsd,
        `cost ledger event ${index + 1} globalLimitNanoUsd`,
      );
      const modeLimitNanoUsd = nonNegativeInteger(
        event.modeLimitNanoUsd,
        `cost ledger event ${index + 1} modeLimitNanoUsd`,
      );
      expectEqual(
        globalLimitNanoUsd,
        GLOBAL_BUDGET_NANO_USD,
        `cost ledger event ${index + 1} canonical global limit`,
      );
      expectEqual(
        modeLimitNanoUsd,
        usdToNanoUsd(
          MODE_BUDGET_USD[mode],
          `${mode} canonical ledger mode limit`,
        ),
        `cost ledger event ${index + 1} canonical mode limit`,
      );
      const requestFingerprint =
        event.requestFingerprint === undefined
          ? undefined
          : expectDigest(
              event.requestFingerprint,
              `cost ledger event ${index + 1} requestFingerprint`,
            );
      const pricingCatalogDigestSha256 =
        event.pricingCatalogDigestSha256 === undefined
          ? undefined
          : expectDigest(
              event.pricingCatalogDigestSha256,
              `cost ledger event ${index + 1} pricingCatalogDigestSha256`,
            );
      const currentGlobalCommitted = [...states.values()].reduce(
        (total, state) => total + state.amountNanoUsd,
        0,
      );
      const currentModeCommitted = [...states.values()]
        .filter((state) => state.runId === runId && state.mode === mode)
        .reduce((total, state) => total + state.amountNanoUsd, 0);
      if (currentGlobalCommitted + amountNanoUsd > globalLimitNanoUsd) {
        throw new SummaryError(
          "cost ledger reservation exceeds its global budget.",
        );
      }
      if (currentModeCommitted + amountNanoUsd > modeLimitNanoUsd) {
        throw new SummaryError(
          "cost ledger reservation exceeds its mode budget.",
        );
      }
      states.set(reservationId, {
        reservationId,
        runId,
        mode,
        provider,
        model,
        action,
        amountNanoUsd,
        globalLimitNanoUsd,
        modeLimitNanoUsd,
        requestFingerprint,
        pricingCatalogDigestSha256,
        reservationSequence: index + 1,
      });
      continue;
    }
    if (!current || current.action !== "reserved") {
      throw new SummaryError(
        "cost ledger contains an invalid terminal transition.",
      );
    }
    if (
      current.runId !== runId ||
      current.mode !== mode ||
      current.provider !== provider ||
      current.model !== model
    ) {
      throw new SummaryError("cost ledger reservation scope changed.");
    }
    if (
      event.globalLimitNanoUsd !== undefined ||
      event.modeLimitNanoUsd !== undefined
    ) {
      throw new SummaryError(
        "only cost reservation events may contain budget limits.",
      );
    }
    expectEqual(
      event.requestFingerprint,
      current.requestFingerprint,
      `cost ledger event ${index + 1} requestFingerprint`,
    );
    expectEqual(
      event.pricingCatalogDigestSha256,
      current.pricingCatalogDigestSha256,
      `cost ledger event ${index + 1} pricingCatalogDigestSha256`,
    );
    if (action === "failed" && amountNanoUsd !== 0) {
      throw new SummaryError(
        "failed cost ledger reservations must commit zero spend.",
      );
    }
    if (action === "unknown" && amountNanoUsd !== current.amountNanoUsd) {
      throw new SummaryError(
        "unknown cost ledger reservations must retain reserved spend.",
      );
    }
    if (action === "settled" && amountNanoUsd > current.amountNanoUsd) {
      throw new SummaryError(
        "settled cost cannot exceed its reservation without an overage event.",
      );
    }
    let promptTokens = 0;
    let completionTokens = 0;
    if (action === "settled" || action === "overage") {
      promptTokens = nonNegativeInteger(
        event.promptTokens,
        `cost ledger event ${index + 1} promptTokens`,
      );
      completionTokens = nonNegativeInteger(
        event.completionTokens,
        `cost ledger event ${index + 1} completionTokens`,
      );
      oneOf(
        event.costSource,
        [
          "provider-authoritative",
          "pinned-token-estimate",
        ],
        `cost ledger event ${index + 1} costSource`,
      );
    } else {
      if (
        event.promptTokens !== undefined ||
        event.completionTokens !== undefined
      ) {
        throw new SummaryError(
          "failed and unknown ledger events cannot contain settled token usage.",
        );
      }
      expectEqual(
        event.costSource,
        action === "failed"
          ? "known-not-charged"
          : "reservation-conservative",
        `cost ledger event ${index + 1} ${action} costSource`,
      );
      requiredString(
        event.reason,
        `cost ledger event ${index + 1} ${action} reason`,
      );
    }
    const overageReasons =
      event.overageReasons === undefined
        ? undefined
        : stringArray(
            event.overageReasons,
            `cost ledger event ${index + 1} overageReasons`,
          );
    if (
      action === "overage" &&
      (!overageReasons ||
        overageReasons.length === 0 ||
        overageReasons.some(
          (reason) =>
            reason !== "reservation" &&
            reason !== "global" &&
            reason !== "mode",
        ))
    ) {
      throw new SummaryError(
        "cost ledger overage event has invalid overage reasons.",
      );
    }
    if (action !== "overage" && overageReasons !== undefined) {
      throw new SummaryError(
        "only cost ledger overage events may contain overage reasons.",
      );
    }
    if (
      action === "settled" &&
      event.reason !== undefined
    ) {
      throw new SummaryError(
        "settled cost ledger events cannot contain a failure or overage reason.",
      );
    }
    const globalWithoutReservation =
      [...states.values()].reduce(
        (total, state) => total + state.amountNanoUsd,
        0,
      ) - current.amountNanoUsd;
    const modeWithoutReservation =
      [...states.values()]
        .filter(
          (state) =>
            state.runId === current.runId && state.mode === current.mode,
        )
        .reduce((total, state) => total + state.amountNanoUsd, 0) -
      current.amountNanoUsd;
    const expectedOverageReasons = [];
    if (amountNanoUsd > current.amountNanoUsd) {
      expectedOverageReasons.push("reservation");
    }
    if (
      globalWithoutReservation + amountNanoUsd >
      current.globalLimitNanoUsd
    ) {
      expectedOverageReasons.push("global");
    }
    if (
      modeWithoutReservation + amountNanoUsd >
      current.modeLimitNanoUsd
    ) {
      expectedOverageReasons.push("mode");
    }
    if (action === "overage") {
      expectStringArraysEqual(
        overageReasons,
        expectedOverageReasons,
        `cost ledger event ${index + 1} overage reasons`,
      );
    } else if (expectedOverageReasons.length > 0) {
      throw new SummaryError(
        "cost ledger terminal event hides a budget overage.",
      );
    }
    if (
      globalWithoutReservation + amountNanoUsd >
        GLOBAL_BUDGET_NANO_USD ||
      modeWithoutReservation + amountNanoUsd >
        usdToNanoUsd(
          MODE_BUDGET_USD[current.mode],
          `${current.mode} canonical terminal mode budget`,
        )
    ) {
      throw new SummaryError(
        "cost ledger terminal commitment exceeds a canonical research budget.",
      );
    }
    states.set(reservationId, {
      reservationId,
      runId,
      mode,
      provider,
      model,
      action,
      amountNanoUsd,
      promptTokens,
      completionTokens,
      costSource: event.costSource,
      ...(event.reason === undefined
        ? {}
        : { reason: event.reason }),
      requestFingerprint: current.requestFingerprint,
      reservationSequence: current.reservationSequence,
    });
  }
  const reservations = [...states.values()];
  if (reservations.some((entry) => entry.action === "reserved")) {
    throw new SummaryError(
      "cost ledger contains an unterminated reservation.",
    );
  }
  const actualNanoUsd = reservations
    .filter(
      (entry) =>
        entry.action === "settled" || entry.action === "overage",
    )
    .reduce((total, entry) => total + entry.amountNanoUsd, 0);
  const committedNanoUsd = reservations.reduce(
    (total, entry) => total + entry.amountNanoUsd,
    0,
  );
  if (
    actualNanoUsd > GLOBAL_BUDGET_NANO_USD ||
    committedNanoUsd > GLOBAL_BUDGET_NANO_USD
  ) {
    throw new SummaryError(
      "cost ledger aggregate exceeds the canonical global research budget.",
    );
  }
  return {
    reservations,
    actualNanoUsd,
    committedNanoUsd,
  };
}

function assertExactLedgerEventKeys(event, action, eventNumber) {
  const common = [
    "schemaVersion",
    "sequence",
    "eventId",
    "reservationId",
    "action",
    "runId",
    "mode",
    "provider",
    "model",
    "amountNanoUsd",
    "amountUsd",
    "timestamp",
    "previousHash",
    "hash",
    "requestFingerprint",
    "pricingCatalogDigestSha256",
  ];
  const actionKeys = {
    reserved: ["globalLimitNanoUsd", "modeLimitNanoUsd"],
    settled: ["promptTokens", "completionTokens", "costSource"],
    overage: [
      "promptTokens",
      "completionTokens",
      "costSource",
      "overageReasons",
      "reason",
    ],
    failed: ["costSource", "reason"],
    unknown: ["costSource", "reason"],
  };
  const allowed = new Set([...common, ...actionKeys[action]]);
  const unexpected = Object.keys(event)
    .filter((key) => !allowed.has(key))
    .sort(compareText);
  if (unexpected.length > 0) {
    throw new SummaryError(
      `cost ledger event ${eventNumber} contains unsupported fields: ${unexpected.join(", ")}.`,
    );
  }
}

function validateLedgerModelCalls(reservations, physicalCells, bindings) {
  const ledgerByBinding = new Map(
    reservations.map((entry) => [
      ledgerModelCallBindingKey(
        entry.runId,
        entry.mode,
        entry.requestFingerprint,
      ),
      entry,
    ]),
  );
  if (
    ledgerByBinding.size !== reservations.length ||
    reservations.some((entry) => entry.requestFingerprint === undefined)
  ) {
    throw new SummaryError(
      "live ledger reservations require request fingerprints unique within each physical cell.",
    );
  }
  const boundLedgerCalls = new Set();
  let locallyTimedOutSettledOrUndispatchedCalls = 0;
  for (const cell of physicalCells) {
    const key = `${cell.runId}\u0000${cell.mode}`;
    const binding = bindings.get(key);
    if (!binding) {
      throw new SummaryError(
        "physical agent cell has no manifest model binding.",
      );
    }
    const ledgerCalls = reservations.filter(
      (entry) => entry.runId === cell.runId && entry.mode === cell.mode,
    );
    const meteredCalls = binding.modelCalls.filter(
      (call) => call.fingerprintSource === "metered-replay",
    );
    const preMeteringRejections = binding.modelCalls.filter(
      (call) => call.fingerprintSource === "pre-metering-rejection",
    );
    if (ledgerCalls.length !== meteredCalls.length) {
      throw new SummaryError(
        "live model-calls.json does not bind every authoritative ledger reservation exactly once.",
      );
    }
    for (const call of preMeteringRejections) {
      const rejectedBindingKey = ledgerModelCallBindingKey(
        cell.runId,
        cell.mode,
        call.requestFingerprint,
      );
      if (ledgerByBinding.has(rejectedBindingKey)) {
        throw new SummaryError(
          "a pre-metering model-call rejection must not have an authoritative ledger reservation.",
        );
      }
    }
    for (const call of meteredCalls) {
      const ledgerBindingKey = ledgerModelCallBindingKey(
        cell.runId,
        cell.mode,
        call.requestFingerprint,
      );
      const ledgerCall = ledgerByBinding.get(ledgerBindingKey);
      if (
        !ledgerCall ||
        boundLedgerCalls.has(ledgerBindingKey)
      ) {
        throw new SummaryError(
          "model-calls.json contains a missing or repeated ledger request-fingerprint binding.",
        );
      }
      boundLedgerCalls.add(ledgerBindingKey);
      expectEqual(
        ledgerCall.runId,
        cell.runId,
        `${cell.mode} model-call ledger runId`,
      );
      expectEqual(
        ledgerCall.mode,
        cell.mode,
        `${cell.mode} model-call ledger mode`,
      );
      expectEqual(
        ledgerCall.provider,
        call.provider,
        `${cell.mode} model-call ledger provider`,
      );
      expectEqual(
        ledgerCall.model,
        call.model,
        `${cell.mode} model-call ledger model`,
      );
      expectEqual(
        validModelCallLedgerTerminalSemantics(
          call,
          ledgerCall,
          binding.modelCallTrace,
        ),
        true,
        `${cell.mode} model-call/ledger terminal semantics`,
      );
      if (
        isLocallyTimedOutSettledOrUndispatchedCall(
          call,
          ledgerCall,
          binding.modelCallTrace,
        )
      ) {
        locallyTimedOutSettledOrUndispatchedCalls += 1;
      }
    }
  }
  if (locallyTimedOutSettledOrUndispatchedCalls > 1) {
    throw new SummaryError(
      "live cost ledger contains more than one settled or known-not-charged local timeout trigger.",
    );
  }
  if (boundLedgerCalls.size !== reservations.length) {
    throw new SummaryError(
      "cost ledger contains an authoritative reservation not bound by model-calls.json.",
    );
  }
}

function validModelCallLedgerTerminalSemantics(
  call,
  ledgerCall,
  trace,
) {
  switch (ledgerCall.action) {
    case "settled":
      return (
        call.terminalState === "succeeded" ||
        (call.terminalState === "failed" &&
          call.errorCategory === "replay" &&
          trace.execution === "live" &&
          trace.cassettePolicy === "recorded" &&
          call.cassetteReference === undefined) ||
        isLocallyTimedOutSettledOrUndispatchedCall(
          call,
          ledgerCall,
          trace,
        )
      );
    case "overage":
      return (
        call.terminalState === "failed" &&
        call.errorCategory === "budget"
      );
    case "failed":
      return (
        call.terminalState === "canceled" &&
        call.errorCategory === "aborted"
      ) || isLocallyTimedOutSettledOrUndispatchedCall(
        call,
        ledgerCall,
        trace,
      );
    case "unknown":
      return (
        (call.terminalState === "failed" &&
          call.errorCategory !== "aborted") ||
        (call.terminalState === "canceled" &&
          call.errorCategory === "aborted")
      );
    default:
      return false;
  }
}

function isLocallyTimedOutSettledOrUndispatchedCall(
  call,
  ledgerCall,
  trace,
) {
  if (
    trace.execution !== "live" ||
    call.terminalState !== "failed" ||
    call.errorCategory !== "timeout"
  ) {
    return false;
  }
  if (ledgerCall.action === "settled") {
    return true;
  }
  return (
    ledgerCall.action === "failed" &&
    ledgerCall.costSource === "known-not-charged" &&
    ledgerCall.reason ===
      "Live model call was stopped before provider dispatch."
  );
}

function ledgerModelCallBindingKey(runId, mode, requestFingerprint) {
  return `${runId}\u0000${mode}\u0000${requestFingerprint}`;
}

function renderOutputs(summary) {
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

async function renderIntegrityReceipt(summary, evidence, outputs) {
  const outputBindings = [...outputs.entries()]
    .map(([relativePath, content]) => {
      const buffer = Buffer.from(content, "utf8");
      return {
        path: relativePath,
        bytes: buffer.byteLength,
        sha256: sha256Hex(buffer),
      };
    })
    .sort((left, right) => compareText(left.path, right.path));
  const runManifestSetSha256 = sha256Hex(
    canonicalJson(evidence.runManifests),
  );
  const sourceTruthSetSha256 = sha256Hex(
    canonicalJson(evidence.sourceTruth),
  );
  const upstream = {
    suiteIndex: evidence.suiteIndex,
    suiteArtifacts: evidence.suiteArtifacts,
    runManifests: evidence.runManifests,
    runManifestSetSha256,
    sourceTruth: evidence.sourceTruth,
    sourceTruthSetSha256,
  };
  const summarizerContent = await fs.readFile(new URL(import.meta.url));
  const generator = {
    path: "scripts/research/summarize-seven-mode.mjs",
    bytes: summarizerContent.byteLength,
    sha256: sha256Hex(summarizerContent),
  };
  const upstreamBindingSha256 = sha256Hex(canonicalJson(upstream));
  const outputSetSha256 = sha256Hex(canonicalJson(outputBindings));
  const runtimeByMode = MODES.map((mode) => {
    const durations = evidence.runManifests
      .filter((manifest) => manifest.mode === mode)
      .map((manifest) => manifest.durationMs);
    const totalMilliseconds = durations.reduce(
      (total, duration) => total + duration,
      0,
    );
    return {
      mode,
      runCount: durations.length,
      totalMilliseconds,
      meanMilliseconds:
        durations.length === 0 ? null : totalMilliseconds / durations.length,
    };
  });
  const unsigned = {
    schemaVersion: "1.0",
    suiteId: summary.suiteId,
    integrity: INTEGRITY_NOTICE,
    generator,
    upstream,
    upstreamBindingSha256,
    outputBindings,
    outputSetSha256,
    derivationBindingSha256: sha256Hex(
      canonicalJson({
        generatorSha256: generator.sha256,
        suiteIndexSha256: evidence.suiteIndex.sha256,
        upstreamBindingSha256,
        outputSetSha256,
      }),
    ),
    downstreamEvidence: {
      manifestRate: {
        status: "available",
        evidenceSha256: runManifestSetSha256,
        verifiedManifestCount: evidence.runManifests.length,
        expectedManifestCount: summary.cellCount,
        value:
          summary.cellCount === 0
            ? null
            : evidence.runManifests.length / summary.cellCount,
      },
      runtime: {
        status: "available",
        evidenceSha256: runManifestSetSha256,
        source: "verified run manifest startedAt/finishedAt timestamps",
        byMode: runtimeByMode,
      },
      replayAgreement: {
        status: "unavailable",
        reason:
          "The bound suite contains one execution type and no immutable cross-execution pairing evidence.",
      },
    },
    verification: {
      requiresDeterministicRerun: true,
      instructions:
        "Verify the v3 suite index and every upstream digest, verify the generator digest, recompute every output digest and receiptSha256, then rerun this deterministic summarizer. This local SHA-256 receipt is not a digital signature.",
    },
  };
  const receipt = {
    ...unsigned,
    receiptSha256: sha256Hex(canonicalJson(unsigned)),
  };
  return `${JSON.stringify(receipt, null, 2)}\n`;
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
      lines.push(`| ${markdownCell(mode.label)} | None | - | - | - | 0 | 0 | 0 |`);
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
  lines.push("\\hline", "\\end{tabular}", "", "% Per-class metrics", "\\begin{tabular}{llrrrrrr}", "\\hline", "Mode & Class & Precision & Recall & F1 & TP & FP & FN \\\\", "\\hline");
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

async function writeFreshDirectory(outputDirectory, outputs) {
  try {
    await fs.lstat(outputDirectory);
    throw new SummaryError(
      "The --out directory already exists; choose a fresh path.",
    );
  } catch (error) {
    if (error instanceof SummaryError) {
      throw error;
    }
    if (error?.code !== "ENOENT") {
      throw new SummaryError("Unable to validate the --out directory.");
    }
  }
  const parent = path.dirname(outputDirectory);
  try {
    await fs.mkdir(parent, { recursive: true });
  } catch {
    throw new SummaryError("Unable to create the --out parent directory.");
  }
  let stagingDirectory;
  try {
    stagingDirectory = await fs.mkdtemp(
      path.join(parent, `.${path.basename(outputDirectory)}.tmp-`),
    );
    for (const fileName of OUTPUT_FILES) {
      const content = outputs.get(fileName);
      if (typeof content !== "string") {
        throw new SummaryError(`Missing rendered output ${fileName}.`);
      }
      await fs.writeFile(path.join(stagingDirectory, fileName), content, {
        encoding: "utf8",
        flag: "wx",
      });
    }
    await fs.rename(stagingDirectory, outputDirectory);
    stagingDirectory = undefined;
  } catch (error) {
    if (error instanceof SummaryError) {
      throw error;
    }
    throw new SummaryError("Unable to write summary artifacts safely.");
  } finally {
    if (stagingDirectory) {
      await fs.rm(stagingDirectory, { recursive: true, force: true });
    }
  }
}

async function resolveConfinedRegularFile(rootDirectory, relativePath, label) {
  const safePath = safeRelativeArtifactPath(relativePath, `${label} path`);
  let root;
  try {
    root = await fs.realpath(path.resolve(rootDirectory));
  } catch {
    throw new SummaryError(`Unable to resolve ${label} root.`);
  }
  const candidate = path.resolve(root, ...safePath.split("/"));
  const relative = path.relative(root, candidate);
  if (
    relative === ".." ||
    relative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relative)
  ) {
    throw new SummaryError(`${label} escapes its trusted directory.`);
  }
  let stat;
  try {
    stat = await fs.lstat(candidate);
  } catch {
    throw new SummaryError(`Unable to read required ${label}.`);
  }
  if (stat.isSymbolicLink() || !stat.isFile()) {
    throw new SummaryError(`${label} must be a regular file.`);
  }
  let real;
  try {
    real = await fs.realpath(candidate);
  } catch {
    throw new SummaryError(`Unable to resolve required ${label}.`);
  }
  const realRelative = path.relative(root, real);
  if (
    realRelative === ".." ||
    realRelative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(realRelative)
  ) {
    throw new SummaryError(`${label} resolves outside its trusted directory.`);
  }
  return real;
}

async function readPlainJsonFile(filePath, label) {
  const content = await readFileBuffer(filePath, label);
  return parseJsonBuffer(content, label);
}

async function readFileBuffer(filePath, label) {
  try {
    return await fs.readFile(filePath);
  } catch {
    throw new SummaryError(`Unable to read required ${label}.`);
  }
}

function parseJsonBuffer(content, label) {
  try {
    return JSON.parse(content.toString("utf8"));
  } catch {
    throw new SummaryError(`${label} is not valid JSON.`);
  }
}

function readArtifactWrapper(value, label) {
  const wrapper = objectValue(value, `${label} wrapper`);
  expectEqual(wrapper.schemaVersion, "1.0", `${label} wrapper schemaVersion`);
  stringArray(wrapper.redactionMarkers, `${label} redactionMarkers`);
  return wrapper.data;
}

async function listRegularFiles(rootDirectory) {
  let root;
  try {
    root = await fs.realpath(path.resolve(rootDirectory));
  } catch {
    throw new SummaryError("Unable to resolve run artifact directory.");
  }
  const pending = [root];
  const files = [];
  while (pending.length > 0) {
    const directory = pending.pop();
    let entries;
    try {
      entries = await fs.readdir(directory, { withFileTypes: true });
    } catch {
      throw new SummaryError("Unable to enumerate run artifacts.");
    }
    for (const entry of entries) {
      const absolute = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) {
        throw new SummaryError(
          "run artifact directory contains a symbolic link.",
        );
      }
      if (entry.isDirectory()) {
        pending.push(absolute);
      } else if (entry.isFile()) {
        files.push(path.relative(root, absolute).replaceAll("\\", "/"));
      } else {
        throw new SummaryError(
          "run artifact directory contains a non-regular entry.",
        );
      }
    }
  }
  return files.sort(compareText);
}

function safeRelativeArtifactPath(value, label) {
  const relative = requiredString(value, label);
  if (
    relative.includes("\0") ||
    relative.includes("\\") ||
    path.posix.isAbsolute(relative) ||
    path.win32.isAbsolute(relative) ||
    path.posix.normalize(relative) !== relative ||
    relative === "." ||
    relative === ".." ||
    relative.startsWith("../") ||
    relative.includes("/../") ||
    relative.endsWith("/")
  ) {
    throw new SummaryError(`${label} must be a normalized relative path.`);
  }
  return relative;
}

function assertExactObjectKeys(value, expectedKeys, label) {
  const actual = Object.keys(objectValue(value, label)).sort(compareText);
  const expected = [...expectedKeys].sort(compareText);
  expectStringArraysEqual(actual, expected, `${label} fields`);
}

function assertIntegrityNotice(value, label) {
  canonicalEqual(value, INTEGRITY_NOTICE, label);
}

function validTimestamp(value, label) {
  if (
    typeof value !== "string" ||
    value.trim().length === 0 ||
    Number.isNaN(Date.parse(value))
  ) {
    throw new SummaryError(`${label} must be a valid timestamp.`);
  }
  return value;
}

function expectDigest(value, label) {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/u.test(value)) {
    throw new SummaryError(`${label} must be a lowercase SHA-256 digest.`);
  }
  return value;
}

function canonicalEqual(actual, expected, label) {
  if (canonicalJson(actual) !== canonicalJson(expected)) {
    throw new SummaryError(`${label} does not match immutable evidence.`);
  }
}

function withoutProperty(value, property) {
  return Object.fromEntries(
    Object.entries(value).filter(([key]) => key !== property),
  );
}

function canonicalJson(value) {
  return JSON.stringify(normalizeForCanonicalJson(value));
}

function prettyCanonicalJson(value) {
  return `${JSON.stringify(normalizeForCanonicalJson(value), null, 2)}\n`;
}

function normalizeForCanonicalJson(value, seen = new WeakSet()) {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new SummaryError(
        "canonical research evidence cannot contain non-finite numbers.",
      );
    }
    return value;
  }
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== "object") {
    throw new SummaryError(
      `canonical research evidence cannot contain ${typeof value}.`,
    );
  }
  if (seen.has(value)) {
    throw new SummaryError("canonical research evidence cannot be circular.");
  }
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      return value.map(
        (entry) => normalizeForCanonicalJson(entry, seen) ?? null,
      );
    }
    const output = Object.create(null);
    for (const key of Object.keys(value).sort(compareText)) {
      const normalized = normalizeForCanonicalJson(value[key], seen);
      if (normalized !== undefined) {
        output[key] = normalized;
      }
    }
    return output;
  } finally {
    seen.delete(value);
  }
}

function sha256Hex(value) {
  return createHash("sha256").update(value).digest("hex");
}

function usdToNanoUsd(value, label) {
  const usd = nonNegativeNumber(value, label);
  const nano = Math.round(usd * NANO_USD_PER_USD);
  if (!Number.isSafeInteger(nano) || nano < 0) {
    throw new SummaryError(`${label} cannot be represented in nanodollars.`);
  }
  if (Math.abs(nano / NANO_USD_PER_USD - usd) > 0.5 / NANO_USD_PER_USD) {
    throw new SummaryError(`${label} loses nanodollar precision.`);
  }
  return nano;
}

function assertExactModes(values, label) {
  const modes = arrayValue(values, label);
  if (modes.length !== MODES.length) {
    throw new SummaryError(
      `${label} must contain exactly the seven canonical modes.`,
    );
  }
  const canonical = modes.map((value, index) =>
    canonicalMode(value, `${label} ${index}`),
  );
  if (new Set(canonical).size !== MODES.length) {
    throw new SummaryError(
      `${label} must contain each canonical mode exactly once.`,
    );
  }
}

function canonicalMode(value, label) {
  return oneOf(value, MODES, label);
}

function oneOf(value, allowed, label) {
  if (typeof value !== "string" || !allowed.includes(value)) {
    throw new SummaryError(`${label} is invalid.`);
  }
  return value;
}

function uniqueSafeStrings(value, label) {
  const values = stringArray(value, label).map((entry, index) =>
    safeOutputString(entry, `${label} ${index}`),
  );
  if (new Set(values).size !== values.length) {
    throw new SummaryError(`${label} contains duplicates.`);
  }
  return values;
}

function safeOutputString(value, label) {
  if (
    value.length > 200 ||
    /[\u0000-\u001f\u007f]/u.test(value) ||
    path.win32.isAbsolute(value) ||
    path.posix.isAbsolute(value) ||
    /(?:^|[\s"'(])(?:[A-Za-z]:[\\/]|\\\\)/u.test(value) ||
    /(?:sk-(?:or-)?[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{12,}|AKIA[0-9A-Z]{12,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)/u.test(
      value,
    )
  ) {
    throw new SummaryError(`${label} is not safe for aggregate output.`);
  }
  return value;
}

function objectValue(value, label) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value)
  ) {
    throw new SummaryError(`${label} must be an object.`);
  }
  return value;
}

function arrayValue(value, label) {
  if (!Array.isArray(value)) {
    throw new SummaryError(`${label} must be an array.`);
  }
  return value;
}

function stringArray(value, label) {
  return arrayValue(value, label).map((entry, index) =>
    requiredString(entry, `${label} ${index}`),
  );
}

function requiredString(value, label) {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new SummaryError(`${label} must be a non-empty string.`);
  }
  return value;
}

function booleanValue(value, label) {
  if (typeof value !== "boolean") {
    throw new SummaryError(`${label} must be boolean.`);
  }
  return value;
}

function nonNegativeNumber(value, label) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    throw new SummaryError(`${label} must be a finite non-negative number.`);
  }
  return Object.is(value, -0) ? 0 : value;
}

function nonNegativeInteger(value, label) {
  const number = nonNegativeNumber(value, label);
  if (!Number.isSafeInteger(number)) {
    throw new SummaryError(`${label} must be a safe integer.`);
  }
  return number;
}

function probability(value, label) {
  const number = nonNegativeNumber(value, label);
  if (number > 1) {
    throw new SummaryError(`${label} must be between 0 and 1.`);
  }
  return number;
}

function nullableNonNegativeInteger(value, label) {
  return value === null ? null : nonNegativeInteger(value, label);
}

function nullableProbability(value, label) {
  return value === null ? null : probability(value, label);
}

function expectEqual(actual, expected, label) {
  if (actual !== expected) {
    throw new SummaryError(`${label} does not match the suite contract.`);
  }
}

function expectStringArraysEqual(actual, expected, label) {
  if (
    actual.length !== expected.length ||
    actual.some((value, index) => value !== expected[index])
  ) {
    throw new SummaryError(`${label} does not match the suite contract.`);
  }
}

function assertUniqueValues(values, label) {
  if (new Set(values).size !== values.length) {
    throw new SummaryError(`${label} contains duplicates.`);
  }
}

function nearlyEqual(actual, expected, label) {
  const difference = Math.abs(actual - expected);
  const scale = Math.max(1, Math.abs(actual), Math.abs(expected));
  if (difference > 1e-9 * scale) {
    throw new SummaryError(`${label} does not reconcile across artifacts.`);
  }
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
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

function printHelp() {
  process.stdout.write(`Hermsec deterministic seven-mode summarizer

Usage:
  node scripts/research/summarize-seven-mode.mjs --suite <directory> --out <directory>

Required:
  --suite <directory>   Immutable suite produced by experimentRunner
  --out <directory>     Fresh output directory; existing paths are refused

Outputs:
  ${OUTPUT_FILES.join(", ")}
`);
}
