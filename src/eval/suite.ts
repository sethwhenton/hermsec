import fs from "node:fs/promises";
import path from "node:path";
import type { Finding } from "../shared/types.js";
import {
  applyGroupedF1,
  computeCategoryMetrics,
  computeGroupedMetricSummary,
  computeVulnerabilityClassMetrics,
} from "./categoryScoring.js";
import { projectFindings } from "./findingProjection.js";
import {
  validateFixtureManifestV2,
  validateTruthSetV2,
} from "./groundTruthSchema.js";
import {
  fixtureProjectPath,
  validateFixtureLayout,
  type ValidatedFixtureLayout,
} from "./fixtureLayout.js";
import { matchFindings } from "./matcher.js";
import {
  computeExecutionCompleteness,
  computeSelectiveMetrics,
  computeSuiteMetrics,
} from "./metrics.js";
import {
  buildCapabilityNormalizedComparison,
  buildCostNormalizedComparison,
  type CapabilityBudget,
  type CapabilityNormalizedRow,
  type CostNormalizedRow,
  type ModeEvaluationObservation,
  type NormalizedComparison,
} from "./modeComparison.js";
import type {
  EvalFindingCategory,
  EvalMetrics,
  ExecutionCompleteness,
  ExecutionCompletenessInput,
  FixtureManifestV2,
  GroupedMetricSummary,
  MatchResult,
  SelectiveEvaluationCounts,
  SelectiveMetrics,
  TruthSetV2,
} from "./schema.js";
import {
  captureStableTree,
  readStableConfinedFile,
  type StableTreeLimits,
  type StableTreeSnapshot,
} from "../research/stableFiles.js";

export type LoadedEvaluationFixture = {
  fixtureRoot: string;
  projectRoot: string;
  layout: ValidatedFixtureLayout;
  manifest: FixtureManifestV2;
  truth: TruthSetV2;
  sourceLines: number;
  sourceFileLines: Record<string, number>;
};

export const EVALUATION_FIXTURE_LIMITS = Object.freeze({
  maxDepth: 32,
  maxDirectories: 1_000,
  maxFiles: 5_000,
  maxFileBytes: 10 * 1024 * 1024,
  maxTotalBytes: 100 * 1024 * 1024,
} satisfies StableTreeLimits);

export type StableLoadedEvaluationFixture = {
  fixture: LoadedEvaluationFixture;
  sourceSnapshot: StableTreeSnapshot;
};

export type EvaluationSuiteCaseInput = {
  fixtureRoot: string;
  findings: readonly Finding[];
  completeness: ExecutionCompletenessInput;
};

export type EvaluationSuiteRunInput = {
  runId: string;
  mode: string;
  cases: readonly EvaluationSuiteCaseInput[];
  costUsd: number;
  totalTokens: number;
  agentCount: number;
  capability: CapabilityBudget;
};

export type EvaluationSuiteInput = {
  suiteId: string;
  runs: readonly EvaluationSuiteRunInput[];
  normalization: {
    targetCostUsd: number;
    toleranceUsd: number;
    requiredModes?: readonly string[];
    capabilityReference?: CapabilityBudget;
  };
};

export type ScoredEvaluationCase = {
  fixtureId: string;
  fixtureRoot: string;
  manifest: FixtureManifestV2;
  truth: TruthSetV2;
  sourceLines: number;
  sourceFileLines: Record<string, number>;
  matchResult: MatchResult;
  metrics: EvalMetrics;
  metricsByCategory: Record<EvalFindingCategory, EvalMetrics>;
  metricsByClass: Record<string, EvalMetrics>;
  categorySummary: GroupedMetricSummary;
  classSummary: GroupedMetricSummary;
  selectiveCounts: SelectiveEvaluationCounts;
  selective: SelectiveMetrics;
  completenessInput: ExecutionCompletenessInput;
  completeness: ExecutionCompleteness;
};

export type ScoredEvaluationRun = {
  runId: string;
  mode: string;
  costUsd: number;
  totalTokens: number;
  agentCount: number;
  capability: CapabilityBudget;
  cases: ScoredEvaluationCase[];
  matchResults: MatchResult[];
  sourceLines: number;
  metrics: EvalMetrics;
  metricsByCategory: Record<EvalFindingCategory, EvalMetrics>;
  metricsByClass: Record<string, EvalMetrics>;
  categorySummary: GroupedMetricSummary;
  classSummary: GroupedMetricSummary;
  selectiveCounts: SelectiveEvaluationCounts;
  selective: SelectiveMetrics;
  completeness: ExecutionCompleteness;
};

export type ScoredEvaluationBundle = {
  schemaVersion: "1.0";
  suiteId: string;
  runs: ScoredEvaluationRun[];
  comparisons: {
    capability: NormalizedComparison<CapabilityNormalizedRow>;
    cost: NormalizedComparison<CostNormalizedRow>;
  };
};

/**
 * Loads only fixture metadata, truth, and declared source text. Vulnerable
 * fixture entrypoints are never imported, spawned, or otherwise executed.
 */
export async function loadEvaluationFixture(
  fixtureRoot: string,
): Promise<LoadedEvaluationFixture> {
  return (await loadStableEvaluationFixture(fixtureRoot)).fixture;
}

export async function loadStableEvaluationFixture(
  fixtureRoot: string,
): Promise<StableLoadedEvaluationFixture> {
  const requestedRoot = path.resolve(fixtureRoot);
  const sourceSnapshot = await captureStableTree(
    requestedRoot,
    EVALUATION_FIXTURE_LIMITS,
  );
  const canonicalRoot = await fs.realpath(requestedRoot);
  const manifestDocument = JSON.parse(
    (
      await readSnapshotFile(
        canonicalRoot,
        sourceSnapshot,
        "fixture.json",
      )
    ).toString("utf8"),
  ) as unknown;
  const manifest = validateFixtureManifestV2(manifestDocument);
  const layout = validateFixtureLayout(
    manifest,
    sourceSnapshot.identities,
  );
  const truthDocument = JSON.parse(
    (
      await readSnapshotFile(
        canonicalRoot,
        sourceSnapshot,
        "truth.json",
      )
    ).toString("utf8"),
  ) as unknown;
  const projectRoot = path.join(canonicalRoot, manifest.projectRoot);
  const truth = validateTruthSetV2(truthDocument, projectRoot);

  if (truth.fixtureId !== manifest.id) {
    throw new Error(
      `fixture ${manifest.id} truth fixtureId mismatch: ${truth.fixtureId}`,
    );
  }
  if (truth.findings.length !== manifest.expectedFindingCount) {
    throw new Error(
      `fixture ${manifest.id} expectedFindingCount ${manifest.expectedFindingCount} does not match truth count ${truth.findings.length}`,
    );
  }

  assertTruthUsesDeclaredSources(manifest, truth);
  const sourceFileLines: Record<string, number> = {};
  for (const sourceFile of manifest.sourceFiles) {
    sourceFileLines[sourceFile] = countSourceLines(
      (
        await readSnapshotFile(
          canonicalRoot,
          sourceSnapshot,
          fixtureProjectPath(sourceFile),
        )
      ).toString("utf8"),
    );
  }

  const finalSnapshot = await captureStableTree(
    canonicalRoot,
    EVALUATION_FIXTURE_LIMITS,
  );
  if (
    JSON.stringify(finalSnapshot.files) !==
      JSON.stringify(sourceSnapshot.files) ||
    JSON.stringify(finalSnapshot.identities) !==
      JSON.stringify(sourceSnapshot.identities)
  ) {
    throw new Error(
      `fixture ${manifest.id} changed while it was being loaded`,
    );
  }

  return {
    fixture: {
      fixtureRoot: canonicalRoot,
      projectRoot,
      layout,
      manifest,
      truth,
      sourceLines: Object.values(sourceFileLines).reduce(
        (total, lines) => total + lines,
        0,
      ),
      sourceFileLines,
    },
    sourceSnapshot,
  };
}

/**
 * Scores complete multi-mode experiment runs. Every metric in the returned
 * bundle is derived from matched findings loaded through the bound fixture
 * manifest/truth contract; callers cannot inject precomputed F1 values.
 */
export async function runScoredEvaluationSuite(
  input: EvaluationSuiteInput,
): Promise<ScoredEvaluationBundle> {
  validateSuiteInput(input);
  const fixtureCache = new Map<string, Promise<LoadedEvaluationFixture>>();
  const loadFixture = (fixtureRoot: string) => {
    const key = path.resolve(fixtureRoot);
    const cached = fixtureCache.get(key);
    if (cached) {
      return cached;
    }
    const pending = loadEvaluationFixture(key);
    fixtureCache.set(key, pending);
    return pending;
  };

  const runs: ScoredEvaluationRun[] = [];
  for (const run of input.runs) {
    const cases: ScoredEvaluationCase[] = [];
    for (const caseInput of run.cases) {
      cases.push(await scoreEvaluationCase(caseInput, loadFixture));
    }
    cases.sort((left, right) => left.fixtureId.localeCompare(right.fixtureId));
    assertUniqueFixtureIds(run.runId, cases);
    runs.push(scoreEvaluationRun(run, cases));
  }
  runs.sort(
    (left, right) =>
      left.mode.localeCompare(right.mode) ||
      left.runId.localeCompare(right.runId),
  );
  assertComparableFixtureSets(runs);

  const observations = runs.map(toObservation);
  return {
    schemaVersion: "1.0",
    suiteId: input.suiteId,
    runs,
    comparisons: {
      capability: buildCapabilityNormalizedComparison(
        observations,
        input.normalization.capabilityReference,
      ),
      cost: buildCostNormalizedComparison(observations, {
        targetCostUsd: input.normalization.targetCostUsd,
        toleranceUsd: input.normalization.toleranceUsd,
        ...(input.normalization.requiredModes
          ? { requiredModes: input.normalization.requiredModes }
          : {}),
      }),
    },
  };
}

async function scoreEvaluationCase(
  input: EvaluationSuiteCaseInput,
  loadFixture: (
    fixtureRoot: string,
  ) => Promise<LoadedEvaluationFixture>,
): Promise<ScoredEvaluationCase> {
  const fixture = await loadFixture(input.fixtureRoot);
  const projectedFindings = projectFindings(input.findings, {
    fixtureRoot: fixture.projectRoot,
  });
  const matchResult = matchFindings(fixture.truth.findings, projectedFindings);
  const metricsByCategory = computeCategoryMetrics(matchResult);
  const metricsByClass = computeVulnerabilityClassMetrics(matchResult);
  const metrics = applyGroupedF1(
    computeSuiteMetrics([matchResult], {
      sourceLines: fixture.sourceLines,
    }),
    metricsByClass,
  );
  const selectiveCounts = deriveSelectiveCounts([matchResult]);
  const completenessInput = normalizeCompletenessInput(
    fixture,
    input.completeness,
  );

  return {
    fixtureId: fixture.manifest.id,
    fixtureRoot: fixture.fixtureRoot,
    manifest: fixture.manifest,
    truth: fixture.truth,
    sourceLines: fixture.sourceLines,
    sourceFileLines: fixture.sourceFileLines,
    matchResult,
    metrics,
    metricsByCategory,
    metricsByClass,
    categorySummary: computeGroupedMetricSummary(metricsByCategory),
    classSummary: computeGroupedMetricSummary(metricsByClass),
    selectiveCounts,
    selective: computeSelectiveMetrics(selectiveCounts),
    completenessInput,
    completeness: computeExecutionCompleteness(completenessInput),
  };
}

function scoreEvaluationRun(
  input: EvaluationSuiteRunInput,
  cases: ScoredEvaluationCase[],
): ScoredEvaluationRun {
  const matchResults = cases.map((result) => result.matchResult);
  const sourceLines = cases.reduce(
    (total, result) => total + result.sourceLines,
    0,
  );
  const metricsByCategory = computeCategoryMetrics(matchResults);
  const metricsByClass = computeVulnerabilityClassMetrics(matchResults);
  const metrics = applyGroupedF1(
    computeSuiteMetrics(matchResults, { sourceLines }),
    metricsByClass,
  );
  const selectiveCounts = deriveSelectiveCounts(matchResults);

  return {
    runId: input.runId,
    mode: input.mode,
    costUsd: input.costUsd,
    totalTokens: input.totalTokens,
    agentCount: input.agentCount,
    capability: { ...input.capability },
    cases,
    matchResults,
    sourceLines,
    metrics,
    metricsByCategory,
    metricsByClass,
    categorySummary: computeGroupedMetricSummary(metricsByCategory),
    classSummary: computeGroupedMetricSummary(metricsByClass),
    selectiveCounts,
    selective: computeSelectiveMetrics(selectiveCounts),
    completeness: computeExecutionCompleteness(
      aggregateCompletenessInputs(cases),
    ),
  };
}

function deriveSelectiveCounts(
  matchResults: readonly MatchResult[],
): SelectiveEvaluationCounts {
  const counts: SelectiveEvaluationCounts = {
    totalExpected: 0,
    acceptedTruePositive: 0,
    acceptedFalsePositive: 0,
    needsReviewTruePositive: 0,
    needsReviewFalsePositive: 0,
    rejectedTruePositive: 0,
    rejectedFalsePositive: 0,
  };

  for (const result of matchResults) {
    counts.totalExpected +=
      result.matches.length + result.falseNegatives.length;
    for (const match of result.matches) {
      incrementDisposition(counts, match.actualDisposition, true);
    }
    for (const finding of result.falsePositives) {
      incrementDisposition(counts, finding.disposition, false);
    }
  }
  return counts;
}

function incrementDisposition(
  counts: SelectiveEvaluationCounts,
  disposition: "accepted" | "rejected" | "needs-review" | undefined,
  truePositive: boolean,
): void {
  const resolved = disposition ?? "accepted";
  if (resolved === "needs-review") {
    if (truePositive) counts.needsReviewTruePositive += 1;
    else counts.needsReviewFalsePositive += 1;
    return;
  }
  if (resolved === "rejected") {
    if (truePositive) {
      counts.rejectedTruePositive =
        (counts.rejectedTruePositive ?? 0) + 1;
    } else {
      counts.rejectedFalsePositive =
        (counts.rejectedFalsePositive ?? 0) + 1;
    }
    return;
  }
  if (truePositive) counts.acceptedTruePositive += 1;
  else counts.acceptedFalsePositive += 1;
}

function normalizeCompletenessInput(
  fixture: LoadedEvaluationFixture,
  input: ExecutionCompletenessInput,
): ExecutionCompletenessInput {
  return {
    plannedComponents: [...input.plannedComponents],
    completedComponents: [...input.completedComponents],
    ...(input.failedComponents
      ? { failedComponents: [...input.failedComponents] }
      : {}),
    ...(input.skippedComponents
      ? { skippedComponents: [...input.skippedComponents] }
      : {}),
    eligibleFiles: input.eligibleFiles ?? fixture.manifest.sourceFiles.length,
    ...(typeof input.inspectedFiles === "number"
      ? { inspectedFiles: input.inspectedFiles }
      : {}),
    ...(typeof input.inspectedBytes === "number"
      ? { inspectedBytes: input.inspectedBytes }
      : {}),
    ...(input.unsupportedLanguages
      ? { unsupportedLanguages: [...input.unsupportedLanguages] }
      : {}),
    ...(input.degradedReasons
      ? { degradedReasons: [...input.degradedReasons] }
      : {}),
  };
}

function aggregateCompletenessInputs(
  cases: readonly ScoredEvaluationCase[],
): ExecutionCompletenessInput {
  const prefix = (fixtureId: string, values: readonly string[]) =>
    values.map((value) => `${fixtureId}:${value}`);
  const inspectedFiles = cases.every(
    (result) =>
      typeof result.completenessInput.inspectedFiles === "number",
  )
    ? cases.reduce(
        (total, result) =>
          total + (result.completenessInput.inspectedFiles ?? 0),
        0,
      )
    : undefined;

  return {
    plannedComponents: cases.flatMap((result) =>
      prefix(
        result.fixtureId,
        result.completenessInput.plannedComponents,
      ),
    ),
    completedComponents: cases.flatMap((result) =>
      prefix(
        result.fixtureId,
        result.completenessInput.completedComponents,
      ),
    ),
    failedComponents: cases.flatMap((result) =>
      prefix(
        result.fixtureId,
        result.completenessInput.failedComponents ?? [],
      ),
    ),
    skippedComponents: cases.flatMap((result) =>
      prefix(
        result.fixtureId,
        result.completenessInput.skippedComponents ?? [],
      ),
    ),
    eligibleFiles: cases.reduce(
      (total, result) =>
        total + (result.completenessInput.eligibleFiles ?? 0),
      0,
    ),
    ...(typeof inspectedFiles === "number" ? { inspectedFiles } : {}),
    inspectedBytes: cases.reduce(
      (total, result) =>
        total + (result.completenessInput.inspectedBytes ?? 0),
      0,
    ),
    unsupportedLanguages: [
      ...new Set(
        cases.flatMap(
          (result) =>
            result.completenessInput.unsupportedLanguages ?? [],
        ),
      ),
    ].sort(),
    degradedReasons: cases
      .flatMap((result) =>
        (result.completenessInput.degradedReasons ?? []).map(
          (reason) => `${result.fixtureId}:${reason}`,
        ),
      )
      .sort(),
  };
}

function toObservation(run: ScoredEvaluationRun): ModeEvaluationObservation {
  return {
    runId: run.runId,
    mode: run.mode,
    precision: run.metrics.precision,
    recall: run.metrics.recall,
    f1: run.metrics.f1,
    costUsd: run.costUsd,
    totalTokens: run.totalTokens,
    agentCount: run.agentCount,
    capability: { ...run.capability },
  };
}

function validateSuiteInput(input: EvaluationSuiteInput): void {
  if (!input.suiteId.trim()) {
    throw new Error("evaluation suiteId is required");
  }
  if (input.runs.length === 0) {
    throw new Error("evaluation suite requires at least one run");
  }
  const runIds = new Set<string>();
  for (const run of input.runs) {
    if (!run.runId.trim() || !run.mode.trim()) {
      throw new Error("evaluation runs require runId and mode");
    }
    if (runIds.has(run.runId)) {
      throw new Error(`evaluation runId must be unique: ${run.runId}`);
    }
    runIds.add(run.runId);
    if (run.cases.length === 0) {
      throw new Error(`evaluation run ${run.runId} requires at least one case`);
    }
  }
}

function assertUniqueFixtureIds(
  runId: string,
  cases: readonly ScoredEvaluationCase[],
): void {
  const fixtureIds = new Set<string>();
  for (const result of cases) {
    if (fixtureIds.has(result.fixtureId)) {
      throw new Error(
        `evaluation run ${runId} repeats fixture ${result.fixtureId}`,
      );
    }
    fixtureIds.add(result.fixtureId);
  }
}

function assertComparableFixtureSets(
  runs: readonly ScoredEvaluationRun[],
): void {
  const reference = runs[0]?.cases.map((result) => result.fixtureId).join("\0");
  for (const run of runs.slice(1)) {
    const fixtureSet = run.cases
      .map((result) => result.fixtureId)
      .join("\0");
    if (fixtureSet !== reference) {
      throw new Error(
        `evaluation run ${run.runId} does not use the same fixture set as ${runs[0]?.runId}`,
      );
    }
  }
}

function assertTruthUsesDeclaredSources(
  manifest: FixtureManifestV2,
  truth: TruthSetV2,
): void {
  const declared = new Set(
    manifest.sourceFiles.map((sourceFile) => normalizeRelative(sourceFile)),
  );
  const declaredClasses = new Set(
    manifest.supportedVulnerabilityClasses,
  );
  for (const finding of truth.findings) {
    if (
      !finding.vulnerabilityClass ||
      !declaredClasses.has(finding.vulnerabilityClass)
    ) {
      throw new Error(
        `fixture ${manifest.id} truth ${finding.id} uses undeclared vulnerability class ${finding.vulnerabilityClass ?? "<missing>"}`,
      );
    }
    const evidenceLocations = [
      ...(finding.location ? [finding.location] : []),
      ...(finding.evidence?.sourceLocations ?? []),
    ];
    for (const location of evidenceLocations) {
      if (!declared.has(normalizeRelative(location.path))) {
        throw new Error(
          `fixture ${manifest.id} truth ${finding.id} references undeclared source ${location.path}`,
        );
      }
    }
  }
}

function normalizeRelative(value: string): string {
  return value.replace(/\\/g, "/").replace(/^\.\//, "").toLowerCase();
}

function countSourceLines(source: string): number {
  if (source.length === 0) {
    return 0;
  }
  const lineCount = source.split(/\r?\n/).length;
  return /\r?\n$/.test(source) ? lineCount - 1 : lineCount;
}

async function readSnapshotFile(
  fixtureRoot: string,
  snapshot: StableTreeSnapshot,
  relativePath: string,
): Promise<Buffer> {
  const expectedDigest = snapshot.files.find(
    (file) => file.path === relativePath,
  );
  const expectedIdentity = snapshot.identities.find(
    (entry) => entry.kind === "file" && entry.path === relativePath,
  );
  if (!expectedDigest || !expectedIdentity) {
    throw new Error(
      `fixture provenance is missing required file: ${relativePath}`,
    );
  }
  const file = await readStableConfinedFile(
    fixtureRoot,
    relativePath,
    {
      maxBytes: EVALUATION_FIXTURE_LIMITS.maxFileBytes,
      expectedIdentity: expectedIdentity.identity,
    },
  );
  if (
    file.bytes !== expectedDigest.bytes ||
    file.sha256 !== expectedDigest.sha256
  ) {
    throw new Error(
      `fixture provenance changed while reading: ${relativePath}`,
    );
  }
  return file.content;
}
