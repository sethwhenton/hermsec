import fs from "node:fs/promises";
import path from "node:path";
import {
  DEFAULT_SINGLE_TOOL_LIMITS,
  DEFAULT_SPECIALIST_TOOL_LIMITS,
} from "../agent/boundedToolLoop.js";
import type { CostLedger } from "../agent/costTracker.js";
import {
  runCanonicalAgentDetector,
  type CanonicalAgentDetectorMode,
  type CanonicalAgentDetectorResult,
  type CanonicalAgentRole,
} from "../agent/canonicalHarness.js";
import {
  MOA_ROLES,
  selectMoaRoles,
} from "../agent/moaRoles.js";
import { redactForLog, sanitizeErrorMessage } from "../agent/redaction.js";
import {
  runCanonicalScanOrchestration,
  type CanonicalAgentDetectorRunner,
  type CanonicalScanOrchestrationResult,
  type CanonicalScannerRunner,
} from "../core/canonicalOrchestrator.js";
import { canonicalScanAssistModes } from "../core/scanAssistModes.js";
import {
  EVALUATION_FIXTURE_LIMITS,
  loadStableEvaluationFixture,
  runScoredEvaluationSuite,
  type LoadedEvaluationFixture,
  type ScoredEvaluationBundle,
} from "../eval/suite.js";
import type { CapabilityBudget } from "../eval/modeComparison.js";
import type { ExecutionCompletenessInput } from "../eval/schema.js";
import type {
  ModelProviderAdapter,
  ModelRequest,
  ModelResponse,
  ModelUsage,
  ProviderConfig,
} from "../model/provider.js";
import type {
  Finding,
  ScanMode,
  ScanRun,
  ScanTerminalStatus,
} from "../shared/types.js";
import { stableId } from "../shared/text.js";
import {
  MAX_RESEARCH_GLOBAL_BUDGET_USD,
  MAX_RESEARCH_MODE_BUDGET_USD,
  type ResearchExecutionMode,
  type ResearchExecutionPolicy,
} from "./execution.js";
import {
  canonicalJson,
  prettyCanonicalJson,
  sha256,
  writeImmutableJson,
} from "./integrity.js";
import {
  createEmptyModelCallTrace,
  createModelCallTraceRecorder,
  MODEL_CALL_TRACE_FILE,
  type ResearchModelCallTrace,
} from "./modelCallTrace.js";
import { createDeterministicResearchMockResponder } from "./mockResponder.js";
import type {
  LivePricingValidationOptions,
  PricingSnapshot,
} from "./pricing.js";
import {
  attachReplayReference,
  ReplayCassetteStore,
} from "./replay.js";
import {
  createRunManifest,
  createSuiteIndex,
  RUN_MANIFEST_FILE,
  SUITE_INDEX_FILE,
  type CreateSuiteTruthBindingInput,
  type ResearchSuiteIndex,
} from "./runManifest.js";
import {
  createResearchModelSuiteRuntime,
  type ResearchModelRuntime,
} from "./runtime.js";
import {
  captureStableTree,
  hashStableConfinedFile,
  type StableTreeSnapshot,
  type StableTreeIdentity,
  type StableTreeLimits,
} from "./stableFiles.js";
import {
  createSubjectSnapshotWorkspace,
  materializeFixtureSnapshots,
  removeSubjectSnapshotWorkspace,
  sealSubjectSnapshotWorkspace,
  type SubjectSnapshotWorkspace,
} from "./subjectSnapshot.js";

export const RESEARCH_EXPERIMENT_MODES = canonicalScanAssistModes;

export const RESEARCH_EXACT_MODEL_ALLOWLIST = Object.freeze([
  "deepseek/deepseek-v4-flash",
  "xiaomi/mimo-v2.5",
  "minimax/minimax-m3",
] as const);

export type ResearchExperimentMode =
  (typeof RESEARCH_EXPERIMENT_MODES)[number];

export type ResearchExperimentFixtureInput = {
  fixtureRoot: string;
};

export type ResearchExperimentRunnerInput = {
  suiteId: string;
  suiteDirectory: string;
  fixtures: readonly ResearchExperimentFixtureInput[];
  execution: ResearchExecutionMode;
  provider: ModelProviderAdapter;
  pricingSnapshot: PricingSnapshot;
  pricingValidation?: LivePricingValidationOptions;
  replayDirectory?: string;
  recordMockCassettes?: boolean;
  recordLiveCassettes?: boolean;
  mockResponder?: (
    request: ModelRequest,
    context: { provider: string; model: string },
  ) => ModelResponse | Promise<ModelResponse>;
  scannerRunner?: CanonicalScannerRunner;
  agentDetectorRunner?: CanonicalAgentDetectorRunner;
  scanMode?: ScanMode;
  allowSpend?: boolean;
  signal?: AbortSignal;
  harnessVersion?: string;
  promptVersion?: string;
  normalization?: {
    targetCostUsd: number;
    toleranceUsd: number;
  };
  now?: () => Date;
};

export type ResearchExperimentCellStatus =
  | "success"
  | "partial"
  | "degraded"
  | "canceled"
  | "failed";

export type ResearchExperimentCost = {
  actualPhysicalSpendUsd: number;
  conservativeCommittedUsd: number;
  attributedCostUsd: number;
  physicalModelCalls: number;
  attributedModelCalls: number;
  physicalTokens: number;
  attributedTokens: number;
};

export type ResearchExperimentCell = {
  schemaVersion: "1.0";
  runId: string;
  fixtureId: string;
  pairId: string;
  fixtureVariant: "vulnerable" | "clean";
  mode: ResearchExperimentMode;
  execution: ResearchExecutionMode;
  physical: boolean;
  derivedFrom: ResearchExperimentMode[];
  status: ResearchExperimentCellStatus;
  findings: Finding[];
  rawScannerFindings: Finding[];
  rawAgentFindings: Finding[];
  scannerEvidence?: ResearchScannerEvidence;
  agentEvidence?: ResearchAgentEvidence;
  completeness: ExecutionCompletenessInput;
  degradationReasons: string[];
  cost: ResearchExperimentCost;
  models: string[];
  modelCallTrace: ResearchModelCallTrace;
  startedAt: string;
  finishedAt: string;
  artifactDirectory: string;
  manifestPath: string;
};

export type ResearchScannerEvidence = {
  runId: string;
  terminalStatus?: ScanTerminalStatus;
  scannerStatuses: ScanRun["scannerStatuses"];
  git?: ScanRun["git"];
};

export type ResearchAgentEvidence = Pick<
  CanonicalAgentDetectorResult,
  | "runId"
  | "mode"
  | "status"
  | "candidates"
  | "traces"
  | "coverage"
  | "roles"
  | "abstentions"
  | "judgments"
  | "groups"
>;

export type ResearchExperimentResult = {
  schemaVersion: "1.0";
  suiteId: string;
  execution: ResearchExecutionMode;
  suiteDirectory: string;
  fixtureIds: string[];
  modes: ResearchExperimentMode[];
  cells: ResearchExperimentCell[];
  evaluation: ScoredEvaluationBundle;
  suiteIndex: ResearchSuiteIndex;
  actualPhysicalSpendUsd: number;
  conservativeCommittedUsd: number;
  attributedModeCostUsd: Record<ResearchExperimentMode, number>;
  physicalExecutions: {
    scanners: number;
    agents: number;
    derivedHybrids: number;
  };
  artifacts: {
    evaluationPath: string;
    summaryPath: string;
    sourceIndexPath: string;
    suiteIndexPath: string;
    costLedgerPath: string;
    truthPaths: Record<string, string>;
  };
};

type FixtureContext = {
  loaded: LoadedEvaluationFixture;
  originalRoot: string;
  subjectRoot: string;
  sourceState: SourceStateArtifact;
  sourceIdentities: readonly StableTreeIdentity[];
  subjectIdentities: readonly StableTreeIdentity[];
  evaluatorIdentities: readonly StableTreeIdentity[];
  directoryName: string;
  truthArtifact?: PublishedFixtureTruth;
};

type PublishedFixtureTruth = Omit<
  CreateSuiteTruthBindingInput,
  | "projectRoot"
  | "projectDigestSha256"
  | "evaluatorDigestSha256"
  | "layoutBindingSha256"
> & {
  projectRoot: "project";
  projectDigestSha256: string;
  evaluatorDigestSha256: string;
  layoutBindingSha256: string;
  absolutePath: string;
  artifactSha256: string;
};

type SourceStateArtifact = {
  schemaVersion: "2.0";
  fixtureId: string;
  pairId: string;
  variant: "vulnerable" | "clean";
  language: string;
  files: Array<{
    path: string;
    bytes: number;
    sha256: string;
  }>;
  fixtureDigestSha256: string;
  project: {
    root: "project";
    files: Array<{
      path: string;
      bytes: number;
      sha256: string;
    }>;
    projectDigestSha256: string;
  };
  evaluator: {
    files: Array<{
      path: string;
      bytes: number;
      sha256: string;
    }>;
    evaluatorDigestSha256: string;
  };
  layoutBindingSha256: string;
  /**
   * Compatibility alias for readers that still call the isolated project
   * snapshot the "subject". It is derived from the structural project split.
   */
  subject: {
    files: Array<{
      path: string;
      bytes: number;
      sha256: string;
    }>;
    subjectDigestSha256: string;
    excludedControlFiles: string[];
    fixtureBindingSha256: string;
  };
};

type PhysicalScannerOutcome = {
  kind: "scanner";
  result?: Readonly<CanonicalScanOrchestrationResult>;
  error?: string;
};

type PhysicalAgentOutcome = {
  kind: "agent";
  mode: Extract<
    ResearchExperimentMode,
    "single-agent" | "moa-low" | "moa-high"
  >;
  detectorMode: CanonicalAgentDetectorMode;
  result?: Readonly<CanonicalAgentDetectorResult>;
  error?: string;
  runtime?: ResearchModelRuntime;
  actualSpendUsd: number;
  committedUsd: number;
  tokens: number;
  modelCalls: number;
  models: string[];
  modelCallTrace: ResearchModelCallTrace;
};

type CellDraft = Omit<
  ResearchExperimentCell,
  "artifactDirectory" | "manifestPath"
>;

const PHYSICAL_AGENT_MODES = [
  "single-agent",
  "moa-low",
  "moa-high",
] as const satisfies readonly ResearchExperimentMode[];

const HYBRID_MODE_BY_AGENT = Object.freeze({
  "single-agent": "scanner-single",
  "moa-low": "scanner-moa-low",
  "moa-high": "scanner-moa-high",
} as const);

const DEEPSEEK_FLASH = RESEARCH_EXACT_MODEL_ALLOWLIST[0];
const MIMO = RESEARCH_EXACT_MODEL_ALLOWLIST[1];
const MINIMAX_AGGREGATOR = RESEARCH_EXACT_MODEL_ALLOWLIST[2];
const RESULT_ARTIFACT = "result.json";
const EVIDENCE_ARTIFACT = "detector-evidence.json";
const COMPLETENESS_ARTIFACT = "completeness.json";
const COST_ARTIFACT = "cost.json";
const SOURCE_STATE_ARTIFACT = "source-state.json";
const TRUTH_EVIDENCE_ARTIFACT = "truth-evidence.json";
const CELL_ARTIFACTS = [
  RESULT_ARTIFACT,
  EVIDENCE_ARTIFACT,
  COMPLETENESS_ARTIFACT,
  COST_ARTIFACT,
  SOURCE_STATE_ARTIFACT,
  MODEL_CALL_TRACE_FILE,
] as const;

const FIXTURE_SOURCE_LIMITS = Object.freeze({
  ...EVALUATION_FIXTURE_LIMITS,
} satisfies StableTreeLimits);

const ALL_MOA_SPECIALIST_ROLES = Object.freeze(
  MOA_ROLES.map((role) => role.id),
);

/**
 * Executes the four independent detector paths for each fixture, derives the
 * three scanner/agent hybrids without provider dispatch, scores all seven
 * canonical modes, and publishes immutable evidence-bound artifacts.
 */
export async function runResearchExperiment(
  input: ResearchExperimentRunnerInput,
): Promise<Readonly<ResearchExperimentResult>> {
  validateRunnerInput(input);
  const snapshotWorkspace = await createSubjectSnapshotWorkspace();
  let result: Readonly<ResearchExperimentResult>;
  try {
    result = await runResearchExperimentWithWorkspace(
      input,
      snapshotWorkspace,
    );
  } catch (primaryError) {
    try {
      await removeSubjectSnapshotWorkspace(snapshotWorkspace);
    } catch (cleanupError) {
      throw new AggregateError(
        [primaryError, cleanupError],
        primaryError instanceof Error
          ? primaryError.message
          : "Research experiment failed before snapshot cleanup.",
        { cause: primaryError },
      );
    }
    throw primaryError;
  }
  await removeSubjectSnapshotWorkspace(snapshotWorkspace);
  return result;
}

async function runResearchExperimentWithWorkspace(
  input: ResearchExperimentRunnerInput,
  snapshotWorkspace: SubjectSnapshotWorkspace,
): Promise<Readonly<ResearchExperimentResult>> {
  const now = input.now ?? (() => new Date());
  const suiteDirectory = path.resolve(input.suiteDirectory);
  await assertFreshSuiteDirectory(suiteDirectory);
  await claimFreshCassetteRecordingDirectory(input);
  const fixtures = await loadFixtureContexts(
    input.fixtures,
    snapshotWorkspace,
  );
  await sealSubjectSnapshotWorkspace(
    snapshotWorkspace,
    FIXTURE_SOURCE_LIMITS,
  );
  await publishFixtureTruthArtifacts(suiteDirectory, fixtures);
  const suiteRuntime = createResearchModelSuiteRuntime({
    suiteId: input.suiteId,
    suiteDirectory,
  });
  await materializeZeroCostLedger(suiteRuntime.ledger);
  const mockResponder = await resolveMockResponder(input);
  const cells: ResearchExperimentCell[] = [];
  const manifestPaths: string[] = [];
  let scannerExecutions = 0;
  let agentExecutions = 0;
  let derivedHybrids = 0;

  for (const fixture of fixtures) {
    scannerExecutions += 1;
    const scanner = await executePhysicalScanner({
      input,
      fixture,
      now,
    });
    const scannerCell = await publishCell({
      suiteDirectory,
      suiteId: input.suiteId,
      fixture,
      draft: scannerCellDraft(input, fixture, scanner),
      harnessVersion: input.harnessVersion ?? "canonical-seven-mode-v1",
      promptVersion: input.promptVersion ?? "bounded-tool-agent-v1",
    });
    cells.push(scannerCell.cell);
    manifestPaths.push(scannerCell.manifestRelativePath);

    for (const mode of PHYSICAL_AGENT_MODES) {
      agentExecutions += 1;
      const agent = await executePhysicalAgent({
        input,
        fixture,
        mode,
        suiteRuntime,
        ...(mockResponder ? { mockResponder } : {}),
        now,
      });
      const agentCell = await publishCell({
        suiteDirectory,
        suiteId: input.suiteId,
        fixture,
        draft: agentCellDraft(input, fixture, agent),
        harnessVersion: input.harnessVersion ?? "canonical-seven-mode-v1",
        promptVersion: input.promptVersion ?? "bounded-tool-agent-v1",
      });
      cells.push(agentCell.cell);
      manifestPaths.push(agentCell.manifestRelativePath);

      derivedHybrids += 1;
      const hybrid = await deriveHybridCell({
        input,
        fixture,
        scanner,
        agent,
        hybridMode: HYBRID_MODE_BY_AGENT[mode],
        now,
      });
      const hybridCell = await publishCell({
        suiteDirectory,
        suiteId: input.suiteId,
        fixture,
        draft: hybrid,
        harnessVersion: input.harnessVersion ?? "canonical-seven-mode-v1",
        promptVersion: input.promptVersion ?? "bounded-tool-agent-v1",
      });
      cells.push(hybridCell.cell);
      manifestPaths.push(hybridCell.manifestRelativePath);
    }
  }

  assertCompleteModeMatrix(fixtures, cells);
  const scoredEvaluation = await withStableFixtures(
    fixtures,
    "scored evaluation",
    () =>
      runScoredEvaluationSuite({
        suiteId: input.suiteId,
        runs: RESEARCH_EXPERIMENT_MODES.map((mode) => {
          const modeCells = cells
            .filter((cell) => cell.mode === mode)
            .sort((left, right) =>
              left.fixtureId.localeCompare(right.fixtureId),
            );
          return {
            runId: stableId(
              `${input.suiteId}\u0000aggregate\u0000${mode}`,
              "evaluation-run",
            ),
            mode,
            cases: modeCells.map((cell) => ({
              fixtureRoot: requireFixture(fixtures, cell.fixtureId)
                .loaded.fixtureRoot,
              findings: cell.findings,
              completeness: cell.completeness,
            })),
            costUsd: sum(
              modeCells.map(
                (cell) => cell.cost.attributedCostUsd,
              ),
            ),
            totalTokens: Math.round(
              sum(
                modeCells.map(
                  (cell) => cell.cost.attributedTokens,
                ),
              ),
            ),
            agentCount: agentCountForMode(mode),
            capability: capabilityForMode(mode),
          };
        }),
        normalization: {
          targetCostUsd: input.normalization?.targetCostUsd ?? 0,
          toleranceUsd:
            input.normalization?.toleranceUsd ??
            MAX_RESEARCH_GLOBAL_BUDGET_USD,
          requiredModes: [...RESEARCH_EXPERIMENT_MODES],
        },
      }),
  );
  const evaluation = evaluationForPublication(
    scoredEvaluation,
    fixtures,
  );

  const sourceIndex = {
    schemaVersion: "1.0" as const,
    suiteId: input.suiteId,
    fixtures: fixtures.map((fixture) => ({
      ...fixture.sourceState,
      truthArtifact: {
        path: requireTruthArtifact(fixture).path,
        fixtureDigestSha256:
          requireTruthArtifact(fixture).fixtureDigestSha256,
        projectDigestSha256:
          requireTruthArtifact(fixture).projectDigestSha256,
        evaluatorDigestSha256:
          requireTruthArtifact(fixture).evaluatorDigestSha256,
        layoutBindingSha256:
          requireTruthArtifact(fixture).layoutBindingSha256,
      },
    })),
  };
  const ledgerSnapshot = await suiteRuntime.ledger.snapshot();
  const actualPhysicalSpendUsd = sum(
    cells
      .filter((cell) => cell.physical)
      .map((cell) => cell.cost.actualPhysicalSpendUsd),
  );
  const conservativeCommittedUsd = ledgerSnapshot.committedUsd;
  const attributedModeCostUsd = Object.fromEntries(
    RESEARCH_EXPERIMENT_MODES.map((mode) => [
      mode,
      sum(
        cells
          .filter((cell) => cell.mode === mode)
          .map((cell) => cell.cost.attributedCostUsd),
      ),
    ]),
  ) as Record<ResearchExperimentMode, number>;
  const evaluationPath = path.join(suiteDirectory, "evaluation.json");
  const sourceIndexPath = path.join(suiteDirectory, "source-index.json");
  const summaryPath = path.join(suiteDirectory, "experiment-summary.json");
  await withStableFixtures(
    fixtures,
    "evaluation artifact publication",
    () =>
      writeSafeImmutableJson(
        evaluationPath,
        evaluation,
        fixtures.flatMap(fixtureLocalRoots),
      ),
  );
  await withStableFixtures(
    fixtures,
    "source index artifact publication",
    () => writeSafeImmutableJson(sourceIndexPath, sourceIndex, []),
  );
  await withStableFixtures(
    fixtures,
    "experiment summary artifact publication",
    () =>
      writeSafeImmutableJson(
        summaryPath,
        {
          schemaVersion: "1.0",
          suiteId: input.suiteId,
          execution: input.execution,
          fixtureIds: fixtures.map(
            (fixture) => fixture.loaded.manifest.id,
          ),
          modes: [...RESEARCH_EXPERIMENT_MODES],
          physicalExecutions: {
            scanners: scannerExecutions,
            agents: agentExecutions,
            derivedHybrids,
          },
          actualPhysicalSpendUsd,
          conservativeCommittedUsd,
          attributedModeCostUsd,
          cells: cells.map((cell) => ({
            runId: cell.runId,
            fixtureId: cell.fixtureId,
            mode: cell.mode,
            status: cell.status,
            physical: cell.physical,
            derivedFrom: cell.derivedFrom,
            cost: cell.cost,
            manifestPath: normalizeRelative(
              path.relative(
                suiteDirectory,
                cell.manifestPath,
              ),
            ),
          })),
        },
        [],
      ),
  );
  const suiteIndex = await withStableFixtures(
    fixtures,
    "suite index publication",
    () =>
      createSuiteIndex(suiteDirectory, {
        suiteId: input.suiteId,
        createdAt: now().toISOString(),
        runManifestPaths: manifestPaths,
        artifactPaths: [
          normalizeRelative(
            path.relative(suiteDirectory, evaluationPath),
          ),
          normalizeRelative(
            path.relative(suiteDirectory, sourceIndexPath),
          ),
          normalizeRelative(
            path.relative(suiteDirectory, summaryPath),
          ),
          normalizeRelative(
            path.relative(
              suiteDirectory,
              suiteRuntime.ledger.filePath,
            ),
          ),
          ...fixtures.map(
            (fixture) => requireTruthArtifact(fixture).path,
          ),
        ],
        fixtureTruth: fixtures.map((fixture) => {
          const truthArtifact = requireTruthArtifact(fixture);
          return {
            fixtureId: truthArtifact.fixtureId,
            pairId: truthArtifact.pairId,
            variant: truthArtifact.variant,
            path: truthArtifact.path,
            fixtureDigestSha256:
              truthArtifact.fixtureDigestSha256,
            projectRoot: truthArtifact.projectRoot,
            projectDigestSha256:
              truthArtifact.projectDigestSha256,
            evaluatorDigestSha256:
              truthArtifact.evaluatorDigestSha256,
            layoutBindingSha256:
              truthArtifact.layoutBindingSha256,
          };
        }),
      }),
  );

  const result: Readonly<ResearchExperimentResult> = deepFreeze({
    schemaVersion: "1.0" as const,
    suiteId: input.suiteId,
    execution: input.execution,
    suiteDirectory,
    fixtureIds: fixtures.map((fixture) => fixture.loaded.manifest.id),
    modes: [...RESEARCH_EXPERIMENT_MODES],
    cells: stableCellOrder(cells),
    evaluation,
    suiteIndex,
    actualPhysicalSpendUsd,
    conservativeCommittedUsd,
    attributedModeCostUsd,
    physicalExecutions: {
      scanners: scannerExecutions,
      agents: agentExecutions,
      derivedHybrids,
    },
    artifacts: {
      evaluationPath,
      summaryPath,
      sourceIndexPath,
      suiteIndexPath: path.join(suiteDirectory, SUITE_INDEX_FILE),
      costLedgerPath: suiteRuntime.ledger.filePath,
      truthPaths: Object.fromEntries(
        fixtures.map((fixture) => [
          fixture.loaded.manifest.id,
          requireTruthArtifact(fixture).absolutePath,
        ]),
      ),
    },
  });
  await assertFixturesUnchanged(
    fixtures,
    "subject snapshot workspace cleanup",
  );
  return result;
}

async function executePhysicalScanner(input: {
  input: ResearchExperimentRunnerInput;
  fixture: FixtureContext;
  now: () => Date;
}): Promise<PhysicalScannerOutcome> {
  const runId = cellRunId(
    input.input.suiteId,
    input.fixture.loaded.manifest.id,
    "scanner-only",
  );
  await assertFixtureUnchanged(
    input.fixture,
    "scanner-only physical execution",
  );
  try {
    return {
      kind: "scanner",
      result: await runCanonicalScanOrchestration({
        target: input.fixture.subjectRoot,
        assistMode: "scanner-only",
        scanMode: input.input.scanMode ?? "offline",
        runId,
        ...(input.input.signal ? { signal: input.input.signal } : {}),
        ...(input.input.scannerRunner
          ? { scannerRunner: input.input.scannerRunner }
          : {}),
        agentDetectorRunner: async () => {
          throw new Error("Scanner-only execution cannot dispatch an agent.");
        },
        now: input.now,
      }),
    };
  } catch (error) {
    return {
      kind: "scanner",
      error: safeError(error, "Scanner execution failed."),
    };
  } finally {
    await assertFixtureUnchanged(
      input.fixture,
      "completed scanner-only physical execution",
    );
  }
}

async function executePhysicalAgent(input: {
  input: ResearchExperimentRunnerInput;
  fixture: FixtureContext;
  mode: (typeof PHYSICAL_AGENT_MODES)[number];
  suiteRuntime: ReturnType<typeof createResearchModelSuiteRuntime>;
  mockResponder?: (
    request: ModelRequest,
    context: { provider: string; model: string },
  ) => ModelResponse | Promise<ModelResponse>;
  now: () => Date;
}): Promise<PhysicalAgentOutcome> {
  const runId = cellRunId(
    input.input.suiteId,
    input.fixture.loaded.manifest.id,
    input.mode,
  );
  const detectorMode = detectorModeFor(input.mode);
  const replayScopeId = [
    input.fixture.loaded.manifest.id,
    input.fixture.sourceState.fixtureDigestSha256,
    input.input.harnessVersion ?? "canonical-seven-mode-v1",
    input.input.promptVersion ?? "bounded-tool-agent-v1",
    input.mode,
  ].join("\u0000");
  const scopedMockResponder = input.mockResponder
    ? scopedCassetteMockResponder(input, replayScopeId)
    : undefined;
  let runtime: ResearchModelRuntime | undefined;
  let plannedSpecialistRoles:
    | readonly CanonicalAgentRole[]
    | undefined =
    input.mode === "single-agent"
      ? ["single-agent-inspector"]
      : input.mode === "moa-high"
        ? ALL_MOA_SPECIALIST_ROLES
        : undefined;
  const traceRecorder = createModelCallTraceRecorder({
    runId,
    mode: input.mode,
    execution: input.input.execution,
    cassettePolicy:
      input.input.execution === "replay"
        ? "replay"
        : input.input.recordMockCassettes ||
            input.input.recordLiveCassettes
          ? "recorded"
          : "none",
    expectedProvider: "openrouter",
    modelForRole,
  });
  await assertFixtureUnchanged(
    input.fixture,
    `${input.mode} physical execution`,
  );
  try {
    const runDirectory = cellDirectory(
      path.resolve(input.input.suiteDirectory),
      input.fixture.directoryName,
      input.mode,
    );
    runtime = input.suiteRuntime.createRun({
      runDirectory,
      runId,
      mode: input.mode,
      policy: executionPolicy(input.input, input.mode),
      provider: input.input.provider,
      pricingSnapshot: input.input.pricingSnapshot,
      ...(input.input.pricingValidation
        ? { pricingValidation: input.input.pricingValidation }
        : {}),
      ...(input.input.replayDirectory
        ? { replayDirectory: path.resolve(input.input.replayDirectory) }
        : {}),
      replayScopeId,
      ...(input.input.recordLiveCassettes !== undefined
        ? { recordLiveCassettes: input.input.recordLiveCassettes }
        : {}),
      ...(scopedMockResponder ? { mockResponder: scopedMockResponder } : {}),
      defaultMaxTokens: 2_000,
      local: input.input.execution !== "live",
    });
    const detector =
      input.input.agentDetectorRunner ?? runCanonicalAgentDetector;
    const result = await detector({
      repoRoot: input.fixture.subjectRoot,
      mode: detectorMode,
      runId,
      ...(input.input.signal ? { signal: input.input.signal } : {}),
      resolveModel: ({ role, gapFill, profile }) => {
        plannedSpecialistRoles = bindCanonicalRolePlan(
          plannedSpecialistRoles,
          rolePlanForProfile(detectorMode, profile),
        );
        const providerConfig = providerConfigForRole(role);
        return {
          provider: traceRecorder.wrapProvider({
            role,
            gapFill,
            provider: runtime!.provider,
            providerConfig,
          }),
          providerConfig,
        };
      },
      now: input.now,
    });
    plannedSpecialistRoles = bindCanonicalRolePlan(
      plannedSpecialistRoles,
      rolePlanForResult(detectorMode, result),
    );
    const modelCallTrace = traceRecorder.finalize({
      physical: true,
      detectorStatus: result.status,
      candidateCount: result.candidates.length,
      requiredSpecialistRoles: plannedSpecialistRoles,
    });
    await validateTraceCassetteReferences({
      trace: modelCallTrace,
      runtime,
      required:
        input.input.execution === "replay" ||
        Boolean(input.input.recordMockCassettes) ||
        Boolean(input.input.recordLiveCassettes),
    });
    const costs = await runtimeCosts(runtime, runId, input.mode);
    return {
      kind: "agent",
      mode: input.mode,
      detectorMode,
      result,
      runtime,
      ...costs,
      tokens: totalTokens(result.usages),
      modelCalls: modelCallTrace.calls.length,
      models: usedTraceModels(modelCallTrace),
      modelCallTrace,
    };
  } catch (error) {
    const modelCallTrace = traceRecorder.finalize({
      physical: true,
      detectorStatus: input.input.signal?.aborted ? "canceled" : "failed",
      candidateCount: 0,
      ...(plannedSpecialistRoles
        ? { requiredSpecialistRoles: plannedSpecialistRoles }
        : {}),
    });
    const costs = runtime
      ? await runtimeCosts(runtime, runId, input.mode)
      : { actualSpendUsd: 0, committedUsd: 0 };
    return {
      kind: "agent",
      mode: input.mode,
      detectorMode,
      error: safeError(error, `${input.mode} execution failed.`),
      ...(runtime ? { runtime } : {}),
      ...costs,
      tokens: 0,
      modelCalls: modelCallTrace.calls.length,
      models: usedTraceModels(modelCallTrace),
      modelCallTrace,
    };
  } finally {
    await assertFixtureUnchanged(
      input.fixture,
      `completed ${input.mode} physical execution`,
    );
  }
}

async function deriveHybridCell(input: {
  input: ResearchExperimentRunnerInput;
  fixture: FixtureContext;
  scanner: PhysicalScannerOutcome;
  agent: PhysicalAgentOutcome;
  hybridMode: Extract<
    ResearchExperimentMode,
    "scanner-single" | "scanner-moa-low" | "scanner-moa-high"
  >;
  now: () => Date;
}): Promise<CellDraft> {
  const runId = cellRunId(
    input.input.suiteId,
    input.fixture.loaded.manifest.id,
    input.hybridMode,
  );
  await assertFixtureUnchanged(
    input.fixture,
    `${input.hybridMode} derivation`,
  );
  try {
    const result = await runCanonicalScanOrchestration({
      target: input.fixture.subjectRoot,
      assistMode: input.hybridMode,
      scanMode: input.input.scanMode ?? "offline",
      runId,
      ...(input.input.signal ? { signal: input.input.signal } : {}),
      scannerRunner: async () => {
        if (!input.scanner.result) {
          throw new Error(input.scanner.error ?? "Physical scanner unavailable.");
        }
        return structuredClone(input.scanner.result.scan);
      },
      agentDetectorRunner: async () => {
        if (
          !input.agent.result ||
          !input.agent.modelCallTrace.producerValidation.valid
        ) {
          throw new Error(input.agent.error ?? "Physical agent unavailable.");
        }
        return structuredClone(input.agent.result);
      },
      resolveModel: () => {
        throw new Error("Derived hybrid modes cannot resolve or call a model.");
      },
      now: input.now,
    });
    return orchestrationCellDraft({
      input: input.input,
      fixture: input.fixture,
      mode: input.hybridMode,
      result,
      physical: false,
      derivedFrom: ["scanner-only", input.agent.mode],
      cost: {
        actualPhysicalSpendUsd: 0,
        conservativeCommittedUsd: 0,
        attributedCostUsd: attributedAgentCost(input.agent),
        physicalModelCalls: 0,
        attributedModelCalls: input.agent.modelCalls,
        physicalTokens: 0,
        attributedTokens: input.agent.tokens,
      },
      models: input.agent.models,
      modelCallTrace: createEmptyModelCallTrace({
        runId,
        mode: input.hybridMode,
        execution: input.input.execution,
        physical: false,
        derivedFrom: ["scanner-only", input.agent.mode],
      }),
    });
  } catch (error) {
    const timestamp = input.now().toISOString();
    const degradationReasons = [
      safeError(error, `${input.hybridMode} derivation failed.`),
    ];
    return {
      schemaVersion: "1.0",
      runId,
      fixtureId: input.fixture.loaded.manifest.id,
      pairId: input.fixture.loaded.manifest.pairId,
      fixtureVariant: input.fixture.loaded.manifest.variant,
      mode: input.hybridMode,
      execution: input.input.execution,
      physical: false,
      derivedFrom: ["scanner-only", input.agent.mode],
      status: "failed",
      findings: [],
      rawScannerFindings:
        input.scanner.result?.scannerFindings.map(cloneFinding) ?? [],
      rawAgentFindings:
        input.agent.result?.rawFindings.map(cloneFinding) ?? [],
      ...(input.scanner.result
        ? {
            scannerEvidence: scannerEvidence(
              input.scanner.result.scan,
            ),
          }
        : {}),
      ...(input.agent.result
        ? { agentEvidence: agentEvidence(input.agent.result) }
        : {}),
      completeness: failedCompleteness(
        componentsForMode(input.hybridMode),
        degradationReasons,
        input.fixture,
      ),
      degradationReasons,
      cost: {
        actualPhysicalSpendUsd: 0,
        conservativeCommittedUsd: 0,
        attributedCostUsd: attributedAgentCost(input.agent),
        physicalModelCalls: 0,
        attributedModelCalls: input.agent.modelCalls,
        physicalTokens: 0,
        attributedTokens: input.agent.tokens,
      },
      models: [...input.agent.models],
      modelCallTrace: createEmptyModelCallTrace({
        runId,
        mode: input.hybridMode,
        execution: input.input.execution,
        physical: false,
        derivedFrom: ["scanner-only", input.agent.mode],
        detectorStatus: "failed",
      }),
      startedAt: timestamp,
      finishedAt: timestamp,
    };
  } finally {
    await assertFixtureUnchanged(
      input.fixture,
      `completed ${input.hybridMode} derivation`,
    );
  }
}

function scannerCellDraft(
  input: ResearchExperimentRunnerInput,
  fixture: FixtureContext,
  outcome: PhysicalScannerOutcome,
): CellDraft {
  if (outcome.result) {
    return orchestrationCellDraft({
      input,
      fixture,
      mode: "scanner-only",
      result: outcome.result,
      physical: true,
      derivedFrom: [],
      cost: emptyPhysicalCost(),
      models: [],
      modelCallTrace: createEmptyModelCallTrace({
        runId: cellRunId(
          input.suiteId,
          fixture.loaded.manifest.id,
          "scanner-only",
        ),
        mode: "scanner-only",
        execution: input.execution,
        physical: true,
      }),
    });
  }
  const timestamp = (input.now ?? (() => new Date()))().toISOString();
  const degradationReasons = [
    outcome.error ?? "Scanner execution failed without a reason.",
  ];
  return {
    schemaVersion: "1.0",
    runId: cellRunId(
      input.suiteId,
      fixture.loaded.manifest.id,
      "scanner-only",
    ),
    fixtureId: fixture.loaded.manifest.id,
    pairId: fixture.loaded.manifest.pairId,
    fixtureVariant: fixture.loaded.manifest.variant,
    mode: "scanner-only",
    execution: input.execution,
    physical: true,
    derivedFrom: [],
    status: "failed",
    findings: [],
    rawScannerFindings: [],
    rawAgentFindings: [],
    completeness: failedCompleteness(
      componentsForMode("scanner-only"),
      degradationReasons,
      fixture,
    ),
    degradationReasons,
    cost: emptyPhysicalCost(),
    models: [],
    modelCallTrace: createEmptyModelCallTrace({
      runId: cellRunId(
        input.suiteId,
        fixture.loaded.manifest.id,
        "scanner-only",
      ),
      mode: "scanner-only",
      execution: input.execution,
      physical: true,
      detectorStatus: "failed",
    }),
    startedAt: timestamp,
    finishedAt: timestamp,
  };
}

function agentCellDraft(
  input: ResearchExperimentRunnerInput,
  fixture: FixtureContext,
  outcome: PhysicalAgentOutcome,
): CellDraft {
  const cost: ResearchExperimentCost = {
    actualPhysicalSpendUsd: outcome.actualSpendUsd,
    conservativeCommittedUsd: outcome.committedUsd,
    attributedCostUsd: attributedAgentCost(outcome),
    physicalModelCalls: outcome.modelCalls,
    attributedModelCalls: outcome.modelCalls,
    physicalTokens: outcome.tokens,
    attributedTokens: outcome.tokens,
  };
  const traceErrors = outcome.modelCallTrace.producerValidation.errors.map(
    (error) => `model-call-trace-integrity:${error}`,
  );
  if (outcome.result) {
    const traceInvalid = traceErrors.length > 0;
    const resultStatus = agentStatus(outcome.result.status);
    return {
      schemaVersion: "1.0",
      runId: cellRunId(
        input.suiteId,
        fixture.loaded.manifest.id,
        outcome.mode,
      ),
      fixtureId: fixture.loaded.manifest.id,
      pairId: fixture.loaded.manifest.pairId,
      fixtureVariant: fixture.loaded.manifest.variant,
      mode: outcome.mode,
      execution: input.execution,
      physical: true,
      derivedFrom: [],
      status:
        traceInvalid && resultStatus === "success"
          ? "failed"
          : resultStatus,
      findings: outcome.result.findings.map(cloneFinding),
      rawScannerFindings: [],
      rawAgentFindings: outcome.result.rawFindings.map(cloneFinding),
      agentEvidence: agentEvidence(outcome.result),
      completeness: traceInvalid
        ? failedCompleteness(
            componentsForMode(outcome.mode),
            traceErrors,
            fixture,
          )
        : agentCompleteness(outcome.result, fixture),
      degradationReasons: [
        ...outcome.result.limitations,
        ...traceErrors,
      ],
      cost,
      models: [...outcome.models],
      modelCallTrace: outcome.modelCallTrace,
      startedAt: outcome.result.startedAt,
      finishedAt: outcome.result.finishedAt,
    };
  }
  const timestamp = (input.now ?? (() => new Date()))().toISOString();
  const degradationReasons = [
    outcome.error ?? `${outcome.mode} failed without a reason.`,
    ...traceErrors,
  ];
  return {
    schemaVersion: "1.0",
    runId: cellRunId(
      input.suiteId,
      fixture.loaded.manifest.id,
      outcome.mode,
    ),
    fixtureId: fixture.loaded.manifest.id,
    pairId: fixture.loaded.manifest.pairId,
    fixtureVariant: fixture.loaded.manifest.variant,
    mode: outcome.mode,
    execution: input.execution,
    physical: true,
    derivedFrom: [],
    status: "failed",
    findings: [],
    rawScannerFindings: [],
    rawAgentFindings: [],
    completeness: failedCompleteness(
      componentsForMode(outcome.mode),
      degradationReasons,
      fixture,
    ),
    degradationReasons,
    cost,
    models: [...outcome.models],
    modelCallTrace: outcome.modelCallTrace,
    startedAt: timestamp,
    finishedAt: timestamp,
  };
}

function orchestrationCellDraft(input: {
  input: ResearchExperimentRunnerInput;
  fixture: FixtureContext;
  mode: ResearchExperimentMode;
  result: Readonly<CanonicalScanOrchestrationResult>;
  physical: boolean;
  derivedFrom: ResearchExperimentMode[];
  cost: ResearchExperimentCost;
  models: string[];
  modelCallTrace: ResearchModelCallTrace;
}): CellDraft {
  return {
    schemaVersion: "1.0",
    runId: cellRunId(
      input.input.suiteId,
      input.fixture.loaded.manifest.id,
      input.mode,
    ),
    fixtureId: input.fixture.loaded.manifest.id,
    pairId: input.fixture.loaded.manifest.pairId,
    fixtureVariant: input.fixture.loaded.manifest.variant,
    mode: input.mode,
    execution: input.input.execution,
    physical: input.physical,
    derivedFrom: [...input.derivedFrom],
    status: terminalStatus(input.result.terminalStatus),
    findings: input.result.findings.map(cloneFinding),
    rawScannerFindings: input.result.scannerFindings.map(cloneFinding),
    rawAgentFindings:
      input.result.agentResult?.rawFindings.map(cloneFinding) ?? [],
    scannerEvidence: scannerEvidence(input.result.scan),
    ...(input.result.agentResult
      ? { agentEvidence: agentEvidence(input.result.agentResult) }
      : {}),
    completeness: orchestrationCompleteness(input.result, input.fixture),
    degradationReasons: [...input.result.degradationReasons],
    cost: { ...input.cost },
    models: [...input.models],
    modelCallTrace: input.modelCallTrace,
    startedAt: input.result.startedAt,
    finishedAt: input.result.finishedAt,
  };
}

async function publishCell(input: {
  suiteDirectory: string;
  suiteId: string;
  fixture: FixtureContext;
  draft: CellDraft;
  harnessVersion: string;
  promptVersion: string;
}): Promise<{
  cell: ResearchExperimentCell;
  manifestRelativePath: string;
}> {
  return withStableFixture(
    input.fixture,
    `${input.draft.mode} immutable run publication`,
    async () => {
      const directory = cellDirectory(
        input.suiteDirectory,
        input.fixture.directoryName,
        input.draft.mode,
      );
      await fs.mkdir(directory, { recursive: true });
      await writeSafeImmutableJson(
        path.join(directory, RESULT_ARTIFACT),
        {
          schemaVersion: "1.0",
          runId: input.draft.runId,
          fixtureId: input.draft.fixtureId,
          pairId: input.draft.pairId,
          fixtureVariant: input.draft.fixtureVariant,
          mode: input.draft.mode,
          execution: input.draft.execution,
          physical: input.draft.physical,
          derivedFrom: input.draft.derivedFrom,
          status: input.draft.status,
          findings: input.draft.findings,
          degradationReasons: input.draft.degradationReasons,
          startedAt: input.draft.startedAt,
          finishedAt: input.draft.finishedAt,
        },
        fixtureLocalRoots(input.fixture),
      );
      await writeSafeImmutableJson(
        path.join(directory, EVIDENCE_ARTIFACT),
        {
          schemaVersion: "1.0",
          rawScannerFindings: input.draft.rawScannerFindings,
          rawAgentFindings: input.draft.rawAgentFindings,
          ...(input.draft.scannerEvidence
            ? { scannerEvidence: input.draft.scannerEvidence }
            : {}),
          ...(input.draft.agentEvidence
            ? { agentEvidence: input.draft.agentEvidence }
            : {}),
          finalFindings: input.draft.findings,
        },
        fixtureLocalRoots(input.fixture),
      );
      await writeSafeImmutableJson(
        path.join(directory, COMPLETENESS_ARTIFACT),
        input.draft.completeness,
        [],
      );
      await writeSafeImmutableJson(
        path.join(directory, COST_ARTIFACT),
        input.draft.cost,
        [],
      );
      await writeSafeImmutableJson(
        path.join(directory, SOURCE_STATE_ARTIFACT),
        input.fixture.sourceState,
        [],
      );
      await writeSafeImmutableJson(
        path.join(directory, MODEL_CALL_TRACE_FILE),
        input.draft.modelCallTrace,
        [],
      );
      const truthArtifact = requireTruthArtifact(input.fixture);
      await createRunManifest(directory, {
        runId: input.draft.runId,
        suite: input.suiteId,
        mode: input.draft.mode,
        execution: input.draft.execution,
        status: input.draft.status,
        startedAt: input.draft.startedAt,
        finishedAt: input.draft.finishedAt,
        harnessVersion: input.harnessVersion,
        promptVersion: input.promptVersion,
        sourceState: input.fixture.sourceState,
        limits: {
          capability: capabilityForMode(input.draft.mode),
          globalBudgetUsd: MAX_RESEARCH_GLOBAL_BUDGET_USD,
          modeBudgetUsd: MAX_RESEARCH_MODE_BUDGET_USD[input.draft.mode],
          noModelFallback: true,
        },
        models: input.draft.models.map((model) => ({
          provider: "openrouter",
          model,
        })),
        metadata: {
          fixtureId: input.draft.fixtureId,
          pairId: input.draft.pairId,
          fixtureVariant: input.draft.fixtureVariant,
          physical: input.draft.physical,
          derivedFrom: input.draft.derivedFrom,
          modelCallTraceSchemaVersion: "1.0",
          modelCallTraceRolePlanVersion: "1.0",
          modelCallTraceCassettePolicy:
            input.draft.modelCallTrace.cassettePolicy,
          subjectSnapshotSchemaVersion: "2.0",
          projectSnapshotSchemaVersion: "1.0",
          truthArtifact: {
            fixtureId: truthArtifact.fixtureId,
            path: truthArtifact.path,
            fixtureDigestSha256:
              truthArtifact.fixtureDigestSha256,
            projectRoot: truthArtifact.projectRoot,
            projectDigestSha256:
              truthArtifact.projectDigestSha256,
            evaluatorDigestSha256:
              truthArtifact.evaluatorDigestSha256,
            layoutBindingSha256:
              truthArtifact.layoutBindingSha256,
          },
          projectSnapshot: {
            root: input.fixture.sourceState.project.root,
            projectDigestSha256:
              input.fixture.sourceState.project.projectDigestSha256,
            evaluatorDigestSha256:
              input.fixture.sourceState.evaluator
                .evaluatorDigestSha256,
            layoutBindingSha256:
              input.fixture.sourceState.layoutBindingSha256,
          },
          subjectSnapshot: {
            subjectDigestSha256:
              input.fixture.sourceState.subject
                .subjectDigestSha256,
            fixtureBindingSha256:
              input.fixture.sourceState.subject
                .fixtureBindingSha256,
          },
          cost: input.draft.cost,
          degradationReasons: input.draft.degradationReasons,
        },
        artifactPaths: CELL_ARTIFACTS,
      });
      const manifestPath = path.join(
        directory,
        RUN_MANIFEST_FILE,
      );
      const manifestRelativePath = normalizeRelative(
        path.relative(input.suiteDirectory, manifestPath),
      );
      return {
        cell: {
          ...input.draft,
          artifactDirectory: directory,
          manifestPath,
        },
        manifestRelativePath,
      };
    },
  );
}

function orchestrationCompleteness(
  result: Readonly<CanonicalScanOrchestrationResult>,
  fixture: FixtureContext,
): ExecutionCompletenessInput {
  const scanner = scannerCompleteness(result.scan, fixture);
  if (result.mode === "scanner-only") {
    return scanner;
  }
  const agent = result.agentResult
    ? agentCompleteness(result.agentResult, fixture)
    : failedCompleteness(
        componentsForMode(result.mode).filter(
          (component) => !component.startsWith("scanner:"),
        ),
        result.degradationReasons.length > 0
          ? result.degradationReasons
          : ["Agent detector result is unavailable."],
        fixture,
      );
  return mergeCompleteness(scanner, agent);
}

function scannerCompleteness(
  scan: ScanRun,
  fixture: FixtureContext,
): ExecutionCompletenessInput {
  const statuses =
    scan.scannerStatuses.length > 0
      ? scan.scannerStatuses
      : [
          {
            id: "scanner-path",
            label: "Scanner path",
            status: "failed" as const,
            message: "Scanner path returned no component status.",
          },
        ];
  const plannedComponents = statuses.map(
    (status) => `scanner:${status.id}`,
  );
  const completedComponents = statuses
    .filter(
      (status) =>
        status.status === "completed" || status.status === "ready",
    )
    .map((status) => `scanner:${status.id}`);
  const failedComponents = statuses
    .filter(
      (status) =>
        status.status === "failed" || status.status === "missing",
    )
    .map((status) => `scanner:${status.id}`);
  const skippedComponents = statuses
    .filter((status) => status.status === "skipped")
    .map((status) => `scanner:${status.id}`);
  return {
    plannedComponents,
    completedComponents,
    failedComponents,
    skippedComponents,
    eligibleFiles: fixture.loaded.manifest.sourceFiles.length,
    inspectedFiles:
      scan.terminalStatus === "failed" || scan.terminalStatus === "canceled"
        ? 0
        : fixture.loaded.manifest.sourceFiles.length,
    inspectedBytes: sourceBytes(fixture),
    ...(scan.degradationReasons?.length
      ? { degradedReasons: [...scan.degradationReasons] }
      : {}),
  };
}

function agentCompleteness(
  result: Readonly<CanonicalAgentDetectorResult>,
  fixture: FixtureContext,
): ExecutionCompletenessInput {
  if (result.mode === "single") {
    const role = result.roles[0];
    const component = "agent:single-agent-inspector";
    const coverage =
      result.coverage.kind === "single"
        ? result.coverage
        : {
            totalFiles: result.profile.files.length,
            inspectedFiles: [],
          };
    return {
      plannedComponents: [component],
      completedComponents:
        role && ["completed", "partial", "degraded"].includes(role.status)
          ? [component]
          : [],
      failedComponents:
        !role || role.status === "failed" || role.status === "canceled"
          ? [component]
          : [],
      skippedComponents: role?.status === "skipped" ? [component] : [],
      eligibleFiles: coverage.totalFiles,
      inspectedFiles: coverage.inspectedFiles.length,
      inspectedBytes: sum(result.traces.map((trace) => trace.bytes)),
      degradedReasons: [
        ...result.limitations,
        ...(role && role.status !== "completed"
          ? [`${component} finished as ${role.status}.`]
          : []),
      ],
    };
  }

  const roleComponents = result.roles.map(
    (role, index) =>
      `agent:${role.role}${role.gapFill ? `:gap-fill-${index}` : ""}`,
  );
  const plannedComponents = [
    ...roleComponents,
    "agent:moa-judge",
    "agent:moa-aggregator",
  ];
  const completedComponents = [
    ...result.roles.flatMap((role, index) =>
      ["completed", "partial", "degraded"].includes(role.status)
        ? [
            `agent:${role.role}${
              role.gapFill ? `:gap-fill-${index}` : ""
            }`,
          ]
        : [],
    ),
    ...(result.judgments !== undefined ? ["agent:moa-judge"] : []),
    ...(result.groups !== undefined ? ["agent:moa-aggregator"] : []),
  ];
  const failedComponents = [
    ...result.roles.flatMap((role, index) =>
      role.status === "failed" || role.status === "canceled"
        ? [
            `agent:${role.role}${
              role.gapFill ? `:gap-fill-${index}` : ""
            }`,
          ]
        : [],
    ),
    ...(result.status === "failed" && result.judgments === undefined
      ? ["agent:moa-judge"]
      : []),
    ...(result.status === "failed" && result.groups === undefined
      ? ["agent:moa-aggregator"]
      : []),
  ];
  const skippedComponents = [
    ...result.roles.flatMap((role, index) =>
      role.status === "skipped"
        ? [
            `agent:${role.role}${
              role.gapFill ? `:gap-fill-${index}` : ""
            }`,
          ]
        : [],
    ),
    ...(result.status === "canceled" && result.judgments === undefined
      ? ["agent:moa-judge"]
      : []),
    ...(result.status === "canceled" && result.groups === undefined
      ? ["agent:moa-aggregator"]
      : []),
  ];
  return {
    plannedComponents,
    completedComponents,
    failedComponents,
    skippedComponents,
    eligibleFiles: result.profile.files.length,
    inspectedFiles: new Set(
      result.traces.flatMap((trace) =>
        result.roles
          .filter(
            (role) =>
              role.role === trace.role && role.gapFill === trace.gapFill,
          )
          .flatMap((role) => role.inspectedFiles),
      ),
    ).size,
    inspectedBytes: sum(result.traces.map((trace) => trace.bytes)),
    degradedReasons: [
      ...result.limitations,
      ...result.roles.flatMap((role) =>
        role.status !== "completed"
          ? [`agent:${role.role} finished as ${role.status}.`]
          : [],
      ),
    ],
    unsupportedLanguages:
      result.profile.languages.length === 0 &&
      fixture.loaded.manifest.sourceFiles.length > 0
        ? [fixture.loaded.manifest.language]
        : [],
  };
}

function failedCompleteness(
  plannedComponents: readonly string[],
  reasons: readonly string[],
  fixture: FixtureContext,
): ExecutionCompletenessInput {
  return {
    plannedComponents: [...plannedComponents],
    completedComponents: [],
    failedComponents: [...plannedComponents],
    skippedComponents: [],
    eligibleFiles: fixture.loaded.manifest.sourceFiles.length,
    inspectedFiles: 0,
    inspectedBytes: 0,
    degradedReasons: [...reasons],
  };
}

function mergeCompleteness(
  left: ExecutionCompletenessInput,
  right: ExecutionCompletenessInput,
): ExecutionCompletenessInput {
  return {
    plannedComponents: uniqueSorted([
      ...left.plannedComponents,
      ...right.plannedComponents,
    ]),
    completedComponents: uniqueSorted([
      ...left.completedComponents,
      ...right.completedComponents,
    ]),
    failedComponents: uniqueSorted([
      ...(left.failedComponents ?? []),
      ...(right.failedComponents ?? []),
    ]),
    skippedComponents: uniqueSorted([
      ...(left.skippedComponents ?? []),
      ...(right.skippedComponents ?? []),
    ]),
    eligibleFiles: Math.max(
      left.eligibleFiles ?? 0,
      right.eligibleFiles ?? 0,
    ),
    inspectedFiles: Math.max(
      left.inspectedFiles ?? 0,
      right.inspectedFiles ?? 0,
    ),
    inspectedBytes:
      (left.inspectedBytes ?? 0) + (right.inspectedBytes ?? 0),
    unsupportedLanguages: uniqueSorted([
      ...(left.unsupportedLanguages ?? []),
      ...(right.unsupportedLanguages ?? []),
    ]),
    degradedReasons: uniqueSorted([
      ...(left.degradedReasons ?? []),
      ...(right.degradedReasons ?? []),
    ]),
  };
}

async function loadFixtureContexts(
  fixtures: readonly ResearchExperimentFixtureInput[],
  snapshotWorkspace: SubjectSnapshotWorkspace,
): Promise<FixtureContext[]> {
  const ids = new Set<string>();
  const contexts: FixtureContext[] = [];
  for (const [fixtureIndex, fixtureInput] of fixtures.entries()) {
    const { fixture, sourceSnapshot } =
      await loadStableEvaluationFixture(fixtureInput.fixtureRoot);
    if (ids.has(fixture.manifest.id)) {
      throw new Error(
        `Research experiment repeats fixture ID: ${fixture.manifest.id}`,
      );
    }
    ids.add(fixture.manifest.id);
    const opaqueId = sha256(
      `${fixtureIndex}\u0000${sha256(
        prettyCanonicalJson(sourceSnapshot.files),
      )}`,
    ).slice(0, 32);
    const snapshots = await materializeFixtureSnapshots({
      workspace: snapshotWorkspace,
      sourceRoot: fixture.fixtureRoot,
      sourceSnapshot,
      layout: fixture.layout,
      opaqueId,
      limits: FIXTURE_SOURCE_LIMITS,
    });
    const sourceState = sourceStateFromSnapshots(
      fixture,
      sourceSnapshot,
      snapshots.subjectSnapshot,
    );
    contexts.push({
      loaded: {
        ...fixture,
        fixtureRoot: snapshots.evaluatorRoot,
        projectRoot: snapshots.subjectRoot,
      },
      originalRoot: fixture.fixtureRoot,
      subjectRoot: snapshots.subjectRoot,
      sourceState,
      sourceIdentities: sourceSnapshot.identities,
      subjectIdentities: snapshots.subjectSnapshot.identities,
      evaluatorIdentities: snapshots.evaluatorSnapshot.identities,
      directoryName: `${safeSegment(fixture.manifest.id).slice(
        0,
        90,
      )}-${sha256(fixture.manifest.id).slice(0, 16)}`,
    });
  }
  const directoryNames = contexts.map((context) => context.directoryName);
  if (new Set(directoryNames).size !== directoryNames.length) {
    throw new Error(
      "Research fixture IDs collide after safe artifact-path normalization.",
    );
  }
  return contexts.sort((left, right) =>
    left.loaded.manifest.id.localeCompare(right.loaded.manifest.id),
  );
}

async function publishFixtureTruthArtifacts(
  suiteDirectory: string,
  fixtures: readonly FixtureContext[],
): Promise<void> {
  for (const fixture of fixtures) {
    await withStableFixture(
      fixture,
      "canonical truth evidence publication",
      async () => {
        const relativePath = normalizeRelative(
          path.posix.join(
            "truth",
            fixture.directoryName,
            TRUTH_EVIDENCE_ARTIFACT,
          ),
        );
        const absolutePath = path.join(
          path.resolve(suiteDirectory),
          ...relativePath.split("/"),
        );
        const sanitized = redactForLog(
          replaceLocalRoots(
            {
              schemaVersion: "1.0",
              fixtureId: fixture.loaded.manifest.id,
              pairId: fixture.loaded.manifest.pairId,
              variant: fixture.loaded.manifest.variant,
              manifest: fixture.loaded.manifest,
              truth: fixture.loaded.truth,
              sourceState: fixture.sourceState,
            },
            fixtureLocalRoots(fixture),
          ),
        );
        const data = sanitized.value as {
          schemaVersion: "1.0";
          fixtureId: string;
          pairId: string;
          variant: "vulnerable" | "clean";
          manifest: Readonly<Record<string, unknown>>;
          truth: Readonly<Record<string, unknown>>;
          sourceState: SourceStateArtifact;
        };
        const document = {
          schemaVersion: "1.0" as const,
          redactionMarkers: sanitized.markers,
          data: {
            ...data,
            binding: {
              manifestSha256: sha256(canonicalJson(data.manifest)),
              truthSha256: sha256(canonicalJson(data.truth)),
              sourceStateSha256: sha256(
                canonicalJson(data.sourceState),
              ),
              fixtureDigestSha256:
                fixture.sourceState.fixtureDigestSha256,
              projectRoot: fixture.sourceState.project.root,
              projectDigestSha256:
                fixture.sourceState.project.projectDigestSha256,
              evaluatorDigestSha256:
                fixture.sourceState.evaluator.evaluatorDigestSha256,
              layoutBindingSha256:
                fixture.sourceState.layoutBindingSha256,
              subjectDigestSha256:
                fixture.sourceState.subject
                  .subjectDigestSha256,
              subjectFixtureBindingSha256:
                fixture.sourceState.subject
                  .fixtureBindingSha256,
            },
          },
        };
        await writeImmutableJson(absolutePath, document);
        const integrity = await hashStableConfinedFile(
          suiteDirectory,
          relativePath,
        );
        fixture.truthArtifact = {
          fixtureId: fixture.loaded.manifest.id,
          pairId: fixture.loaded.manifest.pairId,
          variant: fixture.loaded.manifest.variant,
          path: relativePath,
          fixtureDigestSha256:
            fixture.sourceState.fixtureDigestSha256,
          projectRoot: fixture.sourceState.project.root,
          projectDigestSha256:
            fixture.sourceState.project.projectDigestSha256,
          evaluatorDigestSha256:
            fixture.sourceState.evaluator.evaluatorDigestSha256,
          layoutBindingSha256:
            fixture.sourceState.layoutBindingSha256,
          absolutePath,
          artifactSha256: integrity.sha256,
        };
      },
    );
  }
}

function evaluationForPublication(
  evaluation: ScoredEvaluationBundle,
  fixtures: readonly FixtureContext[],
): ScoredEvaluationBundle {
  const truthByFixture = new Map(
    fixtures.map((fixture) => [
      fixture.loaded.manifest.id,
      requireTruthArtifact(fixture),
    ]),
  );
  return {
    ...structuredClone(evaluation),
    runs: evaluation.runs.map((run) => ({
      ...structuredClone(run),
      cases: run.cases.map((evaluationCase) => {
        const truthArtifact = truthByFixture.get(
          evaluationCase.fixtureId,
        );
        if (!truthArtifact) {
          throw new Error(
            `Evaluation case has no canonical truth artifact: ${evaluationCase.fixtureId}`,
          );
        }
        return {
          ...structuredClone(evaluationCase),
          fixtureRoot: `fixture://${encodeURIComponent(
            evaluationCase.fixtureId,
          )}`,
          truthArtifact: {
            fixtureId: truthArtifact.fixtureId,
            path: truthArtifact.path,
            sha256: truthArtifact.artifactSha256,
            fixtureDigestSha256:
              truthArtifact.fixtureDigestSha256,
          },
        };
      }),
    })),
  };
}

function requireTruthArtifact(
  fixture: FixtureContext,
): PublishedFixtureTruth {
  if (!fixture.truthArtifact) {
    throw new Error(
      `Fixture truth artifact was not published: ${fixture.loaded.manifest.id}`,
    );
  }
  return fixture.truthArtifact;
}

function sourceStateFromSnapshots(
  fixture: LoadedEvaluationFixture,
  fullSnapshot: StableTreeSnapshot,
  subjectSnapshot: StableTreeSnapshot,
): SourceStateArtifact {
  const files = fullSnapshot.files.map((file) => ({
    path: normalizeRelative(file.path),
    bytes: file.bytes,
    sha256: file.sha256,
  }));
  const subjectFiles = subjectSnapshot.files.map((file) => ({
    path: normalizeRelative(file.path),
    bytes: file.bytes,
    sha256: file.sha256,
  }));
  const fixtureDigestSha256 = sha256(prettyCanonicalJson(files));
  const projectPrefix = `${fixture.manifest.projectRoot}/`;
  const projectFiles = files
    .filter((file) => file.path.startsWith(projectPrefix))
    .map((file) => ({
      ...file,
      path: file.path.slice(projectPrefix.length),
    }))
    .sort((left, right) => left.path.localeCompare(right.path));
  const evaluatorFiles = files
    .filter((file) => !file.path.startsWith(projectPrefix))
    .sort((left, right) => left.path.localeCompare(right.path));
  const expectedEvaluatorFiles = [
    "fixture.json",
    ...fixture.manifest.evaluatorFiles,
  ].sort();
  if (
    prettyCanonicalJson(projectFiles) !==
      prettyCanonicalJson(subjectFiles) ||
    prettyCanonicalJson(
      evaluatorFiles.map((file) => file.path),
    ) !== prettyCanonicalJson(expectedEvaluatorFiles)
  ) {
    throw new Error(
      "Research project provenance does not match the validated structural fixture layout.",
    );
  }
  const projectDigestSha256 = sha256(
    prettyCanonicalJson(projectFiles),
  );
  const evaluatorDigestSha256 = sha256(
    prettyCanonicalJson(evaluatorFiles),
  );
  for (const requiredPath of [
    "fixture.json",
    "truth.json",
    ...fixture.manifest.sourceFiles.map(
      (sourceFile) =>
        `${fixture.manifest.projectRoot}/${sourceFile}`,
    ),
  ]) {
    const normalized = normalizeRelative(requiredPath);
    if (!files.some((file) => file.path === normalized)) {
      throw new Error(
        `Research source provenance is missing a required fixture file: ${normalized}`,
      );
    }
  }
  const layoutBindingSha256 = sha256(
    canonicalJson({
      projectRoot: fixture.manifest.projectRoot,
      fixtureDigestSha256,
      projectDigestSha256,
      evaluatorDigestSha256,
    }),
  );
  return {
    schemaVersion: "2.0",
    fixtureId: fixture.manifest.id,
    pairId: fixture.manifest.pairId,
    variant: fixture.manifest.variant,
    language: fixture.manifest.language,
    files,
    fixtureDigestSha256,
    project: {
      root: fixture.manifest.projectRoot,
      files: projectFiles.map((file) => ({ ...file })),
      projectDigestSha256,
    },
    evaluator: {
      files: evaluatorFiles.map((file) => ({ ...file })),
      evaluatorDigestSha256,
    },
    layoutBindingSha256,
    subject: {
      files: projectFiles.map((file) => ({ ...file })),
      subjectDigestSha256: projectDigestSha256,
      excludedControlFiles: evaluatorFiles.map((file) => file.path),
      fixtureBindingSha256: layoutBindingSha256,
    },
  };
}

async function assertFixtureUnchanged(
  fixture: FixtureContext,
  boundary: string,
): Promise<void> {
  let originalSnapshot: StableTreeSnapshot;
  let subjectSnapshot: StableTreeSnapshot;
  let evaluatorSnapshot: StableTreeSnapshot;
  try {
    [originalSnapshot, subjectSnapshot, evaluatorSnapshot] =
      await Promise.all([
        captureStableTree(
          fixture.originalRoot,
          FIXTURE_SOURCE_LIMITS,
        ),
        captureStableTree(
          fixture.subjectRoot,
          FIXTURE_SOURCE_LIMITS,
        ),
        captureStableTree(
          fixture.loaded.fixtureRoot,
          FIXTURE_SOURCE_LIMITS,
        ),
      ]);
  } catch {
    throw new Error(
      `Research source provenance changed for fixture ${JSON.stringify(
        fixture.loaded.manifest.id,
      )} before ${boundary}: the original, subject, or evaluator tree could not be rehashed safely.`,
    );
  }
  const sourceFilesStable =
    sourceFileDifferences(
      fixture.sourceState.files,
      originalSnapshot.files,
    ).length === 0 &&
    prettyCanonicalJson(originalSnapshot.identities) ===
      prettyCanonicalJson(fixture.sourceIdentities);
  const subjectStable =
    prettyCanonicalJson(subjectSnapshot.files) ===
      prettyCanonicalJson(fixture.sourceState.project.files) &&
    prettyCanonicalJson(subjectSnapshot.identities) ===
      prettyCanonicalJson(fixture.subjectIdentities);
  const evaluatorStable =
    prettyCanonicalJson(evaluatorSnapshot.files) ===
      prettyCanonicalJson(fixture.sourceState.files) &&
    prettyCanonicalJson(evaluatorSnapshot.identities) ===
      prettyCanonicalJson(fixture.evaluatorIdentities);
  const changedPaths = uniqueSorted([
    ...sourceFileDifferences(
      fixture.sourceState.files,
      originalSnapshot.files,
    ),
    ...sourceFileDifferences(
      fixture.sourceState.project.files,
      subjectSnapshot.files,
    ).map((entry) => `subject:${entry}`),
    ...sourceFileDifferences(
      fixture.sourceState.files,
      evaluatorSnapshot.files,
    ).map((entry) => `evaluator:${entry}`),
  ]);
  if (!sourceFilesStable || !subjectStable || !evaluatorStable) {
    throw new Error(
      `Research source provenance changed for fixture ${JSON.stringify(
        fixture.loaded.manifest.id,
      )} before ${boundary}: ${
        changedPaths.length > 0
          ? changedPaths.join(", ")
          : "fixture source identity"
      }.`,
    );
  }
  const current = sourceStateFromSnapshots(
    fixture.loaded,
    originalSnapshot,
    subjectSnapshot,
  );
  if (
    prettyCanonicalJson(current) ===
    prettyCanonicalJson(fixture.sourceState)
  ) {
    return;
  }
  throw new Error(
    `Research source provenance changed for fixture ${JSON.stringify(
      fixture.loaded.manifest.id,
    )} before ${boundary}: ${
      changedPaths.length > 0
        ? changedPaths.join(", ")
        : "fixture source state"
    }.`,
  );
}

async function assertFixturesUnchanged(
  fixtures: readonly FixtureContext[],
  boundary: string,
): Promise<void> {
  for (const fixture of fixtures) {
    await assertFixtureUnchanged(fixture, boundary);
  }
}

async function withStableFixture<T>(
  fixture: FixtureContext,
  boundary: string,
  operation: () => Promise<T>,
): Promise<T> {
  await assertFixtureUnchanged(fixture, `starting ${boundary}`);
  try {
    return await operation();
  } finally {
    await assertFixtureUnchanged(fixture, `completed ${boundary}`);
  }
}

async function withStableFixtures<T>(
  fixtures: readonly FixtureContext[],
  boundary: string,
  operation: () => Promise<T>,
): Promise<T> {
  await assertFixturesUnchanged(fixtures, `starting ${boundary}`);
  try {
    return await operation();
  } finally {
    await assertFixturesUnchanged(fixtures, `completed ${boundary}`);
  }
}

function sourceFileDifferences(
  initial: SourceStateArtifact["files"],
  current: StableTreeSnapshot["files"],
): string[] {
  const initialByPath = new Map(
    initial.map((file) => [file.path, file]),
  );
  const currentByPath = new Map(
    current.map((file) => [file.path, file]),
  );
  return uniqueSorted([
    ...initialByPath.keys(),
    ...currentByPath.keys(),
  ]).filter((relativePath) => {
    const before = initialByPath.get(relativePath);
    const after = currentByPath.get(relativePath);
    return (
      !before ||
      !after ||
      before.bytes !== after.bytes ||
      before.sha256 !== after.sha256
    );
  });
}

async function materializeZeroCostLedger(
  ledger: CostLedger,
): Promise<void> {
  await fs.mkdir(path.dirname(ledger.filePath), { recursive: true });
  try {
    const handle = await fs.open(ledger.filePath, "wx");
    try {
      await handle.sync();
    } finally {
      await handle.close();
    }
  } catch (error) {
    if (!isNodeError(error, "EEXIST")) {
      throw error;
    }
  }
  const snapshot = await ledger.snapshot();
  if (
    snapshot.entries.length !== 0 ||
    snapshot.reservations.length !== 0 ||
    snapshot.committedNanoUsd !== 0 ||
    Object.keys(snapshot.committedByRunModeNanoUsd).length !== 0 ||
    snapshot.killSwitch.tripped
  ) {
    throw new Error(
      "Mock and replay research suites require an empty zero-cost ledger.",
    );
  }
}

async function resolveMockResponder(
  input: ResearchExperimentRunnerInput,
): Promise<
  | ((
      request: ModelRequest,
      context: { provider: string; model: string },
    ) => ModelResponse | Promise<ModelResponse>)
  | undefined
> {
  if (input.execution !== "mock") {
    return undefined;
  }
  const base =
    input.mockResponder ?? createDeterministicResearchMockResponder();
  if (input.recordMockCassettes && !input.replayDirectory) {
    throw new Error(
      "Mock cassette recording requires a replayDirectory.",
    );
  }
  return base;
}

function scopedCassetteMockResponder(
  input: {
    input: ResearchExperimentRunnerInput;
    mockResponder?: NonNullable<
      ResearchExperimentRunnerInput["mockResponder"]
    >;
  },
  scopeId: string,
): NonNullable<ResearchExperimentRunnerInput["mockResponder"]> {
  const base = input.mockResponder;
  if (!base) {
    throw new Error("Scoped mock cassette recording requires a responder.");
  }
  if (!input.input.recordMockCassettes) {
    return base;
  }
  if (!input.input.replayDirectory) {
    throw new Error(
      "Mock cassette recording requires a replayDirectory.",
    );
  }
  const store = new ReplayCassetteStore(
    path.resolve(input.input.replayDirectory),
    { scopeId },
  );
  return async (request, context) => {
    const response = await base(request, context);
    const reference = await store.record({
      provider: context.provider,
      model: context.model,
      request,
      response,
    });
    return attachReplayReference(response, reference);
  };
}

async function validateTraceCassetteReferences(input: {
  trace: ResearchModelCallTrace;
  runtime: ResearchModelRuntime;
  required: boolean;
}): Promise<void> {
  if (!input.required) return;
  if (!input.runtime.replayStore) {
    throw new Error("Cassette-backed execution has no replay store.");
  }
  for (const call of input.trace.calls) {
    if (call.terminalState !== "succeeded") continue;
    if (!call.cassetteReference) {
      throw new Error(
        `Successful model call ${call.ordinal} has no cassette reference.`,
      );
    }
    await input.runtime.replayStore.validateReference(
      call.cassetteReference,
    );
  }
}

async function claimFreshCassetteRecordingDirectory(
  input: ResearchExperimentRunnerInput,
): Promise<void> {
  if (!input.recordMockCassettes && !input.recordLiveCassettes) return;
  if (!input.replayDirectory) {
    throw new Error("Cassette recording requires a replayDirectory.");
  }
  const directory = path.resolve(input.replayDirectory);
  await fs.mkdir(path.dirname(directory), { recursive: true });
  try {
    await fs.mkdir(directory);
  } catch (error) {
    if (
      !(
        error instanceof Error &&
        "code" in error &&
        (error as NodeJS.ErrnoException).code === "EEXIST"
      )
    ) {
      throw error;
    }
  }
  const stat = await fs.lstat(directory);
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new Error(
      "Cassette recording root must be a real directory, not a link.",
    );
  }
  const markerPath = path.join(
    directory,
    ".recording-generation.json",
  );
  let marker;
  try {
    marker = await fs.open(markerPath, "wx");
  } catch (error) {
    if (
      error instanceof Error &&
      "code" in error &&
      (error as NodeJS.ErrnoException).code === "EEXIST"
    ) {
      throw new Error(
        "Cassette recording requires an exclusively claimed fresh replayDirectory; another generation already owns this root.",
      );
    }
    throw error;
  }
  try {
    const entries = await fs.readdir(directory);
    if (
      entries.length !== 1 ||
      entries[0] !== ".recording-generation.json"
    ) {
      throw new Error(
        "Cassette recording requires a fresh empty replayDirectory; refusing to append another recording generation.",
      );
    }
    await marker.writeFile(
      `${prettyCanonicalJson({
        schemaVersion: "1.0",
        suiteIdSha256: sha256(
          `hermsec-cassette-generation\u0000${input.suiteId}`,
        ),
        harnessVersion:
          input.harnessVersion ?? "canonical-seven-mode-v1",
        promptVersion:
          input.promptVersion ?? "bounded-tool-agent-v1",
      })}\n`,
      "utf8",
    );
  } catch (error) {
    await marker.close();
    await fs.rm(markerPath, { force: true });
    throw error;
  }
  await marker.close();
}

function executionPolicy(
  input: ResearchExperimentRunnerInput,
  mode: (typeof PHYSICAL_AGENT_MODES)[number],
): ResearchExecutionPolicy {
  return {
    execution: input.execution,
    scored: true,
    allowSpend: input.execution === "live" && input.allowSpend === true,
    noModelFallback: true,
    exactModelAllowlist: [...RESEARCH_EXACT_MODEL_ALLOWLIST],
    globalBudgetUsd: MAX_RESEARCH_GLOBAL_BUDGET_USD,
    modeBudgetUsd: MAX_RESEARCH_MODE_BUDGET_USD[mode],
  };
}

function providerConfigForRole(role: CanonicalAgentRole): ProviderConfig {
  const model = modelForRole(role);
  return {
    provider: "openrouter",
    model,
    allowRemoteProviders: true,
    timeoutMs: 90_000,
    openRouter: {
      scored: true,
      requireParameters: true,
      allowFallbacks: false,
      dataCollection: "deny",
      captureRouteMetadata: true,
    },
  };
}

function modelForRole(role: CanonicalAgentRole): string {
  if (role === "moa-aggregator") {
    return MINIMAX_AGGREGATOR;
  }
  if (
    role === "identity-and-request-security" ||
    role === "sensitive-data-and-cryptography" ||
    role === "platform-storage-and-deployment"
  ) {
    return MIMO;
  }
  return DEEPSEEK_FLASH;
}

function rolePlanForProfile(
  mode: CanonicalAgentDetectorMode,
  profile: CanonicalAgentDetectorResult["profile"],
): readonly CanonicalAgentRole[] {
  if (mode === "single") {
    return ["single-agent-inspector"];
  }
  if (mode === "moa-high") {
    return ALL_MOA_SPECIALIST_ROLES;
  }
  return selectMoaRoles(profile, "low").roles.map(
    (entry) => entry.role.id,
  );
}

function rolePlanForResult(
  mode: CanonicalAgentDetectorMode,
  result: CanonicalAgentDetectorResult,
): readonly CanonicalAgentRole[] {
  return rolePlanForProfile(mode, result.profile);
}

function bindCanonicalRolePlan(
  current: readonly CanonicalAgentRole[] | undefined,
  next: readonly CanonicalAgentRole[],
): readonly CanonicalAgentRole[] {
  if (
    current &&
    canonicalJson(current) !== canonicalJson(next)
  ) {
    throw new Error(
      "Canonical model resolver observed a changing agent role plan.",
    );
  }
  return current ?? Object.freeze([...next]);
}

async function runtimeCosts(
  runtime: ResearchModelRuntime,
  runId: string,
  mode: string,
): Promise<{ actualSpendUsd: number; committedUsd: number }> {
  const actualSpendUsd = sum(
    runtime.getReconciliations().map((entry) => entry.actualUsd),
  );
  const snapshot = await runtime.ledger.snapshot();
  const committedUsd =
    snapshot.committedByRunMode[`${runId}\u0000${mode}`] ?? 0;
  return { actualSpendUsd, committedUsd };
}

function attributedAgentCost(outcome: PhysicalAgentOutcome): number {
  return Math.max(outcome.actualSpendUsd, outcome.committedUsd);
}

function capabilityForMode(mode: ResearchExperimentMode): CapabilityBudget {
  switch (mode) {
    case "scanner-only":
      return {
        modelClass: "deterministic-scanner",
        maxRoundsPerAgent: 0,
        maxToolCallsPerAgent: 0,
        maxInputTokensPerAgent: 0,
        maxOutputTokensPerAgent: 0,
      };
    case "single-agent":
    case "scanner-single":
      return {
        modelClass: "bounded-tool-agent",
        maxRoundsPerAgent: DEFAULT_SINGLE_TOOL_LIMITS.maxRounds,
        maxToolCallsPerAgent: DEFAULT_SINGLE_TOOL_LIMITS.maxToolCalls,
        maxInputTokensPerAgent: 20_000,
        maxOutputTokensPerAgent: 2_000,
      };
    case "moa-low":
    case "moa-high":
    case "scanner-moa-low":
    case "scanner-moa-high":
      return {
        modelClass: "bounded-tool-agent",
        maxRoundsPerAgent: DEFAULT_SPECIALIST_TOOL_LIMITS.maxRounds,
        maxToolCallsPerAgent: DEFAULT_SPECIALIST_TOOL_LIMITS.maxToolCalls,
        maxInputTokensPerAgent: 12_000,
        maxOutputTokensPerAgent: 2_000,
      };
  }
}

function agentCountForMode(mode: ResearchExperimentMode): number {
  switch (mode) {
    case "scanner-only":
      return 0;
    case "single-agent":
    case "scanner-single":
      return 1;
    case "moa-low":
    case "scanner-moa-low":
      return 3;
    case "moa-high":
    case "scanner-moa-high":
      return 5;
  }
}

function componentsForMode(mode: ResearchExperimentMode): string[] {
  switch (mode) {
    case "scanner-only":
      return ["scanner:path"];
    case "single-agent":
      return ["agent:single-agent-inspector"];
    case "moa-low":
    case "moa-high":
      return [
        `agent:${mode}:specialists`,
        "agent:moa-judge",
        "agent:moa-aggregator",
      ];
    case "scanner-single":
      return ["scanner:path", "agent:single-agent-inspector"];
    case "scanner-moa-low":
    case "scanner-moa-high":
      return [
        "scanner:path",
        `agent:${mode}:specialists`,
        "agent:moa-judge",
        "agent:moa-aggregator",
      ];
  }
}

function detectorModeFor(
  mode: (typeof PHYSICAL_AGENT_MODES)[number],
): CanonicalAgentDetectorMode {
  return mode === "single-agent" ? "single" : mode;
}

function terminalStatus(
  status: ScanTerminalStatus,
): ResearchExperimentCellStatus {
  return status === "unchanged" ? "partial" : status;
}

function agentStatus(
  status: CanonicalAgentDetectorResult["status"],
): ResearchExperimentCellStatus {
  return status === "completed" ? "success" : status;
}

function emptyPhysicalCost(): ResearchExperimentCost {
  return {
    actualPhysicalSpendUsd: 0,
    conservativeCommittedUsd: 0,
    attributedCostUsd: 0,
    physicalModelCalls: 0,
    attributedModelCalls: 0,
    physicalTokens: 0,
    attributedTokens: 0,
  };
}

function totalTokens(usages: readonly ModelUsage[]): number {
  return Math.round(
    sum(
      usages.map(
        (usage) =>
          usage.totalTokens ??
          (usage.promptTokens ?? 0) + (usage.completionTokens ?? 0),
      ),
    ),
  );
}

function usedTraceModels(trace: ResearchModelCallTrace): string[] {
  return uniqueSorted(
    trace.calls
      .map((call) => call.model)
      .filter((model) => model !== "<missing>"),
  );
}

async function writeSafeImmutableJson(
  filePath: string,
  value: unknown,
  roots: readonly string[],
): Promise<void> {
  const rootStripped = replaceLocalRoots(value, roots);
  const redacted = redactForLog(rootStripped);
  await writeImmutableJson(filePath, {
    schemaVersion: "1.0",
    redactionMarkers: redacted.markers,
    data: redacted.value,
  });
}

function replaceLocalRoots(value: unknown, roots: readonly string[]): unknown {
  const normalizedRoots = roots.flatMap((root) => [
    path.resolve(root),
    path.resolve(root).replaceAll("\\", "/"),
  ]);
  const visit = (candidate: unknown): unknown => {
    if (typeof candidate === "string") {
      let output = candidate;
      for (const root of normalizedRoots) {
        output =
          process.platform === "win32"
            ? replaceCaseInsensitive(output, root, "$FIXTURE_ROOT")
            : output.replaceAll(root, "$FIXTURE_ROOT");
      }
      return output;
    }
    if (Array.isArray(candidate)) {
      return candidate.map(visit);
    }
    if (candidate && typeof candidate === "object") {
      return Object.fromEntries(
        Object.entries(candidate).map(([key, child]) => [key, visit(child)]),
      );
    }
    return candidate;
  };
  return visit(value);
}

function replaceCaseInsensitive(
  value: string,
  search: string,
  replacement: string,
): string {
  if (!search) {
    return value;
  }
  let output = value;
  let cursor = 0;
  while (cursor <= output.length - search.length) {
    const index = output
      .toLocaleLowerCase("en-US")
      .indexOf(search.toLocaleLowerCase("en-US"), cursor);
    if (index < 0) {
      break;
    }
    output =
      output.slice(0, index) +
      replacement +
      output.slice(index + search.length);
    cursor = index + replacement.length;
  }
  return output;
}

function validateRunnerInput(input: ResearchExperimentRunnerInput): void {
  if (!input.suiteId.trim()) {
    throw new Error("Research experiment suiteId is required.");
  }
  if (input.fixtures.length === 0) {
    throw new Error("Research experiments require at least one fixture.");
  }
  if (input.execution === "live" && input.allowSpend !== true) {
    throw new Error(
      "Live research experiments require explicit allowSpend=true.",
    );
  }
  if (input.execution !== "live" && input.allowSpend === true) {
    throw new Error("Mock and replay experiments cannot enable spending.");
  }
  if (input.execution === "replay" && !input.replayDirectory) {
    throw new Error("Replay experiments require a replayDirectory.");
  }
  if (input.provider.id !== "openrouter") {
    throw new Error(
      "Scored research experiments require the exact OpenRouter provider adapter.",
    );
  }
  if (input.recordLiveCassettes && !input.replayDirectory) {
    throw new Error(
      "Live cassette recording requires a replayDirectory.",
    );
  }
  if (
    input.normalization &&
    (!Number.isFinite(input.normalization.targetCostUsd) ||
      input.normalization.targetCostUsd < 0 ||
      !Number.isFinite(input.normalization.toleranceUsd) ||
      input.normalization.toleranceUsd < 0)
  ) {
    throw new Error(
      "Cost normalization values must be non-negative finite numbers.",
    );
  }
}

async function assertFreshSuiteDirectory(
  suiteDirectory: string,
): Promise<void> {
  await fs.mkdir(suiteDirectory, { recursive: true });
  const stat = await fs.lstat(suiteDirectory);
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new Error(
      "Research suite directory must be a real directory, not a link.",
    );
  }
  try {
    await fs.access(path.join(suiteDirectory, SUITE_INDEX_FILE));
    throw new Error(
      "Research suite directory already contains an immutable suite index.",
    );
  } catch (error) {
    if (!isNodeError(error, "ENOENT")) {
      throw error;
    }
  }
}

function assertCompleteModeMatrix(
  fixtures: readonly FixtureContext[],
  cells: readonly ResearchExperimentCell[],
): void {
  for (const fixture of fixtures) {
    for (const mode of RESEARCH_EXPERIMENT_MODES) {
      const matches = cells.filter(
        (cell) =>
          cell.fixtureId === fixture.loaded.manifest.id &&
          cell.mode === mode,
      );
      if (matches.length !== 1) {
        throw new Error(
          `Experiment matrix requires exactly one ${fixture.loaded.manifest.id}/${mode} cell; received ${matches.length}.`,
        );
      }
    }
  }
}

function requireFixture(
  fixtures: readonly FixtureContext[],
  fixtureId: string,
): FixtureContext {
  const fixture = fixtures.find(
    (candidate) => candidate.loaded.manifest.id === fixtureId,
  );
  if (!fixture) {
    throw new Error(`Unknown experiment fixture: ${fixtureId}`);
  }
  return fixture;
}

function cellRunId(
  suiteId: string,
  fixtureId: string,
  mode: ResearchExperimentMode,
): string {
  return stableId(
    `${suiteId}\u0000${fixtureId}\u0000${mode}`,
    "experiment-cell",
  );
}

function cellDirectory(
  suiteDirectory: string,
  fixtureDirectory: string,
  mode: ResearchExperimentMode,
): string {
  return path.join(
    path.resolve(suiteDirectory),
    "runs",
    fixtureDirectory,
    safeSegment(mode),
  );
}

function safeSegment(value: string): string {
  const normalized = value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/gu, "-")
    .replace(/^-+|-+$/gu, "");
  if (!normalized) {
    throw new Error("Research artifact path segment is empty.");
  }
  return normalized.slice(0, 120);
}

function normalizeRelative(value: string): string {
  return value.replaceAll("\\", "/");
}

function fixtureLocalRoots(fixture: FixtureContext): string[] {
  return [
    fixture.originalRoot,
    fixture.subjectRoot,
    fixture.loaded.fixtureRoot,
  ];
}

function sourceBytes(fixture: FixtureContext): number {
  const declared = new Set(fixture.loaded.manifest.sourceFiles);
  return sum(
    fixture.sourceState.project.files
      .filter((file) => declared.has(file.path))
      .map((file) => file.bytes),
  );
}

function stableCellOrder(
  cells: readonly ResearchExperimentCell[],
): ResearchExperimentCell[] {
  return [...cells].sort(
    (left, right) =>
      left.fixtureId.localeCompare(right.fixtureId) ||
      RESEARCH_EXPERIMENT_MODES.indexOf(left.mode) -
        RESEARCH_EXPERIMENT_MODES.indexOf(right.mode),
  );
}

function safeError(error: unknown, fallback: string): string {
  return sanitizeErrorMessage(error, fallback);
}

function cloneFinding(finding: Finding): Finding {
  return structuredClone(finding);
}

function scannerEvidence(scan: ScanRun): ResearchScannerEvidence {
  return {
    runId: scan.id,
    ...(scan.terminalStatus
      ? { terminalStatus: scan.terminalStatus }
      : {}),
    scannerStatuses: structuredClone(scan.scannerStatuses),
    ...(scan.git ? { git: structuredClone(scan.git) } : {}),
  };
}

function agentEvidence(
  result: Readonly<CanonicalAgentDetectorResult>,
): ResearchAgentEvidence {
  return structuredClone({
    runId: result.runId,
    mode: result.mode,
    status: result.status,
    candidates: result.candidates,
    traces: result.traces,
    coverage: result.coverage,
    roles: result.roles,
    abstentions: result.abstentions,
    ...(result.judgments ? { judgments: result.judgments } : {}),
    ...(result.groups ? { groups: result.groups } : {}),
  });
}

function uniqueSorted(values: readonly string[]): string[] {
  return [...new Set(values.filter(Boolean))].sort();
}

function sum(values: readonly number[]): number {
  return values.reduce((total, value) => total + value, 0);
}

function isNodeError(
  error: unknown,
  code: string,
): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error && error.code === code;
}

function deepFreeze<T>(value: T): Readonly<T> {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(
      value as Record<string, unknown>,
    )) {
      deepFreeze(child);
    }
  }
  return value;
}
