import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  runCanonicalAgentDetector,
  type CanonicalAgentRole,
} from "../../../src/agent/canonicalHarness.js";
import { createCodeInspectionRuntime } from "../../../src/agent/codeInspection.js";
import { CostLedger } from "../../../src/agent/costTracker.js";
import { createInspectionToolRegistry } from "../../../src/agent/inspectionTools.js";
import { dispatchTool } from "../../../src/agent/toolDispatcher.js";
import type {
  CanonicalAgentDetectorRunner,
  CanonicalScannerRunner,
} from "../../../src/core/canonicalOrchestrator.js";
import type {
  GroundTruthFinding,
  TruthSetV2,
} from "../../../src/eval/schema.js";
import type {
  ModelProviderAdapter,
  ModelRequest,
  ModelResponse,
} from "../../../src/model/provider.js";
import { createDeterministicResearchMockResponder } from "../../../src/research/mockResponder.js";
import {
  OPENROUTER_MODELS_CATALOG_URL,
  sealPricingSnapshot,
} from "../../../src/research/pricing.js";
import {
  RESEARCH_EXACT_MODEL_ALLOWLIST,
  RESEARCH_EXPERIMENT_MODES,
  runResearchExperiment,
} from "../../../src/research/experimentRunner.js";
import {
  createModelCallTraceRecorder,
  validateModelCallTrace,
  type ResearchModelCallTrace,
} from "../../../src/research/modelCallTrace.js";
import {
  fingerprintReplayRequest,
  validateReplayCassette,
} from "../../../src/research/replay.js";
import {
  validateRunArtifacts,
  validateSuiteIndex,
} from "../../../src/research/runManifest.js";
import type { Finding, ScanRun } from "../../../src/shared/types.js";

const vulnerableRoot = path.resolve(
  "tests/fixtures/research/micro-js-vulnerable",
);
const cleanRoot = path.resolve(
  "tests/fixtures/research/micro-js-clean",
);

test("runner executes four physical paths, derives hybrids, scores all modes, and seals artifacts", async () => {
  const root = await fs.mkdtemp(
    path.join(os.tmpdir(), "hermsec-experiment-runner-"),
  );
  const suiteDirectory = path.join(root, "suite");
  let scannerExecutions = 0;
  let agentExecutions = 0;
  let modelCalls = 0;
  const modelsByRole = new Map<string, Set<string>>();
  const expectedRequestFingerprints = new Set<string>();
  const detectorTargets = new Set<string>();
  const scannerRunner: CanonicalScannerRunner = async (options) => {
    scannerExecutions += 1;
    detectorTargets.add(options.target);
    assert.equal(
      [vulnerableRoot, cleanRoot].includes(options.target),
      false,
    );
    await assertSubjectHasNoEvaluationControls(options.target);
    return truthBackedScan(options.target, options.runId);
  };
  const detectorRunner: CanonicalAgentDetectorRunner = async (input) => {
    agentExecutions += 1;
    detectorTargets.add(input.repoRoot);
    await assertSubjectHasNoEvaluationControls(input.repoRoot);
    return runCanonicalAgentDetector(input);
  };
  const deterministic = createDeterministicResearchMockResponder();

  try {
    const result = await runResearchExperiment({
      suiteId: `micro-matrix-${path.basename(root)}`,
      suiteDirectory,
      fixtures: [
        { fixtureRoot: vulnerableRoot },
        { fixtureRoot: cleanRoot },
      ],
      execution: "mock",
      provider: throwingProvider(),
      pricingSnapshot: pricingSnapshot(),
      scannerRunner,
      agentDetectorRunner: detectorRunner,
      mockResponder(request, context) {
        modelCalls += 1;
        expectedRequestFingerprints.add(
          fingerprintReplayRequest({
            provider: context.provider,
            model: context.model,
            request,
          }),
        );
        assert.equal(context.provider, "openrouter");
        assert.ok(
          RESEARCH_EXACT_MODEL_ALLOWLIST.includes(
            context.model as (typeof RESEARCH_EXACT_MODEL_ALLOWLIST)[number],
          ),
        );
        const system =
          request.messages.find((message) => message.role === "system")
            ?.content ?? "";
        const role = promptRole(system);
        const models = modelsByRole.get(role) ?? new Set<string>();
        models.add(context.model);
        modelsByRole.set(role, models);
        return deterministic(request, context);
      },
    });

    assert.equal(scannerExecutions, 2);
    assert.equal(agentExecutions, 6);
    assert.deepEqual(result.physicalExecutions, {
      scanners: 2,
      agents: 6,
      derivedHybrids: 6,
    });
    assert.deepEqual(result.modes, [...RESEARCH_EXPERIMENT_MODES]);
    assert.equal(result.cells.length, 14);
    assert.equal(result.evaluation.runs.length, 7);
    assert.ok(
      result.evaluation.runs.every((run) =>
        run.cases.every((evaluationCase) =>
          evaluationCase.fixtureRoot.startsWith("fixture://"),
        ),
      ),
    );
    assert.deepEqual(
      result.evaluation.runs.map((run) => run.mode).sort(),
      [...RESEARCH_EXPERIMENT_MODES].sort(),
    );

    const physicalAgentCalls = result.cells
      .filter(
        (cell) =>
          cell.physical &&
          cell.mode !== "scanner-only",
      )
      .reduce(
        (total, cell) => total + cell.cost.physicalModelCalls,
        0,
      );
    assert.equal(modelCalls, physicalAgentCalls);
    assert.ok(modelCalls > 0);
    assertExactRoleRouting(modelsByRole);
    assert.ok(
      result.cells
        .filter((cell) => !cell.physical)
        .every(
          (cell) =>
            cell.cost.physicalModelCalls === 0 &&
            cell.cost.actualPhysicalSpendUsd === 0 &&
            cell.cost.attributedModelCalls > 0,
        ),
    );
    assert.equal(result.actualPhysicalSpendUsd, 0);
    assert.equal(result.conservativeCommittedUsd, 0);
    await assertZeroCostLedger(result.artifacts.costLedgerPath);
    assert.ok(
      result.cells.every((cell) => cell.status === "success"),
      result.cells
        .filter((cell) => cell.status !== "success")
        .map(
          (cell) =>
            `${cell.fixtureId}/${cell.mode}: ${cell.status} (${cell.degradationReasons.join("; ")})`,
        )
        .join("\n"),
    );
    assert.ok(
      result.cells.every((cell) =>
        cell.degradationReasons.every(
          (reason) =>
            !/per-round tool-call limit|tool calls? per round/iu.test(
              reason,
            ),
        ),
      ),
    );

    const vulnerableCells = result.cells.filter(
      (cell) => cell.fixtureVariant === "vulnerable",
    );
    const cleanCells = result.cells.filter(
      (cell) => cell.fixtureVariant === "clean",
    );
    assert.equal(vulnerableCells.length, 7);
    assert.equal(cleanCells.length, 7);
    for (const mode of RESEARCH_EXPERIMENT_MODES) {
      const vulnerable = vulnerableCells.find(
        (cell) => cell.mode === mode,
      );
      const clean = cleanCells.find((cell) => cell.mode === mode);
      assert.ok(vulnerable);
      assert.ok(clean);
      assert.notDeepEqual(
        vulnerable.findings.map(findingIdentity),
        clean.findings.map(findingIdentity),
        `${mode} must keep the paired fixtures observably distinct`,
      );
    }

    const suiteValidation = await validateSuiteIndex(suiteDirectory);
    assert.equal(suiteValidation.valid, true, suiteValidation.errors.join("\n"));
    assert.equal(suiteValidation.index?.runs.length, 14);
    assert.equal(suiteValidation.index?.schemaVersion, 3);
    if (suiteValidation.index?.schemaVersion !== 3) {
      assert.fail("Fresh experiment suites must emit suite index v3.");
    }
    assert.equal(suiteValidation.index.fixtureTruth.length, 2);
    assert.ok(
      suiteValidation.index.fixtureTruth.every(
        (binding) =>
          /^[a-f0-9]{64}$/u.test(binding.artifactSha256) &&
          /^[a-f0-9]{64}$/u.test(binding.fixtureDigestSha256) &&
          binding.projectRoot === "project" &&
          /^[a-f0-9]{64}$/u.test(
            binding.projectDigestSha256 ?? "",
          ) &&
          /^[a-f0-9]{64}$/u.test(
            binding.evaluatorDigestSha256 ?? "",
          ) &&
          /^[a-f0-9]{64}$/u.test(
            binding.layoutBindingSha256 ?? "",
          ),
      ),
    );
    const publishedEvaluationRaw = await fs.readFile(
      result.artifacts.evaluationPath,
      "utf8",
    );
    assert.equal(
      publishedEvaluationRaw.includes(vulnerableRoot),
      false,
    );
    assert.equal(publishedEvaluationRaw.includes(cleanRoot), false);
    const publishedEvaluation = JSON.parse(
      publishedEvaluationRaw,
    ) as {
      data?: {
        runs?: Array<{
          cases?: Array<{
            fixtureId?: string;
            fixtureRoot?: string;
            truthArtifact?: {
              fixtureId?: string;
              path?: string;
              sha256?: string;
              fixtureDigestSha256?: string;
            };
          }>;
        }>;
      };
    };
    for (const evaluationCase of
      publishedEvaluation.data?.runs?.flatMap(
        (run) => run.cases ?? [],
      ) ?? []) {
      assert.match(evaluationCase.fixtureRoot ?? "", /^fixture:\/\//u);
      assert.equal(
        evaluationCase.truthArtifact?.fixtureId,
        evaluationCase.fixtureId,
      );
      assert.match(
        evaluationCase.truthArtifact?.path ?? "",
        /^truth\/.+\/truth-evidence\.json$/u,
      );
      assert.match(
        evaluationCase.truthArtifact?.sha256 ?? "",
        /^[a-f0-9]{64}$/u,
      );
    }
    for (const cell of result.cells) {
      const validation = await validateRunArtifacts(
        cell.artifactDirectory,
      );
      assert.equal(
        validation.valid,
        true,
        validation.errors.join("\n"),
      );
      assert.equal(validation.manifest?.mode, cell.mode);
      assert.equal(validation.manifest?.runId, cell.runId);
      assert.equal(validation.manifest?.suite, result.suiteId);
      assert.ok(
        validation.manifest?.artifacts.some(
          (artifact) => artifact.path === "model-calls.json",
        ),
      );
      const sourceState = JSON.parse(
        await fs.readFile(
          path.join(cell.artifactDirectory, "source-state.json"),
          "utf8",
        ),
      ) as {
        data?: {
          files?: Array<{ path?: string; sha256?: string }>;
          project?: {
            root?: string;
            files?: Array<{ path?: string; sha256?: string }>;
            projectDigestSha256?: string;
          };
          evaluator?: {
            files?: Array<{ path?: string; sha256?: string }>;
            evaluatorDigestSha256?: string;
          };
          layoutBindingSha256?: string;
          subject?: {
            files?: Array<{ path?: string; sha256?: string }>;
            subjectDigestSha256?: string;
            excludedControlFiles?: string[];
            fixtureBindingSha256?: string;
          };
        };
      };
      assert.ok(sourceState.data?.files?.length);
      assert.ok(
        sourceState.data?.files?.some(
          (file) => file.path === "project/package.json",
        ),
        "recursive provenance must include readable undeclared fixture files",
      );
      assert.ok(
        sourceState.data?.files?.every(
          (file) =>
            typeof file.path === "string" &&
            !path.isAbsolute(file.path) &&
            /^[a-f0-9]{64}$/u.test(file.sha256 ?? ""),
        ),
      );
      const projectState = sourceState.data?.project;
      assert.equal(projectState?.root, "project");
      assert.ok(projectState?.files?.length);
      assert.ok(
        projectState?.files?.some(
          (file) => file.path === "package.json",
        ),
      );
      assert.ok(
        projectState?.files?.every(
          (file) =>
            /^[a-f0-9]{64}$/u.test(file.sha256 ?? ""),
        ),
      );
      assert.deepEqual(
        sourceState.data?.evaluator?.files?.map(
          (file) => file.path,
        ),
        ["fixture.json", "truth.json"],
      );
      assert.match(
        projectState?.projectDigestSha256 ?? "",
        /^[a-f0-9]{64}$/u,
      );
      assert.match(
        sourceState.data?.evaluator?.evaluatorDigestSha256 ?? "",
        /^[a-f0-9]{64}$/u,
      );
      assert.match(
        sourceState.data?.layoutBindingSha256 ?? "",
        /^[a-f0-9]{64}$/u,
      );
      const subject = sourceState.data?.subject;
      assert.ok(
        subject?.excludedControlFiles?.includes("fixture.json"),
      );
      assert.ok(
        subject?.excludedControlFiles?.includes("truth.json"),
      );
      assert.match(
        subject?.subjectDigestSha256 ?? "",
        /^[a-f0-9]{64}$/u,
      );
      assert.match(
        subject?.fixtureBindingSha256 ?? "",
        /^[a-f0-9]{64}$/u,
      );
      const evidence = JSON.parse(
        await fs.readFile(
          path.join(
            cell.artifactDirectory,
            "detector-evidence.json",
          ),
          "utf8",
        ),
      ) as {
        data?: {
          scannerEvidence?: { scannerStatuses?: unknown[] };
          agentEvidence?: { traces?: unknown[] };
        };
      };
      if (cell.mode === "scanner-only") {
        assert.ok(evidence.data?.scannerEvidence?.scannerStatuses?.length);
      }
      if (cell.physical && cell.mode !== "scanner-only") {
        assert.ok(evidence.data?.agentEvidence?.traces?.length);
      }
      if (!cell.physical) {
        assert.ok(evidence.data?.scannerEvidence);
        assert.ok(evidence.data?.agentEvidence);
      }
      const traceDocument = JSON.parse(
        await fs.readFile(
          path.join(cell.artifactDirectory, "model-calls.json"),
          "utf8",
        ),
      ) as { data?: ResearchModelCallTrace };
      const trace = traceDocument.data;
      assert.ok(trace);
      assert.equal(trace.runId, cell.runId);
      assert.equal(trace.mode, cell.mode);
      assert.equal(trace.producerValidation.valid, true);
      assert.equal(trace.traceCompleteness, "complete");
      assert.equal(
        trace.calls.length,
        cell.cost.physicalModelCalls,
      );
      if (cell.mode === "moa-low") {
        assert.equal(
          trace.rolePlan.requiredSpecialistRoles.length,
          3,
        );
      }
      if (cell.mode === "moa-high") {
        assert.deepEqual(
          trace.rolePlan.requiredSpecialistRoles,
          [
            "injection-and-execution",
            "identity-and-request-security",
            "sensitive-data-and-cryptography",
            "dependencies-and-supply-chain",
            "platform-storage-and-deployment",
          ],
        );
      }
      if (!cell.physical) {
        assert.deepEqual(trace.calls, []);
        assert.deepEqual(trace.derivedFrom, cell.derivedFrom);
      }
      for (const call of trace.calls) {
        assert.equal(call.fingerprintSource, "metered-replay");
        assert.ok(
          expectedRequestFingerprints.has(call.requestFingerprint),
        );
        assert.equal(
          call.model === "minimax/minimax-m3",
          call.role === "moa-aggregator",
        );
      }
    }
    for (const [fixtureId, truthPath] of Object.entries(
      result.artifacts.truthPaths,
    )) {
      const raw = await fs.readFile(truthPath, "utf8");
      assert.equal(raw.includes(path.dirname(truthPath)), false);
      const truthArtifact = JSON.parse(raw) as {
        data?: {
          fixtureId?: string;
          binding?: {
            projectRoot?: string;
            fixtureDigestSha256?: string;
            manifestSha256?: string;
            truthSha256?: string;
            sourceStateSha256?: string;
          };
        };
      };
      assert.equal(truthArtifact.data?.fixtureId, fixtureId);
      assert.equal(
        truthArtifact.data?.binding?.projectRoot,
        "project",
      );
      for (const digest of Object.entries(
        truthArtifact.data?.binding ?? {},
      )
        .filter(([key]) => key !== "projectRoot")
        .map(([, value]) => value)) {
        assert.match(digest ?? "", /^[a-f0-9]{64}$/u);
      }
    }
    for (const detectorTarget of detectorTargets) {
      await assertMissing(detectorTarget);
    }
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("model-call trace rejects zero-call success and invalid Minimax role/order", () => {
  const zeroCall = traceDraft({
    mode: "moa-high",
    calls: [],
    candidateCount: 0,
  });
  assert.ok(
    validateModelCallTrace(zeroCall).includes(
      "successful-agent-run-has-zero-model-calls",
    ),
  );

  const wrongRole = traceDraft({
    mode: "moa-low",
    candidateCount: 1,
    calls: [
      traceCall(1, "injection-and-execution"),
      {
        ...traceCall(2, "moa-judge"),
        model: "minimax/minimax-m3",
        responseModel: "minimax/minimax-m3",
      },
    ],
  });
  const wrongRoleErrors = validateModelCallTrace(wrongRole);
  assert.ok(wrongRoleErrors.includes("model-call-role-model-mismatch"));
  assert.ok(wrongRoleErrors.includes("minimax-aggregator-role-invalid"));

  const multipleAggregators = traceDraft({
    mode: "moa-high",
    candidateCount: 1,
    calls: [
      traceCall(1, "injection-and-execution"),
      traceCall(2, "moa-judge"),
      traceCall(3, "moa-aggregator"),
      traceCall(4, "moa-aggregator"),
    ],
  });
  assert.ok(
    validateModelCallTrace(multipleAggregators).includes(
      "multiple-moa-aggregator-calls",
    ),
  );

  const nonTerminalAggregator = traceDraft({
    mode: "moa-low",
    candidateCount: 1,
    calls: [
      traceCall(1, "injection-and-execution"),
      traceCall(2, "moa-aggregator"),
      traceCall(3, "moa-judge"),
    ],
  });
  assert.ok(
    validateModelCallTrace(nonTerminalAggregator).includes(
      "moa-aggregator-not-terminal",
    ),
  );
});

test("model-call trace rejects a successful pre-metering rejection", () => {
  const invalidTrace = traceDraft({
    mode: "single-agent",
    candidateCount: 0,
    calls: [
      {
        ...traceCall(1, "single-agent-inspector"),
        fingerprintSource: "pre-metering-rejection",
      },
    ],
  });

  assert.ok(
    validateModelCallTrace(invalidTrace).includes(
      "pre-metering-rejection-terminal-invalid",
    ),
  );
});

test("model-call trace enforces exact specialist plans and candidate adjudication", () => {
  const validZeroCandidateHigh = traceDraft({
    mode: "moa-high",
    candidateCount: 0,
    calls: [
      traceCall(1, "injection-and-execution"),
      traceCall(2, "identity-and-request-security"),
      traceCall(3, "sensitive-data-and-cryptography"),
      traceCall(4, "dependencies-and-supply-chain"),
      traceCall(5, "platform-storage-and-deployment"),
    ],
  });
  assert.deepEqual(
    validateModelCallTrace(validZeroCandidateHigh),
    [],
    "zero-candidate MoA must not invent judge or aggregator requirements",
  );

  const underProvisionedLow = traceDraft({
    mode: "moa-low",
    candidateCount: 0,
    calls: [
      traceCall(1, "injection-and-execution"),
      traceCall(2, "identity-and-request-security"),
    ],
  });
  assert.ok(
    validateModelCallTrace(underProvisionedLow).includes(
      "successful-moa-role-plan-under-provisioned",
    ),
  );

  const unplannedSpecialist = traceDraft({
    mode: "moa-low",
    candidateCount: 0,
    calls: [
      traceCall(1, "injection-and-execution"),
      traceCall(2, "identity-and-request-security"),
      traceCall(3, "dependencies-and-supply-chain"),
    ],
  });
  assert.ok(
    validateModelCallTrace(unplannedSpecialist).includes(
      "moa-unplanned-specialist-call",
    ),
  );

  const failedJudge = traceDraft({
    mode: "moa-low",
    candidateCount: 1,
    traceCompleteness: "incomplete",
    calls: [
      traceCall(1, "injection-and-execution"),
      traceCall(2, "identity-and-request-security"),
      traceCall(3, "sensitive-data-and-cryptography"),
      failedTraceCall(4, "moa-judge"),
      traceCall(5, "moa-aggregator"),
    ],
  });
  const failedJudgeErrors = validateModelCallTrace(failedJudge);
  assert.ok(
    failedJudgeErrors.includes(
      "candidate-bearing-moa-judge-incomplete",
    ),
  );
  assert.equal(
    failedJudgeErrors.includes(
      "model-call-trace-completeness-invalid",
    ),
    false,
  );

  const missingAggregator = traceDraft({
    mode: "moa-low",
    candidateCount: 1,
    traceCompleteness: "incomplete",
    calls: [
      traceCall(1, "injection-and-execution"),
      traceCall(2, "identity-and-request-security"),
      traceCall(3, "sensitive-data-and-cryptography"),
      traceCall(4, "moa-judge"),
    ],
  });
  assert.ok(
    validateModelCallTrace(missingAggregator).includes(
      "candidate-bearing-moa-aggregator-incomplete",
    ),
  );
});

test("trusted resolver wrapper blocks Minimax on a non-aggregator role before dispatch", async () => {
  let providerDispatches = 0;
  const baseProvider: ModelProviderAdapter = {
    ...throwingProvider(),
    async complete(request, config) {
      providerDispatches += 1;
      return {
        content: "{}",
        provider: "openrouter",
        model: request.model ?? config?.model ?? "",
      };
    },
  };
  const recorder = createModelCallTraceRecorder({
    runId: "wrong-role-run",
    mode: "moa-low",
    execution: "mock",
    expectedProvider: "openrouter",
    modelForRole: expectedTraceModel,
  });
  const wrapped = recorder.wrapProvider({
    role: "injection-and-execution",
    gapFill: false,
    provider: baseProvider,
    providerConfig: {
      provider: "openrouter",
      model: "deepseek/deepseek-v4-flash",
    },
  });
  await assert.rejects(
    () =>
      wrapped.complete(
        {
          messages: [{ role: "user", content: "bounded test" }],
          model: "minimax/minimax-m3",
        },
        {
          provider: "openrouter",
          model: "minimax/minimax-m3",
        },
      ),
    /exact provider\/model policy/iu,
  );
  assert.equal(providerDispatches, 0);
  const trace = recorder.finalize({
    physical: true,
    detectorStatus: "failed",
    candidateCount: 0,
  });
  assert.equal(trace.calls.length, 1);
  assert.equal(trace.calls[0]?.terminalState, "failed");
  assert.equal(
    trace.calls[0]?.errorCategory,
    "exact-model-policy",
  );
  assert.ok(
    trace.producerValidation.errors.includes(
      "model-call-role-model-mismatch",
    ),
  );
  assert.ok(
    trace.producerValidation.errors.includes(
      "minimax-aggregator-role-invalid",
    ),
  );
});

test("pre-metering rejected request fingerprints are structural, distinct, and content-free", async () => {
  const recorder = createModelCallTraceRecorder({
    runId: "unsafe-request-fingerprints",
    mode: "single-agent",
    execution: "mock",
    expectedProvider: "openrouter",
    modelForRole: expectedTraceModel,
  });
  const wrapped = recorder.wrapProvider({
    role: "single-agent-inspector",
    gapFill: false,
    provider: throwingProvider(),
    providerConfig: {
      provider: "openrouter",
      model: "deepseek/deepseek-v4-flash",
    },
  });
  const secrets = [
    ["sk", "manifest-secret-value-1111111111"].join("-"),
    ["sk", "manifest-secret-value-2222222222"].join("-"),
  ];
  const requests: ModelRequest[] = [
    {
      model: "deepseek/deepseek-v4-flash",
      messages: [
        {
          role: "user",
          content: `Inspect alpha route. apiKey=${secrets[0]}`,
        },
      ],
      tools: [
        {
          type: "function",
          function: {
            name: "read_file",
            description: "Read one bounded file.",
            parameters: {
              type: "object",
              properties: { path: { type: "string" } },
            },
          },
        },
      ],
    },
    {
      model: "deepseek/deepseek-v4-flash",
      messages: [
        {
          role: "user",
          content: `Inspect bravo route. apiKey=${secrets[1]}`,
        },
      ],
      tools: [
        {
          type: "function",
          function: {
            name: "search_code",
            description: "Search bounded source text.",
            parameters: {
              type: "object",
              properties: { query: { type: "string" } },
            },
          },
        },
      ],
    },
  ];
  for (const request of requests) {
    assert.throws(
      () =>
        fingerprintReplayRequest({
          provider: "openrouter",
          model: "deepseek/deepseek-v4-flash",
          request,
        }),
      /secret|sensitive|replay/iu,
    );
    await assert.rejects(
      () => wrapped.complete(request),
      /must not be called|provider/iu,
    );
  }

  const trace = recorder.finalize({
    physical: true,
    detectorStatus: "failed",
    candidateCount: 0,
    requiredSpecialistRoles: ["single-agent-inspector"],
  });
  assert.equal(trace.calls.length, 2);
  assert.ok(
    trace.calls.every(
      (call) =>
        call.fingerprintSource === "pre-metering-rejection",
    ),
  );
  assert.notEqual(
    trace.calls[0]?.requestFingerprint,
    trace.calls[1]?.requestFingerprint,
  );
  const serialized = JSON.stringify(trace);
  for (const forbidden of [
    ...secrets,
    "Inspect alpha route",
    "Inspect bravo route",
    "Read one bounded file",
    "Search bounded source text",
  ]) {
    assert.equal(serialized.includes(forbidden), false);
  }
});

test("producer fails closed when a completed agent bypasses all model calls", async () => {
  const root = await fs.mkdtemp(
    path.join(os.tmpdir(), "hermsec-experiment-zero-call-"),
  );
  const deterministic = createDeterministicResearchMockResponder();
  const detectorRunner: CanonicalAgentDetectorRunner = async (input) => {
    if (input.mode !== "moa-high") {
      return runCanonicalAgentDetector(input);
    }
    const bypassed = await runCanonicalAgentDetector({
      ...input,
      resolveModel: () => undefined,
    });
    return {
      ...bypassed,
      status: "completed",
      limitations: [],
    };
  };
  try {
    const result = await runResearchExperiment({
      suiteId: `zero-call-${path.basename(root)}`,
      suiteDirectory: path.join(root, "suite"),
      fixtures: [{ fixtureRoot: vulnerableRoot }],
      execution: "mock",
      provider: throwingProvider(),
      pricingSnapshot: pricingSnapshot(),
      scannerRunner: async (options) =>
        truthBackedScan(options.target, options.runId),
      agentDetectorRunner: detectorRunner,
      mockResponder: deterministic,
    });
    const invalid = result.cells.find(
      (cell) => cell.mode === "moa-high",
    );
    const hybrid = result.cells.find(
      (cell) => cell.mode === "scanner-moa-high",
    );
    assert.equal(invalid?.status, "failed");
    assert.deepEqual(invalid?.modelCallTrace.calls, []);
    assert.ok(
      invalid?.modelCallTrace.producerValidation.errors.includes(
        "successful-agent-run-has-zero-model-calls",
      ),
    );
    assert.match(
      invalid?.degradationReasons.join(" ") ?? "",
      /successful-agent-run-has-zero-model-calls/u,
    );
    assert.notEqual(hybrid?.status, "success");
    const validation = await validateSuiteIndex(result.suiteDirectory);
    assert.equal(validation.valid, true, validation.errors.join("\n"));
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("failed physical agent cells remain explicit while the hybrid preserves scanner evidence", async () => {
  const root = await fs.mkdtemp(
    path.join(os.tmpdir(), "hermsec-experiment-failure-"),
  );
  const detectorRunner: CanonicalAgentDetectorRunner = async (input) => {
    if (input.mode === "moa-high") {
      throw new Error("deliberate provider failure");
    }
    return runCanonicalAgentDetector(input);
  };

  try {
    const result = await runResearchExperiment({
      suiteId: `explicit-failure-${path.basename(root)}`,
      suiteDirectory: path.join(root, "suite"),
      fixtures: [{ fixtureRoot: vulnerableRoot }],
      execution: "mock",
      provider: throwingProvider(),
      pricingSnapshot: pricingSnapshot(),
      scannerRunner: async (options) =>
        truthBackedScan(options.target, options.runId),
      agentDetectorRunner: detectorRunner,
    });

    const failed = result.cells.find(
      (cell) => cell.mode === "moa-high",
    );
    const hybrid = result.cells.find(
      (cell) => cell.mode === "scanner-moa-high",
    );
    const scanner = result.cells.find(
      (cell) => cell.mode === "scanner-only",
    );
    assert.equal(failed?.status, "failed");
    assert.equal(failed?.findings.length, 0);
    assert.match(
      failed?.degradationReasons.join(" ") ?? "",
      /deliberate provider failure/u,
    );
    assert.equal(hybrid?.status, "partial");
    assert.deepEqual(
      hybrid?.findings.map(findingIdentity),
      scanner?.findings.map(findingIdentity),
    );
    assert.equal(hybrid?.cost.physicalModelCalls, 0);
    assert.equal(failed?.modelCallTrace.producerValidation.valid, true);
    assert.deepEqual(failed?.modelCallTrace.calls, []);
    assert.equal(hybrid?.modelCallTrace.physical, false);
    assert.deepEqual(hybrid?.modelCallTrace.calls, []);
    assert.equal(result.evaluation.runs.length, 7);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("canceled suites retain explicit zero-call traces and sealed failure artifacts", async () => {
  const root = await fs.mkdtemp(
    path.join(os.tmpdir(), "hermsec-experiment-canceled-"),
  );
  const controller = new AbortController();
  controller.abort(new Error("deliberate test cancellation"));
  try {
    const result = await runResearchExperiment({
      suiteId: `canceled-${path.basename(root)}`,
      suiteDirectory: path.join(root, "suite"),
      fixtures: [{ fixtureRoot: vulnerableRoot }],
      execution: "mock",
      provider: throwingProvider(),
      pricingSnapshot: pricingSnapshot(),
      scannerRunner: async (options) =>
        truthBackedScan(options.target, options.runId),
      mockResponder: createDeterministicResearchMockResponder(),
      signal: controller.signal,
    });
    assert.equal(result.cells.length, 7);
    assert.ok(
      result.cells.some(
        (cell) =>
          cell.status === "canceled" ||
          cell.status === "failed" ||
          cell.status === "partial",
      ),
    );
    for (const cell of result.cells) {
      assert.equal(cell.modelCallTrace.calls.length, 0);
      assert.equal(
        cell.modelCallTrace.producerValidation.valid,
        true,
        cell.modelCallTrace.producerValidation.errors.join("\n"),
      );
      const validation = await validateRunArtifacts(
        cell.artifactDirectory,
      );
      assert.equal(
        validation.valid,
        true,
        validation.errors.join("\n"),
      );
    }
    const suiteValidation = await validateSuiteIndex(
      result.suiteDirectory,
    );
    assert.equal(
      suiteValidation.valid,
      true,
      suiteValidation.errors.join("\n"),
    );
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("mock cassettes replay the same seven-mode matrix without provider fallback", async () => {
  const root = await fs.mkdtemp(
    path.join(os.tmpdir(), "hermsec-experiment-replay-"),
  );
  const replayDirectory = path.join(root, "cassettes");
  const fixtures = [
    { fixtureRoot: vulnerableRoot },
    { fixtureRoot: cleanRoot },
  ];
  const scannerRunner: CanonicalScannerRunner = async (options) =>
    truthBackedScan(options.target, options.runId);

  try {
    const recorded = await runResearchExperiment({
      suiteId: `record-${path.basename(root)}`,
      suiteDirectory: path.join(root, "recorded-suite"),
      fixtures,
      execution: "mock",
      provider: throwingProvider(),
      pricingSnapshot: pricingSnapshot(),
      scannerRunner,
      replayDirectory,
      recordMockCassettes: true,
    });
    const replayed = await runResearchExperiment({
      suiteId: `replay-${path.basename(root)}`,
      suiteDirectory: path.join(root, "replayed-suite"),
      fixtures,
      execution: "replay",
      provider: throwingProvider(),
      pricingSnapshot: pricingSnapshot(),
      scannerRunner,
      replayDirectory,
    });

    assert.equal(recorded.cells.length, fixtures.length * RESEARCH_EXPERIMENT_MODES.length);
    assert.equal(replayed.cells.length, recorded.cells.length);
    for (const recordedCell of recorded.cells) {
      const replayedCell = replayed.cells.find(
        (cell) =>
          cell.fixtureId === recordedCell.fixtureId &&
          cell.mode === recordedCell.mode,
      );
      assert.ok(replayedCell);
      assert.deepEqual(
        replayedCell.findings.map(findingIdentity),
        recordedCell.findings.map(findingIdentity),
      );
      assert.equal(replayedCell.status, recordedCell.status);
      assert.deepEqual(
        replayedCell.completeness,
        recordedCell.completeness,
      );
      assert.deepEqual(
        replayedCell.degradationReasons,
        recordedCell.degradationReasons,
      );
      if (
        replayedCell.physical &&
        replayedCell.mode !== "scanner-only"
      ) {
        for (const call of replayedCell.modelCallTrace.calls) {
          if (call.terminalState !== "succeeded") continue;
          assert.ok(call.cassetteReference);
          const cassette = await validateReplayCassette(
            path.join(
              replayDirectory,
              call.cassetteReference.relativePath,
            ),
          );
          assert.equal(
            cassette.requestFingerprint,
            call.requestFingerprint,
          );
          assert.equal(
            cassette.integritySha256,
            call.cassetteReference.integritySha256,
          );
          assert.equal(
            cassette.scopeIdSha256,
            call.cassetteReference.scopeIdSha256,
          );
        }
      }
    }
    assert.equal(replayed.actualPhysicalSpendUsd, 0);
    await assertZeroCostLedger(recorded.artifacts.costLedgerPath);
    await assertZeroCostLedger(replayed.artifacts.costLedgerPath);
    assert.equal(
      (await validateSuiteIndex(replayed.suiteDirectory)).valid,
      true,
    );
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("cassette recording refuses stale generations and replay consumes only the fresh set", async () => {
  const root = await fs.mkdtemp(
    path.join(os.tmpdir(), "hermsec-experiment-generation-"),
  );
  const cassetteA = path.join(root, "cassettes-a");
  const cassetteB = path.join(root, "cassettes-b");
  const fixture = [{ fixtureRoot: vulnerableRoot }];
  const scannerRunner: CanonicalScannerRunner = async (options) =>
    truthBackedScan(options.target, options.runId);
  const responder = (generation: string) => {
    const base = createDeterministicResearchMockResponder();
    return async (
      request: ModelRequest,
      context: { provider: string; model: string },
    ): Promise<ModelResponse> => ({
      ...(await base(request, context)),
      responseId: generation,
    });
  };

  try {
    await runResearchExperiment({
      suiteId: `generation-a-${path.basename(root)}`,
      suiteDirectory: path.join(root, "suite-a"),
      fixtures: fixture,
      execution: "mock",
      provider: throwingProvider(),
      pricingSnapshot: pricingSnapshot(),
      scannerRunner,
      replayDirectory: cassetteA,
      recordMockCassettes: true,
      mockResponder: responder("generation-a"),
    });

    await assert.rejects(
      runResearchExperiment({
        suiteId: `generation-stale-${path.basename(root)}`,
        suiteDirectory: path.join(root, "suite-stale"),
        fixtures: fixture,
        execution: "mock",
        provider: throwingProvider(),
        pricingSnapshot: pricingSnapshot(),
        scannerRunner,
        replayDirectory: cassetteA,
        recordMockCassettes: true,
        mockResponder: responder("generation-b"),
      }),
      /fresh empty replayDirectory|exclusively claimed fresh replayDirectory/iu,
    );

    await runResearchExperiment({
      suiteId: `generation-b-${path.basename(root)}`,
      suiteDirectory: path.join(root, "suite-b"),
      fixtures: fixture,
      execution: "mock",
      provider: throwingProvider(),
      pricingSnapshot: pricingSnapshot(),
      scannerRunner,
      replayDirectory: cassetteB,
      recordMockCassettes: true,
      mockResponder: responder("generation-b"),
    });
    const replayed = await runResearchExperiment({
      suiteId: `generation-replay-${path.basename(root)}`,
      suiteDirectory: path.join(root, "suite-replay"),
      fixtures: fixture,
      execution: "replay",
      provider: throwingProvider(),
      pricingSnapshot: pricingSnapshot(),
      scannerRunner,
      replayDirectory: cassetteB,
    });

    const references = replayed.cells
      .filter(
        (cell) =>
          cell.physical && cell.mode !== "scanner-only",
      )
      .flatMap((cell) =>
        cell.modelCallTrace.calls.flatMap((call) =>
          call.cassetteReference
            ? [call.cassetteReference]
            : [],
        ),
      );
    assert.ok(references.length > 0);
    for (const reference of references) {
      const cassette = await validateReplayCassette(
        path.join(cassetteB, reference.relativePath),
      );
      assert.equal(cassette.response.responseId, "generation-b");
    }
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("parallel cassette recorders cannot share one fresh generation root", async () => {
  const root = await fs.mkdtemp(
    path.join(os.tmpdir(), "hermsec-experiment-exclusive-generation-"),
  );
  const replayDirectory = path.join(root, "cassettes");
  const fixtures = [{ fixtureRoot: vulnerableRoot }];
  const scannerRunner: CanonicalScannerRunner = async (options) =>
    truthBackedScan(options.target, options.runId);
  const run = (suffix: string) =>
    runResearchExperiment({
      suiteId: `exclusive-${suffix}-${path.basename(root)}`,
      suiteDirectory: path.join(root, `suite-${suffix}`),
      fixtures,
      execution: "mock",
      provider: throwingProvider(),
      pricingSnapshot: pricingSnapshot(),
      scannerRunner,
      replayDirectory,
      recordMockCassettes: true,
    });

  try {
    const settled = await Promise.allSettled([run("a"), run("b")]);
    const fulfilled = settled.filter(
      (result) => result.status === "fulfilled",
    );
    const rejected = settled.filter(
      (result): result is PromiseRejectedResult =>
        result.status === "rejected",
    );
    assert.equal(fulfilled.length, 1);
    assert.equal(rejected.length, 1);
    assert.match(
      String(rejected[0]!.reason),
      /exclusively claimed fresh replayDirectory/iu,
    );
    const marker = JSON.parse(
      await fs.readFile(
        path.join(replayDirectory, ".recording-generation.json"),
        "utf8",
      ),
    ) as { schemaVersion?: string };
    assert.equal(marker.schemaVersion, "1.0");
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("replay rejects cassettes recorded for the same fixture id before its source changed", async () => {
  const root = await fs.mkdtemp(
    path.join(os.tmpdir(), "hermsec-experiment-source-scope-"),
  );
  const fixtureRoot = path.join(root, "fixture");
  const replayDirectory = path.join(root, "cassettes");
  const scannerRunner: CanonicalScannerRunner = async (options) =>
    truthBackedScan(options.target, options.runId);

  try {
    await fs.cp(vulnerableRoot, fixtureRoot, { recursive: true });
    const recorded = await runResearchExperiment({
      suiteId: `source-record-${path.basename(root)}`,
      suiteDirectory: path.join(root, "recorded-suite"),
      fixtures: [{ fixtureRoot }],
      execution: "mock",
      provider: throwingProvider(),
      pricingSnapshot: pricingSnapshot(),
      scannerRunner,
      replayDirectory,
      recordMockCassettes: true,
    });
    await fs.writeFile(
      path.join(fixtureRoot, "project", "SOURCE-REVISION.txt"),
      "source revision b\n",
      "utf8",
    );
    const replayed = await runResearchExperiment({
      suiteId: `source-replay-${path.basename(root)}`,
      suiteDirectory: path.join(root, "replayed-suite"),
      fixtures: [{ fixtureRoot }],
      execution: "replay",
      provider: throwingProvider(),
      pricingSnapshot: pricingSnapshot(),
      scannerRunner,
      replayDirectory,
    });

    const recordedSource = JSON.parse(
      await fs.readFile(
        path.join(
          recorded.cells[0]!.artifactDirectory,
          "source-state.json",
        ),
        "utf8",
      ),
    ) as { data: { fixtureDigestSha256: string } };
    const replayedSource = JSON.parse(
      await fs.readFile(
        path.join(
          replayed.cells[0]!.artifactDirectory,
          "source-state.json",
        ),
        "utf8",
      ),
    ) as { data: { fixtureDigestSha256: string } };
    assert.notEqual(
      recordedSource.data.fixtureDigestSha256,
      replayedSource.data.fixtureDigestSha256,
    );

    const physicalAgents = replayed.cells.filter(
      (cell) =>
        cell.physical && cell.mode !== "scanner-only",
    );
    assert.equal(physicalAgents.length, 3);
    assert.ok(
      physicalAgents.every(
        (cell) =>
          cell.status === "failed" &&
          cell.modelCallTrace.calls.some(
            (call) =>
              call.terminalState === "failed" &&
              call.errorCategory === "replay",
          ),
      ),
    );
    assert.ok(
      physicalAgents.every((cell) =>
        cell.modelCallTrace.calls.every(
          (call) => !call.cassetteReference,
        ),
      ),
    );
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("detectors and inspection tools see only the project subject snapshot", async () => {
  const root = await fs.mkdtemp(
    path.join(os.tmpdir(), "hermsec-experiment-subject-"),
  );
  const fixtureRoot = path.join(root, "fixture-copy");
  const suiteDirectory = path.join(root, "suite");
  const manifest = JSON.parse(
    await fs.readFile(
      path.join(vulnerableRoot, "fixture.json"),
      "utf8",
    ),
  ) as {
    pairId: string;
    pairedFixtureId: string;
    supportedVulnerabilityClasses: string[];
    evaluatorFiles: string[];
  };
  const truth = JSON.parse(
    await fs.readFile(
      path.join(vulnerableRoot, "truth.json"),
      "utf8",
    ),
  ) as TruthSetV2;
  const forbiddenContent = [
    "expectedFindingCount",
    "supportedVulnerabilityClasses",
    "pairedFixtureId",
    manifest.pairId,
    manifest.pairedFixtureId,
    "EVALUATOR_ONLY_LABEL",
    "EVALUATOR_ONLY_ORACLE",
    "EVALUATOR_ONLY_EVALUATION",
    ...truth.findings.map((finding) => finding.id),
  ];
  let subjectRoot: string | undefined;

  const inspectSubject = async (target: string): Promise<void> => {
    subjectRoot ??= target;
    assert.equal(target, subjectRoot);
    assert.equal(target.includes(truth.fixtureId), false);
    await assertSubjectHasNoEvaluationControls(target);
    const files = await listFilesRecursively(target);
    assert.ok(files.includes("package.json"));
    assert.ok(files.includes("package-lock.json"));
    assert.ok(files.includes(".eslintrc.json"));
    assert.ok(files.some((file) => file.startsWith("src/")));
    assert.ok(files.includes("project-data/truth.json"));
    assert.equal(files.includes("labels.json"), false);
    assert.equal(files.includes("oracle.json"), false);
    assert.equal(files.includes("evaluation.json"), false);
    const snapshotText = (
      await Promise.all(
        files.map((file) =>
          fs.readFile(
            path.join(target, ...file.split("/")),
            "utf8",
          ),
        ),
      )
    ).join("\n");
    for (const forbidden of forbiddenContent) {
      assert.equal(
        snapshotText.includes(forbidden),
        false,
        `subject snapshot leaked evaluator content: ${forbidden}`,
      );
    }

    const runtime = await createCodeInspectionRuntime(target);
    const registry = createInspectionToolRegistry(runtime);
    const context = {
      workspaceRoot: target,
      offlineMode: true,
      userApproved: false,
    };
    const listed = await dispatchTool(
      registry,
      "list_files",
      { limit: 500 },
      context,
    );
    const listedText = JSON.stringify(listed.output);
    assert.equal(listedText.includes('"labels.json"'), false);
    assert.equal(listedText.includes('"oracle.json"'), false);
    assert.equal(listedText.includes('"evaluation.json"'), false);
    assert.equal(listedText.includes('"fixture.json"'), false);
    assert.equal(listedText.includes("project-data/truth.json"), true);
    for (const query of [
      "expectedFindingCount",
      manifest.pairId,
      truth.findings[0]?.id ?? "missing-truth-id",
    ]) {
      const searched = await dispatchTool(
        registry,
        "search_code",
        { query, limit: 20 },
        context,
      );
      assert.deepEqual(
        (searched.output as { matches?: unknown[] }).matches,
        [],
      );
    }
    await assert.rejects(
      dispatchTool(
        registry,
        "read_file_snippet",
        { path: "truth.json" },
        context,
      ),
      /not in the allowed source set/iu,
    );
    const legitimateTruth = await dispatchTool(
      registry,
      "read_file_snippet",
      { path: "project-data/truth.json" },
      context,
    );
    assert.match(
      JSON.stringify(legitimateTruth.output),
      /LEGITIMATE_PROJECT_DATA/u,
    );
  };

  try {
    await fs.cp(vulnerableRoot, fixtureRoot, { recursive: true });
    await fs.writeFile(
      path.join(fixtureRoot, "labels.json"),
      '{"label":"EVALUATOR_ONLY_LABEL"}\n',
      "utf8",
    );
    await fs.writeFile(
      path.join(fixtureRoot, "oracle.json"),
      '{"oracle":"EVALUATOR_ONLY_ORACLE"}\n',
      "utf8",
    );
    await fs.writeFile(
      path.join(fixtureRoot, "evaluation.json"),
      '{"evaluation":"EVALUATOR_ONLY_EVALUATION"}\n',
      "utf8",
    );
    manifest.evaluatorFiles = [
      "evaluation.json",
      "labels.json",
      "oracle.json",
      "truth.json",
    ];
    await fs.writeFile(
      path.join(fixtureRoot, "fixture.json"),
      `${JSON.stringify(manifest, null, 2)}\n`,
      "utf8",
    );
    await fs.writeFile(
      path.join(fixtureRoot, "project", "package-lock.json"),
      '{"lockfileVersion":3}\n',
      "utf8",
    );
    await fs.writeFile(
      path.join(fixtureRoot, "project", ".eslintrc.json"),
      '{"root":true}\n',
      "utf8",
    );
    await fs.mkdir(
      path.join(fixtureRoot, "project", "project-data"),
      { recursive: true },
    );
    await fs.writeFile(
      path.join(
        fixtureRoot,
        "project",
        "project-data",
        "truth.json",
      ),
      '{"kind":"LEGITIMATE_PROJECT_DATA"}\n',
      "utf8",
    );
    const result = await runResearchExperiment({
      suiteId: `subject-${path.basename(root)}`,
      suiteDirectory,
      fixtures: [{ fixtureRoot }],
      execution: "mock",
      provider: throwingProvider(),
      pricingSnapshot: pricingSnapshot(),
      scannerRunner: async (options) => {
        await inspectSubject(options.target);
        return truthBackedScan(options.target, options.runId);
      },
      agentDetectorRunner: async (input) => {
        await inspectSubject(input.repoRoot);
        return runCanonicalAgentDetector(input);
      },
    });
    const sourceState = JSON.parse(
      await fs.readFile(
        path.join(
          result.cells[0]!.artifactDirectory,
          "source-state.json",
        ),
        "utf8",
      ),
    ) as {
      data?: {
        files?: Array<{ path?: string }>;
        project?: {
          files?: Array<{ path?: string }>;
          projectDigestSha256?: string;
        };
        evaluator?: {
          files?: Array<{ path?: string }>;
          evaluatorDigestSha256?: string;
        };
        layoutBindingSha256?: string;
        subject?: {
          files?: Array<{ path?: string }>;
          excludedControlFiles?: string[];
          subjectDigestSha256?: string;
          fixtureBindingSha256?: string;
        };
      };
    };
    const fullPaths = sourceState.data?.files?.map(
      (file) => file.path,
    );
    const projectPaths = sourceState.data?.project?.files?.map(
      (file) => file.path,
    );
    assert.ok(fullPaths?.includes("labels.json"));
    assert.ok(fullPaths?.includes("oracle.json"));
    assert.ok(fullPaths?.includes("evaluation.json"));
    assert.ok(fullPaths?.includes("project/project-data/truth.json"));
    assert.ok(projectPaths?.includes("package-lock.json"));
    assert.ok(projectPaths?.includes(".eslintrc.json"));
    assert.ok(projectPaths?.includes("project-data/truth.json"));
    assert.deepEqual(
      sourceState.data?.evaluator?.files?.map(
        (file) => file.path,
      ),
      [
        "evaluation.json",
        "fixture.json",
        "labels.json",
        "oracle.json",
        "truth.json",
      ],
    );
    assert.match(
      sourceState.data?.subject?.subjectDigestSha256 ?? "",
      /^[a-f0-9]{64}$/u,
    );
    assert.match(
      sourceState.data?.subject?.fixtureBindingSha256 ?? "",
      /^[a-f0-9]{64}$/u,
    );
    assert.ok(
      result.evaluation.runs.every((run) =>
        run.cases.every(
          (evaluationCase) =>
            evaluationCase.fixtureRoot ===
            `fixture://${encodeURIComponent(truth.fixtureId)}`,
        ),
      ),
    );
    assert.ok(subjectRoot);
    await assertMissing(subjectRoot);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("transient original mutation cannot change detector snapshot input", async () => {
  const root = await fs.mkdtemp(
    path.join(os.tmpdir(), "hermsec-experiment-transient-"),
  );
  const fixtureRoot = path.join(root, "fixture-copy");
  const suiteDirectory = path.join(root, "suite");
  let subjectRoot: string | undefined;
  try {
    await fs.cp(vulnerableRoot, fixtureRoot, { recursive: true });
    const originalPath = path.join(
      fixtureRoot,
      "project",
      "package.json",
    );
    const originalContent = await fs.readFile(originalPath, "utf8");
    await assert.rejects(
      runResearchExperiment({
        suiteId: `transient-${path.basename(root)}`,
        suiteDirectory,
        fixtures: [{ fixtureRoot }],
        execution: "mock",
        provider: throwingProvider(),
        pricingSnapshot: pricingSnapshot(),
        scannerRunner: async (options) => {
          subjectRoot = options.target;
          assert.notEqual(
            path.resolve(options.target),
            path.resolve(fixtureRoot),
          );
          const subjectPackage = path.join(
            options.target,
            "package.json",
          );
          const snapshotBefore = await fs.readFile(
            subjectPackage,
            "utf8",
          );
          await fs.writeFile(
            originalPath,
            `${originalContent}\nTRANSIENT_EVALUATOR_MARKER\n`,
            "utf8",
          );
          assert.match(
            await fs.readFile(originalPath, "utf8"),
            /TRANSIENT_EVALUATOR_MARKER/u,
          );
          await fs.writeFile(originalPath, originalContent, "utf8");
          const snapshotAfter = await fs.readFile(
            subjectPackage,
            "utf8",
          );
          assert.equal(snapshotAfter, snapshotBefore);
          assert.equal(
            snapshotAfter.includes("TRANSIENT_EVALUATOR_MARKER"),
            false,
          );
          return truthBackedScan(options.target, options.runId);
        },
      }),
      /Research source provenance changed.*completed scanner-only physical execution/iu,
    );
    assert.ok(subjectRoot);
    await assertMissing(subjectRoot);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("undeclared fixture mutation fails closed before cell manifests or suite index are sealed", async () => {
  const root = await fs.mkdtemp(
    path.join(os.tmpdir(), "hermsec-experiment-provenance-"),
  );
  const fixtureRoot = path.join(root, "fixture-copy");
  const suiteDirectory = path.join(root, "suite");

  try {
    await fs.cp(vulnerableRoot, fixtureRoot, { recursive: true });
    await assert.rejects(
      runResearchExperiment({
        suiteId: `mutation-${path.basename(root)}`,
        suiteDirectory,
        fixtures: [{ fixtureRoot }],
        execution: "mock",
        provider: throwingProvider(),
        pricingSnapshot: pricingSnapshot(),
        scannerRunner: async (options) => {
          const scan = await truthBackedScan(
            options.target,
            options.runId,
          );
          await fs.appendFile(
            path.join(fixtureRoot, "project", "package.json"),
            "\n",
            "utf8",
          );
          return scan;
        },
      }),
      /Research source provenance changed for fixture "micro-js-vulnerable" before completed scanner-only physical execution: project\/package\.json\./u,
    );
    assert.deepEqual(
      await findFilesNamed(suiteDirectory, "run-manifest.json"),
      [],
    );
    await assert.rejects(
      fs.access(path.join(suiteDirectory, "suite-index.json")),
      (error: unknown) =>
        error instanceof Error &&
        "code" in error &&
        error.code === "ENOENT",
    );
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("same-content fixture path replacement is rejected by identity provenance", async () => {
  const root = await fs.mkdtemp(
    path.join(os.tmpdir(), "hermsec-experiment-identity-"),
  );
  const fixtureRoot = path.join(root, "fixture-copy");
  const suiteDirectory = path.join(root, "suite");
  try {
    await fs.cp(vulnerableRoot, fixtureRoot, { recursive: true });
    await assert.rejects(
      runResearchExperiment({
        suiteId: `identity-${path.basename(root)}`,
        suiteDirectory,
        fixtures: [{ fixtureRoot }],
        execution: "mock",
        provider: throwingProvider(),
        pricingSnapshot: pricingSnapshot(),
        scannerRunner: async (options) => {
          const scan = await truthBackedScan(
            options.target,
            options.runId,
          );
          const target = path.join(
            fixtureRoot,
            "project",
            "src/config.js",
          );
          const replacement = `${target}.replacement`;
          const previous = `${target}.previous`;
          const content = await fs.readFile(target);
          await fs.writeFile(replacement, content);
          await fs.rename(target, previous);
          await fs.rename(replacement, target);
          await fs.rm(previous);
          return scan;
        },
      }),
      /Research source provenance changed.*completed scanner-only physical execution/iu,
    );
    await assert.rejects(
      fs.access(path.join(suiteDirectory, "suite-index.json")),
      (error: unknown) =>
        error instanceof Error &&
        "code" in error &&
        error.code === "ENOENT",
    );
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("fixture hard links are rejected before scanner execution", async () => {
  const root = await fs.mkdtemp(
    path.join(os.tmpdir(), "hermsec-experiment-hardlink-"),
  );
  const fixtureRoot = path.join(root, "fixture-copy");
  const suiteDirectory = path.join(root, "suite");
  let scannerExecutions = 0;
  try {
    await fs.cp(vulnerableRoot, fixtureRoot, { recursive: true });
    await fs.link(
      path.join(fixtureRoot, "project", "src/server.js"),
      path.join(fixtureRoot, "project", "src/server-alias.js"),
    );
    await assert.rejects(
      runResearchExperiment({
        suiteId: `hardlink-${path.basename(root)}`,
        suiteDirectory,
        fixtures: [{ fixtureRoot }],
        execution: "mock",
        provider: throwingProvider(),
        pricingSnapshot: pricingSnapshot(),
        scannerRunner: async (options) => {
          scannerExecutions += 1;
          return truthBackedScan(options.target, options.runId);
        },
      }),
      /regular single-link files/iu,
    );
    assert.equal(scannerExecutions, 0);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

async function truthBackedScan(
  fixtureRoot: string,
  runId?: string,
): Promise<ScanRun> {
  const packageDocument = JSON.parse(
    await fs.readFile(
      path.join(fixtureRoot, "package.json"),
      "utf8",
    ),
  ) as { name?: string };
  const truthRoot = packageDocument.name?.endsWith("-clean")
    ? cleanRoot
    : vulnerableRoot;
  const truth = JSON.parse(
    await fs.readFile(path.join(truthRoot, "truth.json"), "utf8"),
  ) as TruthSetV2;
  const findings = truth.findings.map(findingFromTruth);
  const startedAt = "2026-07-25T00:00:00.000Z";
  const finishedAt = "2026-07-25T00:00:01.000Z";
  return {
    schemaVersion: "1.0",
    id: runId ?? `scanner-${truth.fixtureId}`,
    assistMode: "scanner-only",
    terminalStatus: "success",
    target: path.resolve(fixtureRoot),
    mode: "offline",
    startedAt,
    finishedAt,
    durationMs: 1_000,
    scannerStatuses: [
      {
        id: "truth-backed-scanner",
        label: "Truth-backed test scanner",
        status: "completed",
        message: "Test scanner completed.",
      },
    ],
    findings,
    summary: {
      total: findings.length,
      critical: findings.filter(
        (finding) => finding.severity === "critical",
      ).length,
      high: findings.filter((finding) => finding.severity === "high")
        .length,
      medium: findings.filter(
        (finding) => finding.severity === "medium",
      ).length,
      low: findings.filter((finding) => finding.severity === "low")
        .length,
      info: findings.filter((finding) => finding.severity === "info")
        .length,
    },
  };
}

async function assertSubjectHasNoEvaluationControls(
  subjectRoot: string,
): Promise<void> {
  const files = await listFilesRecursively(subjectRoot);
  assert.ok(files.length > 0);
  assert.equal(files.includes("fixture.json"), false);
  assert.equal(files.includes("truth.json"), false);
  assert.equal(files.includes("labels.json"), false);
  assert.equal(files.includes("oracle.json"), false);
  assert.equal(files.includes("evaluation.json"), false);
}

async function listFilesRecursively(root: string): Promise<string[]> {
  const files: string[] = [];
  const visit = async (
    directory: string,
    relativeDirectory: string,
  ): Promise<void> => {
    const entries = await fs.readdir(directory, {
      withFileTypes: true,
    });
    for (const entry of entries.sort((left, right) =>
      left.name.localeCompare(right.name),
    )) {
      const relativePath = relativeDirectory
        ? `${relativeDirectory}/${entry.name}`
        : entry.name;
      const absolutePath = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        await visit(absolutePath, relativePath);
      } else if (entry.isFile()) {
        files.push(relativePath);
      } else {
        assert.fail(
          `Subject snapshot contains a non-file entry: ${relativePath}`,
        );
      }
    }
  };
  await visit(root, "");
  return files.sort();
}

async function assertMissing(target: string): Promise<void> {
  await assert.rejects(
    fs.access(target),
    (error: unknown) =>
      error instanceof Error &&
      "code" in error &&
      error.code === "ENOENT",
  );
}

function findingFromTruth(truth: GroundTruthFinding): Finding {
  const location = truth.location
    ? {
        file: truth.location.path,
        ...(truth.location.startLine !== undefined
          ? { startLine: truth.location.startLine }
          : {}),
        ...(truth.location.endLine !== undefined
          ? { endLine: truth.location.endLine }
          : {}),
      }
    : undefined;
  return {
    id: `scanner-${truth.id}`,
    fingerprint: `scanner-${truth.id.toLowerCase()}`,
    title: truth.title,
    category: truth.category,
    severity: truth.severity,
    confidence: "confirmed",
    description: truth.evidence?.description ?? truth.title,
    evidence: truth.evidence?.description ?? truth.title,
    remediation: "Apply the fixture remediation.",
    tool: "truth-backed-test-scanner",
    ruleId:
      truth.ruleIds?.[0] ?? `test.${truth.vulnerabilityClass}`,
    cwe: [...truth.cwe],
    ...(location ? { location } : {}),
    ...(truth.evidence?.sourceLocations
      ? {
          sourceLocations: truth.evidence.sourceLocations.map(
            (source) => ({
              file: source.path,
              ...(source.startLine !== undefined
                ? { startLine: source.startLine }
                : {}),
              ...(source.endLine !== undefined
                ? { endLine: source.endLine }
                : {}),
            }),
          ),
        }
      : {}),
  };
}

function pricingSnapshot() {
  return sealPricingSnapshot({
    schemaVersion: 2,
    capturedAt: "2026-07-25T00:00:00.000Z",
    source: OPENROUTER_MODELS_CATALOG_URL,
    prices: RESEARCH_EXACT_MODEL_ALLOWLIST.map((model) => ({
      provider: "openrouter",
      model,
      inputUsdPerMillionTokens: 0.1,
      outputUsdPerMillionTokens: 0.2,
      contextLength: 1_048_576,
      supportedParameters: [
        "max_tokens",
        "tool_choice",
        "tools",
      ],
    })),
  });
}

function throwingProvider(): ModelProviderAdapter {
  const fail = (): never => {
    throw new Error("mock experiment contacted the live provider");
  };
  return {
    id: "openrouter",
    capabilities: {
      tools: true,
      jsonResponse: true,
      externalAbort: true,
      streaming: false,
    },
    async listModels() {
      return fail();
    },
    async healthCheck() {
      return fail();
    },
    async complete(_request: ModelRequest) {
      return fail();
    },
  };
}

function findingIdentity(finding: Finding): string {
  return [
    finding.cwe?.join(",") ?? "",
    finding.location?.file ?? "",
    finding.location?.startLine ?? 0,
  ].join(":");
}

function promptRole(systemPrompt: string): string {
  const system = systemPrompt.toLowerCase();
  const roles = [
    "single bounded investigator",
    "injection and execution specialist",
    "identity and request security specialist",
    "sensitive data and cryptography specialist",
    "dependencies and supply-chain specialist",
    "platform, storage, and deployment specialist",
    "moa evidence judge",
    "moa aggregator",
  ] as const;
  const role = roles.find((candidate) => system.includes(candidate));
  assert.ok(role, `Unrecognized research prompt role: ${systemPrompt}`);
  return {
    "single bounded investigator": "single-agent-inspector",
    "injection and execution specialist": "injection-and-execution",
    "identity and request security specialist":
      "identity-and-request-security",
    "sensitive data and cryptography specialist":
      "sensitive-data-and-cryptography",
    "dependencies and supply-chain specialist":
      "dependencies-and-supply-chain",
    "platform, storage, and deployment specialist":
      "platform-storage-and-deployment",
    "moa evidence judge": "moa-judge",
    "moa aggregator": "moa-aggregator",
  }[role];
}

function assertExactRoleRouting(
  modelsByRole: ReadonlyMap<string, ReadonlySet<string>>,
): void {
  const expected = new Map<string, string>([
    ["single-agent-inspector", "deepseek/deepseek-v4-flash"],
    ["injection-and-execution", "deepseek/deepseek-v4-flash"],
    ["identity-and-request-security", "xiaomi/mimo-v2.5"],
    ["sensitive-data-and-cryptography", "xiaomi/mimo-v2.5"],
    ["dependencies-and-supply-chain", "deepseek/deepseek-v4-flash"],
    ["platform-storage-and-deployment", "xiaomi/mimo-v2.5"],
    ["moa-judge", "deepseek/deepseek-v4-flash"],
    ["moa-aggregator", "minimax/minimax-m3"],
  ]);
  assert.deepEqual(
    [...modelsByRole.keys()].sort(),
    [...expected.keys()].sort(),
  );
  for (const [role, model] of expected) {
    assert.deepEqual(modelsByRole.get(role), new Set([model]), role);
  }
  for (const [role, models] of modelsByRole) {
    assert.equal(
      models.has("minimax/minimax-m3"),
      role === "moa-aggregator",
      `Minimax routing mismatch for ${role}`,
    );
    if (models.has("xiaomi/mimo-v2.5")) {
      assert.ok(
        [
          "identity-and-request-security",
          "sensitive-data-and-cryptography",
          "platform-storage-and-deployment",
        ].includes(role),
        `MiMo must not be routed to ${role}`,
      );
    }
  }
}

async function assertZeroCostLedger(filePath: string): Promise<void> {
  assert.equal((await fs.stat(filePath)).isFile(), true);
  const snapshot = await new CostLedger(filePath).snapshot();
  assert.equal(snapshot.entries.length, 0);
  assert.equal(snapshot.reservations.length, 0);
  assert.equal(snapshot.committedNanoUsd, 0);
  assert.equal(snapshot.committedUsd, 0);
  assert.deepEqual(snapshot.committedByRunMode, {});
  assert.equal(snapshot.killSwitch.tripped, false);
}

async function findFilesNamed(
  root: string,
  fileName: string,
): Promise<string[]> {
  let entries: Awaited<ReturnType<typeof fs.readdir>>;
  try {
    entries = await fs.readdir(root, { withFileTypes: true });
  } catch (error) {
    if (
      error instanceof Error &&
      "code" in error &&
      error.code === "ENOENT"
    ) {
      return [];
    }
    throw error;
  }
  const matches: string[] = [];
  for (const entry of entries) {
    const absolute = path.join(root, entry.name);
    if (entry.isDirectory()) {
      matches.push(...(await findFilesNamed(absolute, fileName)));
    } else if (entry.isFile() && entry.name === fileName) {
      matches.push(absolute);
    }
  }
  return matches.sort();
}

function traceDraft(input: {
  mode: "single-agent" | "moa-low" | "moa-high";
  calls: ResearchModelCallTrace["calls"];
  candidateCount: number;
  traceCompleteness?: ResearchModelCallTrace["traceCompleteness"];
}): Omit<ResearchModelCallTrace, "producerValidation"> {
  return {
    schemaVersion: "1.0",
    runId: `trace-${input.mode}`,
    mode: input.mode,
    execution: "mock",
    cassettePolicy: "none",
    physical: true,
    derivedFrom: [],
    detectorStatus: "completed",
    candidateCount: input.candidateCount,
    aggregationDisposition:
      input.mode.startsWith("moa") && input.candidateCount > 0
        ? "required"
        : input.mode.startsWith("moa")
          ? "not-required-no-candidates"
          : "not-applicable",
    rolePlan: {
      status: "complete",
      requiredSpecialistRoles:
        input.mode === "single-agent"
          ? ["single-agent-inspector"]
          : input.mode === "moa-high"
            ? [
                "injection-and-execution",
                "identity-and-request-security",
                "sensitive-data-and-cryptography",
                "dependencies-and-supply-chain",
                "platform-storage-and-deployment",
              ]
            : [
                "injection-and-execution",
                "identity-and-request-security",
                "sensitive-data-and-cryptography",
              ],
    },
    traceCompleteness: input.traceCompleteness ?? "complete",
    calls: input.calls,
  };
}

function traceCall(
  ordinal: number,
  role: CanonicalAgentRole,
): ResearchModelCallTrace["calls"][number] {
  const model = expectedTraceModel(role);
  return {
    ordinal,
    role,
    gapFill: false,
    provider: "openrouter",
    model,
    requestFingerprint: ordinal.toString(16).padStart(64, "0"),
    fingerprintSource: "metered-replay",
    terminalState: "succeeded",
    responseProvider: "openrouter",
    responseModel: model,
  };
}

function failedTraceCall(
  ordinal: number,
  role: CanonicalAgentRole,
): ResearchModelCallTrace["calls"][number] {
  const {
    responseProvider: _responseProvider,
    responseModel: _responseModel,
    ...call
  } = traceCall(ordinal, role);
  return {
    ...call,
    terminalState: "failed",
    errorCategory: "provider",
  };
}

function expectedTraceModel(role: CanonicalAgentRole): string {
  return role === "moa-aggregator"
    ? "minimax/minimax-m3"
    : role === "identity-and-request-security" ||
        role === "sensitive-data-and-cryptography" ||
        role === "platform-storage-and-deployment"
      ? "xiaomi/mimo-v2.5"
      : "deepseek/deepseek-v4-flash";
}
