import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test, { type TestContext } from "node:test";
import { CostLedger } from "../../../src/agent/costTracker.js";
import {
  createRunManifest,
  createSuiteIndex,
} from "../../../src/research/runManifest.js";
import {
  validateModelCallTrace,
  type ResearchModelCallTrace,
} from "../../../src/research/modelCallTrace.js";
import {
  canonicalJson,
  prettyCanonicalJson,
  sha256,
} from "../../../src/research/integrity.js";
import { projectFindings } from "../../../src/eval/findingProjection.js";
import { matchFindings } from "../../../src/eval/matcher.js";
import {
  computeSuiteMetrics,
} from "../../../src/eval/metrics.js";
import {
  applyGroupedF1,
  computeGroupedMetricSummary,
  computeVulnerabilityClassMetrics,
} from "../../../src/eval/categoryScoring.js";
import type { Finding } from "../../../src/shared/types.js";
import type { GroundTruthFinding } from "../../../src/eval/schema.js";

const MODES = [
  "scanner-only",
  "single-agent",
  "moa-low",
  "moa-high",
  "scanner-single",
  "scanner-moa-low",
  "scanner-moa-high",
] as const;

type Mode = (typeof MODES)[number];
type PhysicalAgentMode = "single-agent" | "moa-low" | "moa-high";
type CellStatus =
  | "success"
  | "partial"
  | "degraded"
  | "canceled"
  | "failed";

const OUTPUT_FILES = [
  "completeness.csv",
  "cost-table.tex",
  "cost.csv",
  "integrity-receipt.json",
  "metrics-table.tex",
  "metrics.csv",
  "metrics.md",
  "summary.json",
] as const;

const DEEPSEEK_FLASH = "deepseek/deepseek-v4-flash";
const MIMO = "xiaomi/mimo-v2.5";
const MINIMAX_AGGREGATOR = "minimax/minimax-m3";
const GLOBAL_BUDGET_USD = 3.25;
const MODE_BUDGET_USD: Readonly<Record<Mode, number>> = {
  "scanner-only": 0,
  "single-agent": 0.015,
  "moa-low": 0.06,
  "moa-high": 0.12,
  "scanner-single": 0.015,
  "scanner-moa-low": 0.06,
  "scanner-moa-high": 0.12,
};
type ModelRole =
  | "single-agent-inspector"
  | "injection-and-execution"
  | "identity-and-request-security"
  | "sensitive-data-and-cryptography"
  | "dependencies-and-supply-chain"
  | "platform-storage-and-deployment"
  | "moa-judge"
  | "moa-aggregator";
type LiveCallStatus = "settled" | "failed" | "unknown";

type LiveCall = {
  role: ModelRole;
  model: string;
  costNanoUsd: number;
  tokens: number;
  status?: LiveCallStatus;
};

type SyntheticMatchResult = ReturnType<typeof authoritativeMatchResult>;
type SyntheticMetricBundle = ReturnType<typeof authoritativeMetrics>;
type SyntheticEvaluationCase = {
  truth: ReturnType<typeof authoritativeTruthSet>;
  matchResult: SyntheticMatchResult;
  metrics: SyntheticMetricBundle["metrics"];
  metricsByClass: SyntheticMetricBundle["metricsByClass"];
  classSummary: SyntheticMetricBundle["classSummary"];
};
type SyntheticEvaluationRun = {
  cases: SyntheticEvaluationCase[];
  matchResults: SyntheticMatchResult[];
  metrics: SyntheticMetricBundle["metrics"];
  metricsByClass: SyntheticMetricBundle["metricsByClass"];
  classSummary: SyntheticMetricBundle["classSummary"];
};
type SyntheticEvaluationDocument = {
  data: { runs: SyntheticEvaluationRun[] };
  [key: string]: unknown;
};

const DEFAULT_LIVE_CALLS: Readonly<
  Record<PhysicalAgentMode, readonly LiveCall[]>
> = {
  "single-agent": [
    {
      role: "single-agent-inspector",
      model: DEEPSEEK_FLASH,
      costNanoUsd: 10_000_000,
      tokens: 100,
    },
  ],
  "moa-low": [
    {
      role: "injection-and-execution",
      model: DEEPSEEK_FLASH,
      costNanoUsd: 12_000_000,
      tokens: 120,
    },
    {
      role: "identity-and-request-security",
      model: MIMO,
      costNanoUsd: 8_000_000,
      tokens: 80,
    },
    {
      role: "sensitive-data-and-cryptography",
      model: MIMO,
      costNanoUsd: 8_000_000,
      tokens: 80,
    },
    {
      role: "moa-judge",
      model: DEEPSEEK_FLASH,
      costNanoUsd: 5_000_000,
      tokens: 50,
    },
    {
      role: "moa-aggregator",
      model: MINIMAX_AGGREGATOR,
      costNanoUsd: 8_000_000,
      tokens: 80,
    },
  ],
  "moa-high": [
    {
      role: "injection-and-execution",
      model: DEEPSEEK_FLASH,
      costNanoUsd: 10_000_000,
      tokens: 100,
    },
    {
      role: "identity-and-request-security",
      model: MIMO,
      costNanoUsd: 10_000_000,
      tokens: 100,
    },
    {
      role: "sensitive-data-and-cryptography",
      model: MIMO,
      costNanoUsd: 10_000_000,
      tokens: 100,
    },
    {
      role: "dependencies-and-supply-chain",
      model: DEEPSEEK_FLASH,
      costNanoUsd: 10_000_000,
      tokens: 100,
    },
    {
      role: "platform-storage-and-deployment",
      model: MIMO,
      costNanoUsd: 10_000_000,
      tokens: 100,
    },
    {
      role: "moa-judge",
      model: DEEPSEEK_FLASH,
      costNanoUsd: 5_000_000,
      tokens: 50,
    },
    {
      role: "moa-aggregator",
      model: MINIMAX_AGGREGATOR,
      costNanoUsd: 12_000_000,
      tokens: 120,
    },
  ],
};

test("writes stable integrity-bound summaries without paths or secrets", async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-summary-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const suite = path.join(root, "suite");
  const firstOutput = path.join(root, "summary-a");
  const secondOutput = path.join(root, "summary-b");
  await writeSyntheticSuite(suite, root, {
    statusByMode: { "moa-high": "degraded" },
  });

  const first = await runSummary(suite, firstOutput);
  const second = await runSummary(suite, secondOutput);
  assert.equal(first.code, 0, first.stderr);
  assert.equal(second.code, 0, second.stderr);
  assert.deepEqual(
    (await fs.readdir(firstOutput)).sort(),
    [...OUTPUT_FILES],
  );
  assert.deepEqual(
    (await fs.readdir(secondOutput)).sort(),
    [...OUTPUT_FILES],
  );

  let allOutput = "";
  for (const fileName of OUTPUT_FILES) {
    const firstContent = await fs.readFile(
      path.join(firstOutput, fileName),
      "utf8",
    );
    const secondContent = await fs.readFile(
      path.join(secondOutput, fileName),
      "utf8",
    );
    assert.equal(secondContent, firstContent, `${fileName} changed across runs`);
    allOutput += firstContent;
  }
  assert.equal(allOutput.includes(root), false);
  assert.equal(allOutput.includes("sk-or-v1-not-for-output"), false);
  assert.match(
    allOutput,
    /single-agent,class,cross-site-scripting,1,1,1,1,0,0,,,/,
  );
  assert.match(
    allOutput,
    /single-agent,class,sql-injection,1,0\.5,0\.666666666667,1,0,1,,,/,
  );
  assert.match(allOutput, /CAVEAT degraded:1; completeness:degraded/);
  assert.match(
    await fs.readFile(path.join(firstOutput, "metrics.md"), "utf8"),
    /Metrics remain visible for incomplete runs/u,
  );

  const summary = JSON.parse(
    await fs.readFile(path.join(firstOutput, "summary.json"), "utf8"),
  ) as {
    suiteId: string;
    modeOrder: string[];
    fixtureCount: number;
    totals: {
      actualPhysicalSpendUsd: number;
      attributedCostUsd: number;
      degradedCaseCount: number;
      degradationReasonCount: number;
    };
  };
  assert.equal(summary.suiteId, "synthetic-seven-mode");
  assert.deepEqual(summary.modeOrder, MODES);
  assert.equal(summary.fixtureCount, 1);
  assert.equal(summary.totals.actualPhysicalSpendUsd, 0);
  assert.equal(summary.totals.attributedCostUsd, 0);
  assert.equal(summary.totals.degradedCaseCount, 1);
  assert.equal(summary.totals.degradationReasonCount, 1);
  const receipt = await verifyIntegrityReceipt(firstOutput, suite);
  assert.equal(receipt.upstream.suiteIndex.path, "suite-index.json");
  assert.equal(receipt.upstream.suiteArtifacts.length, 5);
  assert.equal(receipt.upstream.runManifests.length, 7);
  assert.equal(receipt.upstream.sourceTruth.length, 1);
  assert.equal(
    receipt.downstreamEvidence.manifestRate.value,
    1,
  );
  assert.equal(
    receipt.downstreamEvidence.runtime.status,
    "available",
  );
  assert.equal(
    receipt.downstreamEvidence.replayAgreement.status,
    "unavailable",
  );
  assert.equal(
    receipt.derivationBindingSha256,
    sha256(
      canonicalJson({
        generatorSha256: receipt.generator.sha256,
        suiteIndexSha256: receipt.upstream.suiteIndex.sha256,
        upstreamBindingSha256: receipt.upstreamBindingSha256,
        outputSetSha256: receipt.outputSetSha256,
      }),
    ),
  );
  await fs.appendFile(path.join(secondOutput, "summary.json"), " ");
  await assert.rejects(
    verifyIntegrityReceipt(secondOutput, suite),
    /output (?:byte|digest) mismatch/u,
  );

  const before = await fs.readFile(
    path.join(firstOutput, "summary.json"),
    "utf8",
  );
  const overwrite = await runSummary(suite, firstOutput);
  assert.equal(overwrite.code, 1);
  assert.match(overwrite.stderr, /already exists/u);
  assert.equal(
    await fs.readFile(path.join(firstOutput, "summary.json"), "utf8"),
    before,
  );
});

test("receipt verification detects upstream suite artifact mutation", async (t) => {
  const root = await temporaryRoot(t, "hermsec-summary-receipt-upstream-");
  const suite = path.join(root, "suite");
  const output = path.join(root, "summary");
  await writeSyntheticSuite(suite, root);
  const result = await runSummary(suite, output);
  assert.equal(result.code, 0, result.stderr);
  await verifyIntegrityReceipt(output, suite);
  await fs.appendFile(path.join(suite, "evaluation.json"), " ");
  await assert.rejects(
    verifyIntegrityReceipt(output, suite),
    /upstream artifact byte mismatch: evaluation\.json/u,
  );
});

test("rejects a tampered raw artifact bound by the suite index", async (t) => {
  const root = await temporaryRoot(t, "hermsec-summary-tamper-");
  const suite = path.join(root, "suite");
  const output = path.join(root, "summary");
  await writeSyntheticSuite(suite, root);
  await fs.appendFile(
    path.join(
      suite,
      "runs",
      "fixture-vulnerable",
      "single-agent",
      "result.json",
    ),
    " ",
  );

  const result = await runSummary(suite, output);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /result\.json (?:byte count|artifact hash)/u);
  await assert.rejects(fs.access(output));
});

test("accepts a live suite whose physical usage reconciles to the ledger", async (t) => {
  const root = await temporaryRoot(t, "hermsec-summary-live-");
  const suite = path.join(root, "suite");
  const output = path.join(root, "summary");
  await writeSyntheticSuite(suite, root, { execution: "live" });

  const result = await runSummary(suite, output);
  assert.equal(result.code, 0, result.stderr);
  const summary = JSON.parse(
    await fs.readFile(path.join(output, "summary.json"), "utf8"),
  ) as {
    totals: {
      actualPhysicalSpendUsd: number;
      conservativeCommittedUsd: number;
      physicalModelCalls: number;
      physicalTokens: number;
    };
  };
  assert.ok(
    Math.abs(summary.totals.actualPhysicalSpendUsd - 0.118) < 1e-12,
  );
  assert.ok(
    Math.abs(summary.totals.conservativeCommittedUsd - 0.118) < 1e-12,
  );
  assert.equal(summary.totals.physicalModelCalls, 13);
  assert.equal(summary.totals.physicalTokens, 1_180);
});

test("rejects live physical cost claims that disagree with the ledger", async (t) => {
  const root = await temporaryRoot(t, "hermsec-summary-ledger-");
  const suite = path.join(root, "suite");
  const output = path.join(root, "summary");
  await writeSyntheticSuite(suite, root, {
    execution: "live",
    claimedCostDeltaMode: "single-agent",
  });

  const result = await runSummary(suite, output);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /ledger physical spend/u);
  await assert.rejects(fs.access(output));
});

test("rejects precision recall or F1 arithmetic mismatches", async (t) => {
  const root = await temporaryRoot(t, "hermsec-summary-arithmetic-");
  const suite = path.join(root, "suite");
  const output = path.join(root, "summary");
  await writeSyntheticSuite(suite, root);
  const evaluationPath = path.join(suite, "evaluation.json");
  const evaluation = JSON.parse(
    await fs.readFile(evaluationPath, "utf8"),
  ) as { data: { runs: Array<{ metrics: { f1: number } }> } };
  evaluation.data.runs[0]!.metrics.f1 = 0.99;
  await fs.writeFile(
    evaluationPath,
    `${JSON.stringify(evaluation, null, 2)}\n`,
    "utf8",
  );
  await rehashSuiteArtifact(suite, "evaluation.json");

  const result = await runSummary(suite, output);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /metrics F1/u);
  await assert.rejects(fs.access(output));
});

test("rejects coherent aggregate metric tampering against per-case matches", async (t) => {
  const root = await temporaryRoot(t, "hermsec-summary-coherent-metric-");
  const suite = path.join(root, "suite");
  const output = path.join(root, "summary");
  await writeSyntheticSuite(suite, root);
  const evaluationPath = path.join(suite, "evaluation.json");
  const evaluation = JSON.parse(
    await fs.readFile(evaluationPath, "utf8"),
  ) as {
    data: {
      runs: Array<{
        metrics: Record<string, number>;
        cases: Array<{ metrics: Record<string, number> }>;
      }>;
    };
  };
  const fabricated = {
    totalExpected: 3,
    totalActual: 3,
    precision: 1,
    recall: 1,
    f1: 1,
    truePositive: 3,
    falsePositive: 0,
    falseNegative: 0,
    macroF1: 1,
    weightedF1: 1,
  };
  Object.assign(evaluation.data.runs[0]!.metrics, fabricated);
  Object.assign(evaluation.data.runs[0]!.cases[0]!.metrics, fabricated);
  await fs.writeFile(
    evaluationPath,
    `${JSON.stringify(evaluation, null, 2)}\n`,
    "utf8",
  );
  await rehashSuiteArtifact(suite, "evaluation.json");

  const result = await runSummary(suite, output);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /metrics truePositive/u);
  await assert.rejects(fs.access(output));
});

test("rejects rehashed evaluation truth that diverges from canonical v3 evidence", async (t) => {
  const root = await temporaryRoot(t, "hermsec-summary-truth-tamper-");
  const suite = path.join(root, "suite");
  const output = path.join(root, "summary");
  await writeSyntheticSuite(suite, root);
  await mutateEvaluation(suite, (evaluation) => {
    evaluation.runs[0]!.cases[0]!.truth.findings[0]!.title =
      "Rewritten truth title";
  });

  const result = await runSummary(suite, output);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /evaluation\/canonical truth binding/u);
  await assert.rejects(fs.access(output));
});

test("accepts declared evaluator controls and legitimate project truth.json names", async (t) => {
  const root = await temporaryRoot(t, "hermsec-summary-structural-valid-");
  const suite = path.join(root, "suite");
  const output = path.join(root, "summary");
  await writeSyntheticSuite(suite, root, {
    evaluatorControlFiles: [
      "evaluation.json",
      "labels.json",
      "oracle.json",
    ],
  });
  const result = await runSummary(suite, output);
  assert.equal(result.code, 0, result.stderr);
  const sourceIndexPath = path.join(suite, "source-index.json");
  const sourceIndex = JSON.parse(
    await fs.readFile(sourceIndexPath, "utf8"),
  ) as {
    data: {
      fixtures: Array<{
        project: {
          files: Array<{ path: string }>;
        };
        evaluator: {
          files: Array<{ path: string }>;
        };
        subject: {
          files: Array<{ path: string }>;
        };
      }>;
    };
  };
  const fixture = sourceIndex.data.fixtures[0]!;
  assert.equal(
    fixture.project.files.some(
      (entry) => entry.path === "project-data/truth.json",
    ),
    true,
  );
  assert.equal(
    fixture.subject.files.some(
      (entry) => entry.path === "project-data/truth.json",
    ),
    true,
  );
  assert.deepEqual(
    fixture.evaluator.files.map((entry) => entry.path),
    [
      "evaluation.json",
      "fixture.json",
      "labels.json",
      "oracle.json",
      "truth.json",
    ],
  );
});

test("rejects coherently rehashed unclassified evaluator-root controls", async (t) => {
  const root = await temporaryRoot(t, "hermsec-summary-root-controls-");
  for (const controlPath of [
    "labels.json",
    "oracle.json",
    "evaluation.json",
  ]) {
    await t.test(controlPath, async () => {
      const suite = path.join(root, `suite-${controlPath}`);
      const output = path.join(root, `summary-${controlPath}`);
      await writeSyntheticSuite(suite, root);
      await coherentlyRewriteStructuralFixture(
        suite,
        (files) => files.push(syntheticFileRecord(controlPath)),
      );

      const result = await runSummary(suite, output);
      assert.equal(result.code, 1);
      assert.match(
        result.stderr,
        /manifest-declared evaluator inventory/u,
      );
      await assert.rejects(fs.access(output));
    });
  }
});

test("rejects evaluator inventory injected into the project compatibility alias", async (t) => {
  const root = await temporaryRoot(t, "hermsec-summary-subject-alias-");
  const suite = path.join(root, "suite");
  const output = path.join(root, "summary");
  await writeSyntheticSuite(suite, root);
  const sourceIndexPath = path.join(suite, "source-index.json");
  const sourceIndex = JSON.parse(
    await fs.readFile(sourceIndexPath, "utf8"),
  ) as {
    data: {
      fixtures: Array<{
        subject: {
          files: Array<{ path: string; bytes: number; sha256: string }>;
          subjectDigestSha256: string;
        };
        evaluator: {
          files: Array<{ path: string; bytes: number; sha256: string }>;
        };
      }>;
    };
  };
  const fixture = sourceIndex.data.fixtures[0]!;
  const truthFile = fixture.evaluator.files.find(
    (entry) => entry.path === "truth.json",
  );
  assert.ok(truthFile);
  fixture.subject.files.push(structuredClone(truthFile));
  fixture.subject.files.sort((left, right) =>
    left.path.localeCompare(right.path),
  );
  fixture.subject.subjectDigestSha256 = sha256(
    prettyCanonicalJson(fixture.subject.files),
  );
  await fs.writeFile(
    sourceIndexPath,
    `${JSON.stringify(sourceIndex, null, 2)}\n`,
    "utf8",
  );
  await rehashSuiteArtifact(suite, "source-index.json");

  const result = await runSummary(suite, output);
  assert.equal(result.code, 1);
  assert.match(
    result.stderr,
    /project\/subject compatibility inventory/u,
  );
  await assert.rejects(fs.access(output));
});

test("rejects coherently rehashed misplaced and aliased structural paths", async (t) => {
  const root = await temporaryRoot(t, "hermsec-summary-path-aliases-");
  const cases = [
    {
      name: "case-folded-project-alias",
      path: "Project/src/index.js",
      expected: /case-folded path aliases/u,
    },
    {
      name: "dot-segment-project-alias",
      path: "project/src/../oracle.json",
      expected: /normalized relative path/u,
    },
    {
      name: "nested-evaluator-path",
      path: "evaluation/oracle.json",
      expected: /unclassified or misplaced path/u,
    },
    {
      name: "project-root-case-alias",
      path: "Project",
      expected: /colliding with.*project\/ subtree/u,
    },
    {
      name: "exact-parent-segment",
      path: "..",
      expected: /normalized relative path/u,
    },
    {
      name: "trailing-slash-project-record",
      path: "project/injected/",
      expected: /normalized relative path/u,
    },
    {
      name: "nul-byte-project-record",
      path: "project/injected\0.js",
      expected: /normalized relative path/u,
    },
  ];
  for (const candidate of cases) {
    await t.test(candidate.name, async () => {
      const suite = path.join(root, `suite-${candidate.name}`);
      const output = path.join(root, `summary-${candidate.name}`);
      await writeSyntheticSuite(suite, root);
      await coherentlyRewriteStructuralFixture(
        suite,
        (files) => files.push(syntheticFileRecord(candidate.path)),
      );

      const result = await runSummary(suite, output);
      assert.equal(result.code, 1);
      assert.match(result.stderr, candidate.expected);
      await assert.rejects(fs.access(output));
    });
  }
});

test("rejects legacy source-state v1 with actionable regeneration guidance", async (t) => {
  const root = await temporaryRoot(t, "hermsec-summary-source-v1-");
  const suite = path.join(root, "suite");
  const output = path.join(root, "summary");
  await writeSyntheticSuite(suite, root);
  const sourceIndexPath = path.join(suite, "source-index.json");
  const sourceIndex = JSON.parse(
    await fs.readFile(sourceIndexPath, "utf8"),
  ) as {
    data: {
      fixtures: Array<Record<string, unknown>>;
    };
  };
  const current = sourceIndex.data.fixtures[0]!;
  sourceIndex.data.fixtures[0] = {
    schemaVersion: "1.0",
    fixtureId: current.fixtureId,
    pairId: current.pairId,
    variant: current.variant,
    language: current.language,
    files: current.files,
    fixtureDigestSha256: current.fixtureDigestSha256,
    subject: current.subject,
    truthArtifact: {
      path: (current.truthArtifact as { path: string }).path,
      fixtureDigestSha256: current.fixtureDigestSha256,
    },
  };
  await fs.writeFile(
    sourceIndexPath,
    `${JSON.stringify(sourceIndex, null, 2)}\n`,
    "utf8",
  );
  await rehashSuiteArtifact(suite, "source-index.json");

  const result = await runSummary(suite, output);
  assert.equal(result.code, 1);
  assert.match(
    result.stderr,
    /legacy source-state schema 1\.0.*Regenerate.*structural source-state schema 2\.0/u,
  );
  await assert.rejects(fs.access(output));
});

test("rejects rehashed matched-evidence detail tampering", async (t) => {
  const root = await temporaryRoot(t, "hermsec-summary-match-detail-");
  const suite = path.join(root, "suite");
  const output = path.join(root, "summary");
  await writeSyntheticSuite(suite, root);
  await mutateEvaluation(suite, (evaluation) => {
    const run = evaluation.runs[0]!;
    run.cases[0]!.matchResult.matches[0]!.signals[0]!.explanation =
      "Fabricated but arithmetically neutral evidence.";
    run.matchResults[0] = structuredClone(
      run.cases[0]!.matchResult,
    );
  });

  const result = await runSummary(suite, output);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /recomputed full match semantics/u);
  await assert.rejects(fs.access(output));
});

test("rejects a rehashed ignoredActual duplicate target rewrite", async (t) => {
  const root = await temporaryRoot(t, "hermsec-summary-ignored-target-");
  const suite = path.join(root, "suite");
  const output = path.join(root, "summary");
  await writeSyntheticSuite(suite, root);
  await mutateEvaluation(suite, (evaluation) => {
    const run = evaluation.runs[0]!;
    const ignored = run.cases[0]!.matchResult.ignoredActual[0]!;
    ignored.duplicateOfId = "actual-secret";
    ignored.duplicateOfFingerprint = "fingerprint-secret";
    run.matchResults[0] = structuredClone(
      run.cases[0]!.matchResult,
    );
  });

  const result = await runSummary(suite, output);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /recomputed full match semantics/u);
  await assert.rejects(fs.access(output));
});

test("rejects coherent suppression of an arbitrary false positive as ignoredActual", async (t) => {
  const root = await temporaryRoot(t, "hermsec-summary-ignored-suppression-");
  const suite = path.join(root, "suite");
  const output = path.join(root, "summary");
  await writeSyntheticSuite(suite, root);
  await mutateEvaluation(suite, (evaluation) => {
    const run = evaluation.runs[0]!;
    const match = run.cases[0]!.matchResult;
    const falsePositive = match.falsePositives.shift();
    assert.ok(falsePositive);
    match.ignoredActual.push({
      id: falsePositive.id,
      fingerprint: falsePositive.fingerprint,
      category: falsePositive.category,
      reason: "duplicate",
      duplicateOfId: "actual-xss",
      duplicateOfFingerprint: "fingerprint-xss",
      noiseKey: "fabricated-suppression",
    });
    match.ignoredActual.sort((left, right) =>
      left.fingerprint.localeCompare(right.fingerprint),
    );
    applyMatchMetrics(run, match);
  });

  const result = await runSummary(suite, output);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /recomputed full match semantics/u);
  await assert.rejects(fs.access(output));
});

test("rejects aggregate completeness tampering that disagrees with cases", async (t) => {
  const root = await temporaryRoot(t, "hermsec-summary-completeness-");
  const suite = path.join(root, "suite");
  const output = path.join(root, "summary");
  await writeSyntheticSuite(suite, root);
  const evaluationPath = path.join(suite, "evaluation.json");
  const evaluation = JSON.parse(
    await fs.readFile(evaluationPath, "utf8"),
  ) as {
    data: {
      runs: Array<{
        completeness: {
          eligibleFiles: number;
          inspectedFiles: number;
          fileCoverage: number;
        };
      }>;
    };
  };
  const completeness = evaluation.data.runs[0]!.completeness;
  completeness.eligibleFiles = 2;
  completeness.inspectedFiles = 2;
  completeness.fileCoverage = 1;
  await fs.writeFile(
    evaluationPath,
    `${JSON.stringify(evaluation, null, 2)}\n`,
    "utf8",
  );
  await rehashSuiteArtifact(suite, "evaluation.json");

  const result = await runSummary(suite, output);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /aggregate eligible files/u);
  await assert.rejects(fs.access(output));
});

test("rejects a rehashed suite index whose run IDs are rebound", async (t) => {
  const root = await temporaryRoot(t, "hermsec-summary-rebinding-");
  const suite = path.join(root, "suite");
  const output = path.join(root, "summary");
  await writeSyntheticSuite(suite, root);
  const indexPath = path.join(suite, "suite-index.json");
  const index = JSON.parse(await fs.readFile(indexPath, "utf8")) as {
    indexSha256: string;
    runs: Array<{ runId: string }>;
    [key: string]: unknown;
  };
  const firstRunId = index.runs[0]!.runId;
  index.runs[0]!.runId = index.runs[1]!.runId;
  index.runs[1]!.runId = firstRunId;
  index.indexSha256 = sha256(
    canonicalJson(withoutTestProperty(index, "indexSha256")),
  );
  await fs.writeFile(indexPath, `${JSON.stringify(index, null, 2)}\n`, "utf8");

  const result = await runSummary(suite, output);
  assert.equal(result.code, 1);
  assert.match(
    result.stderr,
    /suite index run binding does not match/u,
  );
  await assert.rejects(fs.access(output));
});

test("rejects legacy suite-index v2 with an actionable compatibility error", async (t) => {
  const root = await temporaryRoot(t, "hermsec-summary-legacy-index-");
  const suite = path.join(root, "suite");
  const output = path.join(root, "summary");
  await writeSyntheticSuite(suite, root);
  const indexPath = path.join(suite, "suite-index.json");
  const index = JSON.parse(await fs.readFile(indexPath, "utf8")) as {
    schemaVersion: number;
    indexSha256: string;
    [key: string]: unknown;
  };
  index.schemaVersion = 2;
  index.indexSha256 = sha256(
    canonicalJson(withoutTestProperty(index, "indexSha256")),
  );
  await fs.writeFile(indexPath, `${JSON.stringify(index, null, 2)}\n`, "utf8");

  const result = await runSummary(suite, output);
  assert.equal(result.code, 1);
  assert.match(
    result.stderr,
    /requires the fresh suite-index\.json v3 evidence contract.*Regenerate/u,
  );
  await assert.rejects(fs.access(output));
});

test("rejects non-empty cost ledgers for mock and replay suites", async (t) => {
  const root = await temporaryRoot(t, "hermsec-summary-non-live-ledger-");
  for (const execution of ["mock", "replay"] as const) {
    const suite = path.join(root, `suite-${execution}`);
    const output = path.join(root, `summary-${execution}`);
    await writeSyntheticSuite(suite, root, { execution });
    await fs.writeFile(
      path.join(suite, "cost-ledger.jsonl"),
      '{"unexpected":true}\n',
      "utf8",
    );
    await rehashSuiteArtifact(suite, "cost-ledger.jsonl");
    const result = await runSummary(suite, output);
    assert.equal(result.code, 1);
    assert.match(result.stderr, /require a real empty cost-ledger/u);
    await assert.rejects(fs.access(output));
  }
});

test("rejects a malformed live ledger hash chain", async (t) => {
  const root = await temporaryRoot(t, "hermsec-summary-ledger-chain-");
  const suite = path.join(root, "suite");
  const output = path.join(root, "summary");
  await writeSyntheticSuite(suite, root, { execution: "live" });
  const ledgerPath = path.join(suite, "cost-ledger.jsonl");
  const events = await readLedgerEvents(ledgerPath);
  events[1]!.previousHash = "0".repeat(64);
  await writeLedgerEvents(ledgerPath, events, false);
  await rehashSuiteArtifact(suite, "cost-ledger.jsonl");

  const result = await runSummary(suite, output);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /previousHash/u);
  await assert.rejects(fs.access(output));
});

test("rejects a rehashed live ledger with a false overage claim", async (t) => {
  const root = await temporaryRoot(t, "hermsec-summary-ledger-overage-");
  const suite = path.join(root, "suite");
  const output = path.join(root, "summary");
  await writeSyntheticSuite(suite, root, { execution: "live" });
  const ledgerPath = path.join(suite, "cost-ledger.jsonl");
  const events = await readLedgerEvents(ledgerPath);
  events[1]!.action = "overage";
  events[1]!.overageReasons = ["reservation"];
  await writeLedgerEvents(ledgerPath, events, true);
  await rehashSuiteArtifact(suite, "cost-ledger.jsonl");

  const result = await runSummary(suite, output);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /overage reasons/u);
  await assert.rejects(fs.access(output));
});

test("accepts degraded live failed and unknown ledger terminals with canonical cost sources", async (t) => {
  const root = await temporaryRoot(t, "hermsec-summary-degraded-ledger-");
  for (const status of ["failed", "unknown"] as const) {
    const suite = path.join(root, `suite-${status}`);
    const output = path.join(root, `summary-${status}`);
    await writeSyntheticSuite(suite, root, {
      execution: "live",
      statusByMode: {
        "single-agent": "degraded",
        "scanner-single": "degraded",
      },
      liveCallsByMode: {
        "single-agent": [
          {
            role: "single-agent-inspector",
            model: DEEPSEEK_FLASH,
            costNanoUsd: 10_000_000,
            tokens: 100,
            status,
          },
        ],
      },
    });

    const result = await runSummary(suite, output);
    assert.equal(result.code, 0, result.stderr);
    const summary = JSON.parse(
      await fs.readFile(path.join(output, "summary.json"), "utf8"),
    ) as {
      totals: {
        actualPhysicalSpendUsd: number;
        conservativeCommittedUsd: number;
        physicalTokens: number;
        physicalModelCalls: number;
      };
    };
    assert.ok(
      Math.abs(summary.totals.actualPhysicalSpendUsd - 0.108) < 1e-12,
    );
    assert.ok(
      Math.abs(
        summary.totals.conservativeCommittedUsd -
          (status === "unknown" ? 0.118 : 0.108),
      ) < 1e-12,
    );
    assert.equal(summary.totals.physicalTokens, 1_080);
    assert.equal(summary.totals.physicalModelCalls, 13);
  }
});

test("rejects malformed failed and unknown live ledger terminals", async (t) => {
  const root = await temporaryRoot(t, "hermsec-summary-malformed-terminal-");
  for (const status of ["failed", "unknown"] as const) {
    const suite = path.join(root, `suite-${status}`);
    const output = path.join(root, `summary-${status}`);
    await writeSyntheticSuite(suite, root, {
      execution: "live",
      statusByMode: {
        "single-agent": "degraded",
        "scanner-single": "degraded",
      },
      liveCallsByMode: {
        "single-agent": [
          {
            role: "single-agent-inspector",
            model: DEEPSEEK_FLASH,
            costNanoUsd: 10_000_000,
            tokens: 100,
            status,
          },
        ],
      },
    });
    const ledgerPath = path.join(suite, "cost-ledger.jsonl");
    const events = await readLedgerEvents(ledgerPath);
    const terminal = events.find(
      (event) =>
        event.action === status &&
        event.mode === "single-agent",
    );
    assert.ok(terminal);
    terminal.costSource =
      status === "failed"
        ? "reservation-conservative"
        : "known-not-charged";
    await writeLedgerEvents(ledgerPath, events, true);
    await rehashSuiteArtifact(suite, "cost-ledger.jsonl");

    const result = await runSummary(suite, output);
    assert.equal(result.code, 1);
    assert.match(result.stderr, new RegExp(`${status} costSource`, "u"));
    await assert.rejects(fs.access(output));
  }
});

test("rejects rehashed failed and unknown terminal amount arithmetic", async (t) => {
  const root = await temporaryRoot(t, "hermsec-summary-terminal-amount-");
  for (const status of ["failed", "unknown"] as const) {
    const suite = path.join(root, `suite-${status}`);
    const output = path.join(root, `summary-${status}`);
    await writeSyntheticSuite(suite, root, {
      execution: "live",
      statusByMode: {
        "single-agent": "degraded",
        "scanner-single": "degraded",
      },
      liveCallsByMode: {
        "single-agent": [
          {
            role: "single-agent-inspector",
            model: DEEPSEEK_FLASH,
            costNanoUsd: 10_000_000,
            tokens: 100,
            status,
          },
        ],
      },
    });
    const ledgerPath = path.join(suite, "cost-ledger.jsonl");
    const events = await readLedgerEvents(ledgerPath);
    const terminal = events.find(
      (event) =>
        event.action === status &&
        event.mode === "single-agent",
    );
    assert.ok(terminal);
    terminal.amountNanoUsd = status === "failed" ? 1 : 0;
    terminal.amountUsd =
      (terminal.amountNanoUsd as number) / 1_000_000_000;
    await writeLedgerEvents(ledgerPath, events, true);
    await rehashSuiteArtifact(suite, "cost-ledger.jsonl");

    const result = await runSummary(suite, output);
    assert.equal(result.code, 1);
    assert.match(
      result.stderr,
      status === "failed"
        ? /must commit zero spend/u
        : /must retain reserved spend/u,
    );
    await assert.rejects(fs.access(output));
  }
});

test("rejects rehashed manifest and ledger attempts to raise fixed research budgets", async (t) => {
  const root = await temporaryRoot(t, "hermsec-summary-budget-rehash-");
  const manifestSuite = path.join(root, "suite-manifest");
  const manifestOutput = path.join(root, "summary-manifest");
  await writeSyntheticSuite(manifestSuite, root, { execution: "live" });
  await mutateRunManifest(manifestSuite, "single-agent", (manifest) => {
    const limits = manifest.limits as {
      globalBudgetUsd: number;
      modeBudgetUsd: number;
    };
    limits.globalBudgetUsd = 4;
    limits.modeBudgetUsd = 0.02;
  });
  const manifestResult = await runSummary(manifestSuite, manifestOutput);
  assert.equal(manifestResult.code, 1);
  assert.match(manifestResult.stderr, /canonical global budget/u);
  await assert.rejects(fs.access(manifestOutput));

  const ledgerSuite = path.join(root, "suite-ledger");
  const ledgerOutput = path.join(root, "summary-ledger");
  await writeSyntheticSuite(ledgerSuite, root, { execution: "live" });
  const ledgerPath = path.join(ledgerSuite, "cost-ledger.jsonl");
  const events = await readLedgerEvents(ledgerPath);
  const reservation = events.find(
    (event) =>
      event.action === "reserved" &&
      event.mode === "single-agent",
  );
  assert.ok(reservation);
  reservation.globalLimitNanoUsd = 4_000_000_000;
  reservation.modeLimitNanoUsd = 20_000_000;
  await writeLedgerEvents(ledgerPath, events, true);
  await rehashSuiteArtifact(ledgerSuite, "cost-ledger.jsonl");
  const ledgerResult = await runSummary(ledgerSuite, ledgerOutput);
  assert.equal(ledgerResult.code, 1);
  assert.match(ledgerResult.stderr, /canonical global limit/u);
  await assert.rejects(fs.access(ledgerOutput));
});

test("rejects rehashed live reservations above the canonical per-mode ceiling", async (t) => {
  const root = await temporaryRoot(t, "hermsec-summary-overbudget-");
  const suite = path.join(root, "suite");
  const output = path.join(root, "summary");
  await writeSyntheticSuite(suite, root, { execution: "live" });
  const ledgerPath = path.join(suite, "cost-ledger.jsonl");
  const events = await readLedgerEvents(ledgerPath);
  const matching = events.filter(
    (event) => event.mode === "single-agent",
  );
  assert.equal(matching.length, 2);
  for (const event of matching) {
    event.amountNanoUsd = 16_000_000;
    event.amountUsd = 0.016;
  }
  await writeLedgerEvents(ledgerPath, events, true);
  await rehashSuiteArtifact(suite, "cost-ledger.jsonl");

  const result = await runSummary(suite, output);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /reservation exceeds its mode budget/u);
  await assert.rejects(fs.access(output));
});

test("rejects coherent hybrid attribution that diverges from its physical source", async (t) => {
  const root = await temporaryRoot(t, "hermsec-summary-hybrid-cost-");
  const suite = path.join(root, "suite");
  const output = path.join(root, "summary");
  await writeSyntheticSuite(suite, root, { execution: "live" });
  const summaryPath = path.join(suite, "experiment-summary.json");
  const summaryDocument = JSON.parse(
    await fs.readFile(summaryPath, "utf8"),
  ) as {
    data: {
      cells: Array<{
        mode: string;
        cost: { attributedCostUsd: number };
      }>;
      attributedModeCostUsd: Record<string, number>;
    };
  };
  const hybridCell = summaryDocument.data.cells.find(
    (cell) => cell.mode === "scanner-single",
  );
  assert.ok(hybridCell);
  hybridCell.cost.attributedCostUsd = 0.011;
  summaryDocument.data.attributedModeCostUsd["scanner-single"] = 0.011;
  await fs.writeFile(
    summaryPath,
    `${JSON.stringify(summaryDocument, null, 2)}\n`,
    "utf8",
  );
  await rehashSuiteArtifact(suite, "experiment-summary.json");

  const result = await runSummary(suite, output);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /hybrid attributed cost/u);
  await assert.rejects(fs.access(output));
});

test("rejects an approved live model that its manifest did not declare", async (t) => {
  const root = await temporaryRoot(t, "hermsec-summary-model-binding-");
  const suite = path.join(root, "suite");
  const output = path.join(root, "summary");
  await writeSyntheticSuite(suite, root, { execution: "live" });
  const ledgerPath = path.join(suite, "cost-ledger.jsonl");
  const events = await readLedgerEvents(ledgerPath);
  events[0]!.model = MIMO;
  events[1]!.model = MIMO;
  await writeLedgerEvents(ledgerPath, events, true);
  await rehashSuiteArtifact(suite, "cost-ledger.jsonl");

  const result = await runSummary(suite, output);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /undeclared by the bound run manifest/u);
  await assert.rejects(fs.access(output));
});

test("accepts the same live request fingerprint in distinct physical cells", async (t) => {
  const root = await temporaryRoot(t, "hermsec-summary-cross-cell-fingerprint-");
  const suite = path.join(root, "suite");
  const output = path.join(root, "summary");
  await writeSyntheticSuite(suite, root, { execution: "live" });
  const sharedFingerprint = sha256("shared-request-across-cells");
  const ledgerPath = path.join(suite, "cost-ledger.jsonl");
  const events = await readLedgerEvents(ledgerPath);
  for (const mode of ["single-agent", "moa-low"] as const) {
    const reservation = events.find(
      (event) => event.action === "reserved" && event.mode === mode,
    );
    assert.ok(reservation);
    for (const event of events.filter(
      (candidate) => candidate.reservationId === reservation.reservationId,
    )) {
      event.requestFingerprint = sharedFingerprint;
    }
    await mutateRunArtifact(suite, mode, "model-calls.json", (value) => {
      const trace = value as {
        calls: Array<Record<string, unknown>>;
      };
      assert.ok(trace.calls[0]);
      trace.calls[0].requestFingerprint = sharedFingerprint;
    });
  }
  await writeLedgerEvents(ledgerPath, events, true);
  await rehashSuiteArtifact(suite, "cost-ledger.jsonl");

  const result = await runSummary(suite, output);
  assert.equal(result.code, 0, result.stderr);
  await fs.access(path.join(output, "summary.json"));
});

test("accepts the same live request fingerprint across run IDs in one mode", async (t) => {
  const root = await temporaryRoot(t, "hermsec-summary-same-mode-cross-run-");
  const suite = path.join(root, "suite");
  const output = path.join(root, "summary");
  const lowCostCalls: Record<PhysicalAgentMode, readonly LiveCall[]> = {
    "single-agent": DEFAULT_LIVE_CALLS["single-agent"].map((call) => ({
      ...call,
      costNanoUsd: 1_000,
      tokens: 2,
    })),
    "moa-low": DEFAULT_LIVE_CALLS["moa-low"].map((call) => ({
      ...call,
      costNanoUsd: 1_000,
      tokens: 2,
    })),
    "moa-high": DEFAULT_LIVE_CALLS["moa-high"].map((call) => ({
        ...call,
        costNanoUsd: 1_000,
        tokens: 2,
    })),
  };
  await writeSyntheticSuite(suite, root, {
    execution: "live",
    fixtureIds: ["fixture-alpha", "fixture-beta"],
    liveCallsByMode: lowCostCalls,
  });

  const result = await runSummary(suite, output);
  assert.equal(result.code, 0, result.stderr);
  await fs.access(path.join(output, "summary.json"));
});

test("rejects a repeated live request fingerprint within one physical cell", async (t) => {
  const root = await temporaryRoot(t, "hermsec-summary-within-cell-fingerprint-");
  const suite = path.join(root, "suite");
  const output = path.join(root, "summary");
  await writeSyntheticSuite(suite, root, { execution: "live" });
  const ledgerPath = path.join(suite, "cost-ledger.jsonl");
  const events = await readLedgerEvents(ledgerPath);
  const reservations = events.filter(
    (event) => event.action === "reserved" && event.mode === "moa-low",
  );
  assert.ok(reservations[0]);
  assert.ok(reservations[1]);
  const repeatedFingerprint = reservations[0].requestFingerprint as string;
  for (const event of events.filter(
    (candidate) =>
      candidate.reservationId === reservations[1]!.reservationId,
  )) {
    event.requestFingerprint = repeatedFingerprint;
  }
  await mutateRunArtifact(suite, "moa-low", "model-calls.json", (value) => {
    const trace = value as {
      calls: Array<Record<string, unknown>>;
    };
    assert.ok(trace.calls[1]);
    trace.calls[1].requestFingerprint = repeatedFingerprint;
  });
  await writeLedgerEvents(ledgerPath, events, true);
  await rehashSuiteArtifact(suite, "cost-ledger.jsonl");

  const result = await runSummary(suite, output);
  assert.equal(result.code, 1);
  assert.match(
    result.stderr,
    /model-call request fingerprints contains duplicates|unique within each physical cell/u,
  );
  await assert.rejects(fs.access(output));
});

test("rejects a pre-metering trace entry bound to a live ledger reservation", async (t) => {
  const root = await temporaryRoot(t, "hermsec-summary-pre-metering-ledger-");
  const suite = path.join(root, "suite");
  const output = path.join(root, "summary");
  await writeSyntheticSuite(suite, root, {
    execution: "live",
    liveCallsByMode: {
      "single-agent": [
        {
          role: "single-agent-inspector",
          model: DEEPSEEK_FLASH,
          costNanoUsd: 5_000_000,
          tokens: 50,
        },
        {
          role: "single-agent-inspector",
          model: DEEPSEEK_FLASH,
          costNanoUsd: 5_000_000,
          tokens: 50,
        },
      ],
    },
  });
  await mutateRunArtifact(suite, "single-agent", "model-calls.json", (value) => {
    const trace = value as {
      calls: Array<Record<string, unknown>>;
    };
    assert.ok(trace.calls[1]);
    trace.calls[1].fingerprintSource = "pre-metering-rejection";
    trace.calls[1].terminalState = "failed";
    delete trace.calls[1].responseProvider;
    delete trace.calls[1].responseModel;
    trace.calls[1].errorCategory = "replay";
  });

  const result = await runSummary(suite, output);
  assert.equal(result.code, 1);
  assert.match(
    result.stderr,
    /pre-metering model-call rejection must not have an authoritative ledger reservation|does not bind every authoritative ledger reservation|model-call count does not match/u,
  );
  await assert.rejects(fs.access(output));
});

test("rejects a successful pre-metering trace entry", async (t) => {
  const root = await temporaryRoot(t, "hermsec-summary-pre-metering-success-");
  const suite = path.join(root, "suite");
  const output = path.join(root, "summary");
  await writeSyntheticSuite(suite, root, { execution: "replay" });
  await mutateRunArtifact(
    suite,
    "single-agent",
    "model-calls.json",
    (value) => {
      const trace = value as {
        calls: Array<Record<string, unknown>>;
      };
      assert.ok(trace.calls[0]);
      trace.calls[0].fingerprintSource = "pre-metering-rejection";
    },
  );

  const result = await runSummary(suite, output);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /pre-metering-rejection-terminal-invalid/u);
  await assert.rejects(fs.access(output));
});

test("rejects Minimax when declared outside an MoA aggregator run", async (t) => {
  const root = await temporaryRoot(t, "hermsec-summary-model-role-");
  const suite = path.join(root, "suite");
  const output = path.join(root, "summary");
  await writeSyntheticSuite(suite, root, { execution: "replay" });
  await mutateRunManifest(suite, "single-agent", (manifest) => {
    manifest.models = [
      {
        provider: "openrouter",
        model: MINIMAX_AGGREGATOR,
      },
    ];
  });

  const result = await runSummary(suite, output);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /Minimax may be declared only/u);
  await assert.rejects(fs.access(output));
});

test("rejects Minimax before MoA specialist or judge calls", async (t) => {
  const root = await temporaryRoot(t, "hermsec-summary-model-order-");
  const suite = path.join(root, "suite");
  const output = path.join(root, "summary");
  await writeSyntheticSuite(suite, root, { execution: "replay" });
  await mutateRunArtifact(suite, "moa-low", "model-calls.json", (value) => {
    const trace = value as {
      calls: Array<Record<string, unknown>>;
    };
    const aggregatorIndex = trace.calls.findIndex(
      (call) => call.role === "moa-aggregator",
    );
    assert.notEqual(aggregatorIndex, -1);
    const [aggregator] = trace.calls.splice(aggregatorIndex, 1);
    assert.ok(aggregator);
    trace.calls.unshift(aggregator);
    trace.calls.forEach((call, index) => {
      call.ordinal = index + 1;
    });
  });

  const result = await runSummary(suite, output);
  assert.equal(result.code, 1);
  assert.match(
    result.stderr,
    /moa-aggregator-not-terminal|moa-aggregator-order-invalid/u,
  );
  await assert.rejects(fs.access(output));
});

test("rejects successful MoA traces with zero calls in replay evidence", async (t) => {
  const root = await temporaryRoot(t, "hermsec-summary-zero-moa-");
  const suite = path.join(root, "suite");
  const output = path.join(root, "summary");
  await writeSyntheticSuite(suite, root, { execution: "replay" });
  await mutateRunArtifact(suite, "moa-low", "model-calls.json", (value) => {
    const trace = value as {
      calls: Array<Record<string, unknown>>;
    };
    trace.calls = [];
  });

  const result = await runSummary(suite, output);
  assert.equal(result.code, 1);
  assert.match(
    result.stderr,
    /successful-agent-run-has-zero-model-calls/u,
  );
  await assert.rejects(fs.access(output));
});

test("rejects a replay trace whose exact cassette reference is rebound", async (t) => {
  const root = await temporaryRoot(
    t,
    "hermsec-summary-cassette-reference-",
  );
  const suite = path.join(root, "suite");
  const output = path.join(root, "summary");
  await writeSyntheticSuite(suite, root, { execution: "replay" });
  await mutateRunArtifact(
    suite,
    "single-agent",
    "model-calls.json",
    (value) => {
      const trace = value as {
        calls: Array<{
          requestFingerprint: string;
          cassetteReference?: {
            requestFingerprint: string;
          };
        }>;
      };
      const call = trace.calls[0];
      assert.ok(call?.cassetteReference);
      call.cassetteReference.requestFingerprint = sha256(
        "unrelated-cassette-request",
      );
    },
  );

  const result = await runSummary(suite, output);
  assert.equal(result.code, 1);
  assert.match(
    result.stderr,
    /model-call-cassette-reference-invalid/u,
  );
  await assert.rejects(fs.access(output));
});

test("rejects a replay trace whose cassette scope binding is removed", async (t) => {
  const root = await temporaryRoot(
    t,
    "hermsec-summary-cassette-scope-",
  );
  const suite = path.join(root, "suite");
  const output = path.join(root, "summary");
  await writeSyntheticSuite(suite, root, { execution: "replay" });
  await mutateRunArtifact(
    suite,
    "single-agent",
    "model-calls.json",
    (value) => {
      const trace = value as {
        calls: Array<{
          cassetteReference?: {
            scopeIdSha256?: string;
          };
        }>;
      };
      const call = trace.calls[0];
      assert.ok(call?.cassetteReference);
      delete call.cassetteReference.scopeIdSha256;
    },
  );

  const result = await runSummary(suite, output);
  assert.equal(result.code, 1);
  assert.match(
    result.stderr,
    /cassetteReference (?:keys|fields)|model-call-cassette-reference-invalid/u,
  );
  await assert.rejects(fs.access(output));
});

test("rejects a replay trace rebound to another well-formed cassette scope", async (t) => {
  const root = await temporaryRoot(
    t,
    "hermsec-summary-cassette-wrong-scope-",
  );
  const suite = path.join(root, "suite");
  const output = path.join(root, "summary");
  await writeSyntheticSuite(suite, root, { execution: "replay" });
  await mutateRunArtifact(
    suite,
    "single-agent",
    "model-calls.json",
    (value) => {
      const trace = value as {
        calls: Array<{
          cassetteReference?: {
            scopeIdSha256: string;
          };
        }>;
      };
      const call = trace.calls[0];
      assert.ok(call?.cassetteReference);
      call.cassetteReference.scopeIdSha256 = sha256(
        "another-valid-cassette-scope",
      );
    },
  );

  const result = await runSummary(suite, output);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /cassette scope binding/u);
  await assert.rejects(fs.access(output));
});

test("rejects a recorded trace when successful calls lack cassette references", async (t) => {
  const root = await temporaryRoot(
    t,
    "hermsec-summary-recorded-reference-",
  );
  const suite = path.join(root, "suite");
  const output = path.join(root, "summary");
  await writeSyntheticSuite(suite, root, { execution: "mock" });
  await mutateRunArtifact(
    suite,
    "single-agent",
    "model-calls.json",
    (value) => {
      const trace = value as Record<string, unknown>;
      trace.cassettePolicy = "recorded";
      refreshProducerValidation(trace);
    },
  );
  await mutateRunManifest(suite, "single-agent", (manifest) => {
    const metadata = manifest.metadata as Record<string, unknown>;
    metadata.modelCallTraceCassettePolicy = "recorded";
  });

  const result = await runSummary(suite, output);
  assert.equal(result.code, 1);
  assert.match(
    result.stderr,
    /successful-replay-call-missing-cassette-reference/u,
  );
  await assert.rejects(fs.access(output));
});

test("rejects multiple explicit Minimax aggregator calls", async (t) => {
  const root = await temporaryRoot(t, "hermsec-summary-multiple-aggregator-");
  const suite = path.join(root, "suite");
  const output = path.join(root, "summary");
  await writeSyntheticSuite(suite, root, { execution: "replay" });
  await mutateRunArtifact(suite, "moa-low", "model-calls.json", (value) => {
    const trace = value as {
      calls: Array<Record<string, unknown>>;
    };
    const aggregator = trace.calls.find(
      (call) => call.role === "moa-aggregator",
    );
    assert.ok(aggregator);
    trace.calls.push({
      ...structuredClone(aggregator),
      ordinal: trace.calls.length + 1,
      requestFingerprint: sha256("second-aggregator"),
    });
  });

  const result = await runSummary(suite, output);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /multiple-moa-aggregator-calls/u);
  await assert.rejects(fs.access(output));
});

test("requires both judge and specialist provenance for successful MoA", async (t) => {
  const root = await temporaryRoot(t, "hermsec-summary-moa-provenance-");
  const cases: Array<{
    name: string;
    mutate: (calls: Array<Record<string, unknown>>) => void;
    expected: RegExp;
  }> = [
    {
      name: "missing-judge",
      mutate: (calls) => {
        const index = calls.findIndex(
          (call) => call.role === "moa-judge",
        );
        assert.notEqual(index, -1);
        calls.splice(index, 1);
      },
      expected: /candidate-bearing-moa-judge-incomplete/u,
    },
    {
      name: "missing-specialist",
      mutate: (calls) => {
        const index = calls.findIndex(
          (call) => call.role === "injection-and-execution",
        );
        assert.notEqual(index, -1);
        calls.splice(index, 1);
      },
      expected: /successful-moa-role-plan-under-provisioned/u,
    },
  ];
  for (const candidate of cases) {
    const suite = path.join(root, `suite-${candidate.name}`);
    const output = path.join(root, `summary-${candidate.name}`);
    await writeSyntheticSuite(suite, root, { execution: "replay" });
    await mutateRunArtifact(
      suite,
      "moa-low",
      "model-calls.json",
      (value) => {
        const trace = value as {
          calls: Array<Record<string, unknown>>;
        };
        candidate.mutate(trace.calls);
        trace.calls.forEach((call, index) => {
          call.ordinal = index + 1;
        });
      },
    );
    const result = await runSummary(suite, output);
    assert.equal(result.code, 1);
    assert.match(result.stderr, candidate.expected);
    await assert.rejects(fs.access(output));
  }
});

test("rejects invalid explicit roles in mock and replay model traces", async (t) => {
  const root = await temporaryRoot(t, "hermsec-summary-non-live-role-");
  for (const execution of ["mock", "replay"] as const) {
    const suite = path.join(root, `suite-${execution}`);
    const output = path.join(root, `summary-${execution}`);
    await writeSyntheticSuite(suite, root, { execution });
    await mutateRunArtifact(
      suite,
      "single-agent",
      "model-calls.json",
      (value) => {
        const trace = value as {
          calls: Array<Record<string, unknown>>;
        };
        trace.calls[0]!.role = "identity-and-request-security";
        trace.calls[0]!.model = MIMO;
        trace.calls[0]!.responseModel = MIMO;
      },
    );

    const result = await runSummary(suite, output);
    assert.equal(result.code, 1);
    assert.match(result.stderr, /single-agent-role-invalid/u);
    await assert.rejects(fs.access(output));
  }
});

test("rejects a rehashed model-call role/model provenance rewrite", async (t) => {
  const root = await temporaryRoot(t, "hermsec-summary-trace-rehash-");
  const suite = path.join(root, "suite");
  const output = path.join(root, "summary");
  await writeSyntheticSuite(suite, root, { execution: "replay" });
  await mutateRunArtifact(
    suite,
    "single-agent",
    "model-calls.json",
    (data) => {
      const trace = data as {
        calls: Array<{ role: string }>;
      };
      trace.calls[0]!.role = "identity-and-request-security";
    },
  );

  const result = await runSummary(suite, output);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /model-call-role-model-mismatch/u);
  await assert.rejects(fs.access(output));
});

test("accepts completed zero-candidate MoA cells with every planned specialist and no adjudication calls", async (t) => {
  const root = await temporaryRoot(t, "hermsec-summary-zero-candidate-");
  const suite = path.join(root, "suite");
  const output = path.join(root, "summary");
  await writeSyntheticSuite(suite, root, {
    execution: "replay",
    candidateCountByMode: {
      "moa-low": 0,
      "moa-high": 0,
    },
  });

  const result = await runSummary(suite, output);
  assert.equal(result.code, 0, result.stderr);
  for (const mode of ["moa-low", "moa-high"] as const) {
    const trace = JSON.parse(
      await fs.readFile(
        path.join(
          suite,
          "runs",
          "fixture-vulnerable",
          mode,
          "model-calls.json",
        ),
        "utf8",
      ),
    ) as {
      data: {
        candidateCount: number;
        aggregationDisposition: string;
        calls: Array<{ role: string }>;
      };
    };
    assert.equal(trace.data.candidateCount, 0);
    assert.equal(
      trace.data.aggregationDisposition,
      "not-required-no-candidates",
    );
    assert.equal(
      trace.data.calls.some(
        (call) =>
          call.role === "moa-judge" ||
          call.role === "moa-aggregator",
      ),
      false,
    );
    assert.equal(
      trace.data.calls.length,
      mode === "moa-low" ? 3 : 5,
    );
  }
});

test("rejects coherently rehashed under-provisioned MoA Low and High traces", async (t) => {
  const root = await temporaryRoot(t, "hermsec-summary-role-plan-");
  for (const mode of ["moa-low", "moa-high"] as const) {
    const suite = path.join(root, `suite-${mode}`);
    const output = path.join(root, `summary-${mode}`);
    await writeSyntheticSuite(suite, root, { execution: "replay" });
    await mutateRunArtifact(
      suite,
      mode,
      "model-calls.json",
      (value) => {
        const trace = value as {
          calls: Array<Record<string, unknown>>;
          [key: string]: unknown;
        };
        const requiredRole =
          mode === "moa-low"
            ? "identity-and-request-security"
            : "platform-storage-and-deployment";
        const index = trace.calls.findIndex(
          (call) => call.role === requiredRole && call.gapFill === false,
        );
        assert.notEqual(index, -1);
        trace.calls.splice(index, 1);
        trace.calls.forEach((call, callIndex) => {
          call.ordinal = callIndex + 1;
        });
        refreshProducerValidation(trace);
      },
    );

    const result = await runSummary(suite, output);
    assert.equal(result.code, 1);
    assert.match(
      result.stderr,
      /successful-moa-role-plan-under-provisioned/u,
    );
    await assert.rejects(fs.access(output));
  }
});

test("validates strict MoA semantics per fixture even when a sibling cell is incomplete", async (t) => {
  const root = await temporaryRoot(t, "hermsec-summary-mixed-fixtures-");
  const fixtures = ["fixture-vulnerable", "fixture-secondary"];
  const statusByFixtureMode = {
    "fixture-secondary": {
      "moa-low": "failed",
      "scanner-moa-low": "failed",
    },
  } as const;
  const validSuite = path.join(root, "suite-valid");
  const validOutput = path.join(root, "summary-valid");
  await writeSyntheticSuite(validSuite, root, {
    execution: "replay",
    fixtureIds: fixtures,
    statusByFixtureMode,
  });
  const validResult = await runSummary(validSuite, validOutput);
  assert.equal(validResult.code, 0, validResult.stderr);

  const tamperedSuite = path.join(root, "suite-tampered");
  const tamperedOutput = path.join(root, "summary-tampered");
  await writeSyntheticSuite(tamperedSuite, root, {
    execution: "replay",
    fixtureIds: fixtures,
    statusByFixtureMode,
  });
  await mutateRunArtifact(
    tamperedSuite,
    "moa-low",
    "model-calls.json",
    (value) => {
      const trace = value as {
        calls: Array<Record<string, unknown>>;
        [key: string]: unknown;
      };
      const index = trace.calls.findIndex(
        (call) =>
          call.role === "sensitive-data-and-cryptography" &&
          call.gapFill === false,
      );
      assert.notEqual(index, -1);
      trace.calls.splice(index, 1);
      trace.calls.forEach((call, callIndex) => {
        call.ordinal = callIndex + 1;
      });
      refreshProducerValidation(trace);
    },
    "fixture-vulnerable",
  );
  const tamperedResult = await runSummary(
    tamperedSuite,
    tamperedOutput,
  );
  assert.equal(tamperedResult.code, 1);
  assert.match(
    tamperedResult.stderr,
    /moa-low\/fixture-vulnerable.*successful-moa-role-plan-under-provisioned/u,
  );
  await assert.rejects(fs.access(tamperedOutput));
});

test("rejects a producer-valid gap-fill rewrite without a bound gap-fill execution", async (t) => {
  const root = await temporaryRoot(t, "hermsec-summary-gap-fill-");
  const suite = path.join(root, "suite");
  const output = path.join(root, "summary");
  await writeSyntheticSuite(suite, root, { execution: "replay" });
  await mutateRunArtifact(
    suite,
    "moa-low",
    "model-calls.json",
    (value) => {
      const trace = value as {
        calls: Array<Record<string, unknown>>;
        producerValidation: { valid: boolean; errors: string[] };
      };
      const specialist = trace.calls.find(
        (call) => call.role === "identity-and-request-security",
      );
      assert.ok(specialist);
      specialist.gapFill = true;
      refreshProducerValidation(trace);
      assert.equal(trace.producerValidation.valid, true);
    },
  );

  const result = await runSummary(suite, output);
  assert.equal(result.code, 1);
  assert.match(
    result.stderr,
    /without a matching role execution|exact initial specialist-call set|gap-fill calls do not match/u,
  );
  await assert.rejects(fs.access(output));
});

test("rejects failed cells presented as complete evaluation evidence", async (t) => {
  const root = await temporaryRoot(t, "hermsec-summary-status-");
  const suite = path.join(root, "suite");
  const output = path.join(root, "summary");
  await writeSyntheticSuite(suite, root, {
    statusByMode: { "single-agent": "failed" },
    forceCompleteModes: new Set(["single-agent"]),
  });

  const result = await runSummary(suite, output);
  assert.equal(result.code, 1);
  assert.match(
    result.stderr,
    /is failed but evaluation completeness is complete/u,
  );
  await assert.rejects(fs.access(output));
});

test("rejects an incomplete seven-mode evaluation before writing", async (t) => {
  const root = await temporaryRoot(t, "hermsec-summary-incomplete-");
  const suite = path.join(root, "suite");
  const output = path.join(root, "summary");
  await writeSyntheticSuite(suite, root);
  const evaluationPath = path.join(suite, "evaluation.json");
  const evaluation = JSON.parse(
    await fs.readFile(evaluationPath, "utf8"),
  ) as { data: { runs: unknown[] } };
  evaluation.data.runs.pop();
  await fs.writeFile(
    evaluationPath,
    `${JSON.stringify(evaluation, null, 2)}\n`,
    "utf8",
  );
  await rehashSuiteArtifact(suite, "evaluation.json");

  const result = await runSummary(suite, output);
  assert.equal(result.code, 1);
  assert.match(
    result.stderr,
    /exactly one run for each of the seven canonical modes/u,
  );
  await assert.rejects(fs.access(output));
});

async function temporaryRoot(
  t: TestContext,
  prefix: string,
): Promise<string> {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  return root;
}

type IntegrityReceipt = {
  receiptSha256: string;
  upstreamBindingSha256: string;
  outputSetSha256: string;
  derivationBindingSha256: string;
  generator: { path: string; bytes: number; sha256: string };
  upstream: {
    suiteIndex: {
      path: string;
      bytes: number;
      sha256: string;
      indexSha256: string;
    };
    suiteArtifacts: Array<{
      path: string;
      bytes: number;
      sha256: string;
    }>;
    runManifests: Array<{
      path: string;
      bytes: number;
      sha256: string;
      manifestSha256: string;
    }>;
    runManifestSetSha256: string;
    sourceTruth: Array<{
      path: string;
      artifactSha256: string;
      manifestSha256: string;
      truthSha256: string;
      sourceStateSha256: string;
      projectDigestSha256: string;
      evaluatorDigestSha256: string;
      layoutBindingSha256: string;
      subjectDigestSha256: string;
      subjectFixtureBindingSha256: string;
    }>;
    sourceTruthSetSha256: string;
  };
  outputBindings: Array<{ path: string; bytes: number; sha256: string }>;
  downstreamEvidence: {
    manifestRate: { value: number | null };
    runtime: { status: string };
    replayAgreement: { status: string };
  };
  [key: string]: unknown;
};

async function verifyIntegrityReceipt(
  outputDirectory: string,
  suiteDirectory: string,
): Promise<IntegrityReceipt> {
  const receipt = JSON.parse(
    await fs.readFile(
      path.join(outputDirectory, "integrity-receipt.json"),
      "utf8",
    ),
  ) as IntegrityReceipt;
  assert.equal(
    receipt.receiptSha256,
    sha256(
      canonicalJson(withoutTestProperty(receipt, "receiptSha256")),
    ),
    "receipt self digest mismatch",
  );
  assert.equal(
    receipt.upstreamBindingSha256,
    sha256(canonicalJson(receipt.upstream)),
    "receipt upstream digest mismatch",
  );
  assert.equal(
    receipt.outputSetSha256,
    sha256(canonicalJson(receipt.outputBindings)),
    "receipt output set digest mismatch",
  );
  assert.equal(
    receipt.upstream.runManifestSetSha256,
    sha256(canonicalJson(receipt.upstream.runManifests)),
    "receipt run manifest set digest mismatch",
  );
  assert.equal(
    receipt.upstream.sourceTruthSetSha256,
    sha256(canonicalJson(receipt.upstream.sourceTruth)),
    "receipt source/truth set digest mismatch",
  );
  assert.equal(
    receipt.derivationBindingSha256,
    sha256(
      canonicalJson({
        generatorSha256: receipt.generator.sha256,
        suiteIndexSha256: receipt.upstream.suiteIndex.sha256,
        upstreamBindingSha256: receipt.upstreamBindingSha256,
        outputSetSha256: receipt.outputSetSha256,
      }),
    ),
    "receipt derivation digest mismatch",
  );
  const generatorContent = await fs.readFile(
    path.resolve(receipt.generator.path),
  );
  assert.equal(generatorContent.byteLength, receipt.generator.bytes);
  assert.equal(sha256(generatorContent), receipt.generator.sha256);
  const suiteIndexContent = await fs.readFile(
    path.join(suiteDirectory, receipt.upstream.suiteIndex.path),
  );
  assert.equal(
    suiteIndexContent.byteLength,
    receipt.upstream.suiteIndex.bytes,
    "receipt suite-index byte mismatch",
  );
  assert.equal(
    sha256(suiteIndexContent),
    receipt.upstream.suiteIndex.sha256,
    "receipt suite-index digest mismatch",
  );
  for (const binding of receipt.upstream.suiteArtifacts) {
    const content = await fs.readFile(
      path.join(suiteDirectory, binding.path),
    );
    assert.equal(
      content.byteLength,
      binding.bytes,
      `upstream artifact byte mismatch: ${binding.path}`,
    );
    assert.equal(
      sha256(content),
      binding.sha256,
      `upstream artifact digest mismatch: ${binding.path}`,
    );
  }
  for (const binding of receipt.upstream.runManifests) {
    const content = await fs.readFile(
      path.join(suiteDirectory, binding.path),
    );
    assert.equal(
      content.byteLength,
      binding.bytes,
      `run manifest byte mismatch: ${binding.path}`,
    );
    assert.equal(
      sha256(content),
      binding.sha256,
      `run manifest digest mismatch: ${binding.path}`,
    );
    const manifest = JSON.parse(content.toString("utf8")) as {
      manifestSha256: string;
    };
    assert.equal(
      manifest.manifestSha256,
      binding.manifestSha256,
      `run manifest canonical digest mismatch: ${binding.path}`,
    );
  }
  for (const binding of receipt.upstream.sourceTruth) {
    const document = JSON.parse(
      await fs.readFile(path.join(suiteDirectory, binding.path), "utf8"),
    ) as {
      data: {
        manifest: unknown;
        truth: unknown;
        sourceState: {
          project: {
            projectDigestSha256: string;
          };
          evaluator: {
            evaluatorDigestSha256: string;
          };
          layoutBindingSha256: string;
          subject: {
            subjectDigestSha256: string;
            fixtureBindingSha256: string;
          };
        };
      };
    };
    assert.equal(
      sha256(canonicalJson(document.data.manifest)),
      binding.manifestSha256,
    );
    assert.equal(
      sha256(canonicalJson(document.data.truth)),
      binding.truthSha256,
    );
    assert.equal(
      sha256(canonicalJson(document.data.sourceState)),
      binding.sourceStateSha256,
    );
    assert.equal(
      document.data.sourceState.project.projectDigestSha256,
      binding.projectDigestSha256,
    );
    assert.equal(
      document.data.sourceState.evaluator.evaluatorDigestSha256,
      binding.evaluatorDigestSha256,
    );
    assert.equal(
      document.data.sourceState.layoutBindingSha256,
      binding.layoutBindingSha256,
    );
    assert.equal(
      document.data.sourceState.subject.subjectDigestSha256,
      binding.subjectDigestSha256,
    );
    assert.equal(
      document.data.sourceState.subject.fixtureBindingSha256,
      binding.subjectFixtureBindingSha256,
    );
  }
  for (const binding of receipt.outputBindings) {
    const content = await fs.readFile(
      path.join(outputDirectory, binding.path),
    );
    assert.equal(
      content.byteLength,
      binding.bytes,
      `output byte mismatch: ${binding.path}`,
    );
    assert.equal(
      sha256(content),
      binding.sha256,
      `output digest mismatch: ${binding.path}`,
    );
  }
  return receipt;
}

type MutableLedgerEvent = {
  sequence: number;
  previousHash: string | null;
  hash: string;
  action: string;
  model: string;
  overageReasons?: string[];
  [key: string]: unknown;
};

async function readLedgerEvents(
  ledgerPath: string,
): Promise<MutableLedgerEvent[]> {
  const source = await fs.readFile(ledgerPath, "utf8");
  return source
    .trimEnd()
    .split("\n")
    .map((line) => JSON.parse(line) as MutableLedgerEvent);
}

async function writeLedgerEvents(
  ledgerPath: string,
  events: MutableLedgerEvent[],
  rebuildChain: boolean,
): Promise<void> {
  if (rebuildChain) {
    let previousHash: string | null = null;
    for (const [index, event] of events.entries()) {
      event.sequence = index + 1;
      event.previousHash = previousHash;
      event.hash = sha256(
        canonicalJson(withoutTestProperty(event, "hash")),
      );
      previousHash = event.hash;
    }
  }
  await fs.writeFile(
    ledgerPath,
    `${events.map((event) => JSON.stringify(event)).join("\n")}\n`,
    "utf8",
  );
}

async function rehashSuiteArtifact(
  suiteDirectory: string,
  relativePath: string,
): Promise<void> {
  const indexPath = path.join(suiteDirectory, "suite-index.json");
  const index = JSON.parse(
    await fs.readFile(indexPath, "utf8"),
  ) as {
    artifacts: Array<{ path: string; bytes: number; sha256: string }>;
    indexSha256: string;
    [key: string]: unknown;
  };
  const record = index.artifacts.find(
    (candidate) => candidate.path === relativePath,
  );
  assert.ok(record, `missing suite artifact ${relativePath}`);
  const content = await fs.readFile(
    path.join(suiteDirectory, relativePath),
  );
  record.bytes = content.byteLength;
  record.sha256 = sha256(content);
  index.indexSha256 = sha256(
    canonicalJson(withoutTestProperty(index, "indexSha256")),
  );
  await fs.writeFile(indexPath, `${JSON.stringify(index, null, 2)}\n`, "utf8");
}

type SyntheticFileRecord = {
  path: string;
  bytes: number;
  sha256: string;
};

function syntheticFileRecord(relativePath: string): SyntheticFileRecord {
  const content = `synthetic-injected-${relativePath}`;
  return {
    path: relativePath,
    bytes: Buffer.byteLength(content),
    sha256: sha256(content),
  };
}

async function coherentlyRewriteStructuralFixture(
  suiteDirectory: string,
  mutateFiles: (files: SyntheticFileRecord[]) => void,
  fixtureId = "fixture-vulnerable",
): Promise<void> {
  const sourceIndexPath = path.join(suiteDirectory, "source-index.json");
  const sourceIndex = JSON.parse(
    await fs.readFile(sourceIndexPath, "utf8"),
  ) as {
    data: {
      fixtures: Array<
        ReturnType<typeof syntheticFixtureContext>["sourceState"] & {
          truthArtifact: {
            path: string;
            fixtureDigestSha256: string;
            projectDigestSha256: string;
            evaluatorDigestSha256: string;
            layoutBindingSha256: string;
          };
        }
      >;
    };
  };
  const indexedFixture = sourceIndex.data.fixtures.find(
    (candidate) => candidate.fixtureId === fixtureId,
  );
  assert.ok(indexedFixture, `missing source-index fixture ${fixtureId}`);
  const files = indexedFixture.files.map((entry) => ({ ...entry }));
  mutateFiles(files);
  files.sort((left, right) => left.path.localeCompare(right.path));
  const sourceState = rebuildStructuralSourceState(
    indexedFixture,
    files,
  );
  const truthArtifactPath = indexedFixture.truthArtifact.path;
  Object.assign(indexedFixture, sourceState, {
    truthArtifact: {
      path: truthArtifactPath,
      fixtureDigestSha256: sourceState.fixtureDigestSha256,
      projectDigestSha256:
        sourceState.project.projectDigestSha256,
      evaluatorDigestSha256:
        sourceState.evaluator.evaluatorDigestSha256,
      layoutBindingSha256: sourceState.layoutBindingSha256,
    },
  });
  await fs.writeFile(
    sourceIndexPath,
    `${JSON.stringify(sourceIndex, null, 2)}\n`,
    "utf8",
  );

  const truthArtifactPathOnDisk = path.join(
    suiteDirectory,
    ...truthArtifactPath.split("/"),
  );
  const truthArtifact = JSON.parse(
    await fs.readFile(truthArtifactPathOnDisk, "utf8"),
  ) as {
    data: {
      manifest: unknown;
      truth: unknown;
      sourceState: unknown;
      binding: Record<string, unknown>;
    };
  };
  truthArtifact.data.sourceState = sourceState;
  Object.assign(truthArtifact.data.binding, {
    sourceStateSha256: sha256(canonicalJson(sourceState)),
    fixtureDigestSha256: sourceState.fixtureDigestSha256,
    projectRoot: sourceState.project.root,
    projectDigestSha256:
      sourceState.project.projectDigestSha256,
    evaluatorDigestSha256:
      sourceState.evaluator.evaluatorDigestSha256,
    layoutBindingSha256: sourceState.layoutBindingSha256,
    subjectDigestSha256:
      sourceState.subject.subjectDigestSha256,
    subjectFixtureBindingSha256:
      sourceState.subject.fixtureBindingSha256,
  });
  await fs.writeFile(
    truthArtifactPathOnDisk,
    `${JSON.stringify(truthArtifact, null, 2)}\n`,
    "utf8",
  );
  const truthArtifactSha256 = sha256(
    await fs.readFile(truthArtifactPathOnDisk),
  );

  const evaluationPath = path.join(suiteDirectory, "evaluation.json");
  const evaluation = JSON.parse(
    await fs.readFile(evaluationPath, "utf8"),
  ) as {
    data: {
      runs: Array<{
        cases: Array<{
          fixtureId: string;
          truthArtifact: {
            sha256: string;
            fixtureDigestSha256: string;
          };
        }>;
      }>;
    };
  };
  for (const run of evaluation.data.runs) {
    const evaluationCase = run.cases.find(
      (candidate) => candidate.fixtureId === fixtureId,
    );
    assert.ok(evaluationCase, `missing evaluation fixture ${fixtureId}`);
    evaluationCase.truthArtifact.sha256 = truthArtifactSha256;
    evaluationCase.truthArtifact.fixtureDigestSha256 =
      sourceState.fixtureDigestSha256;
  }
  await fs.writeFile(
    evaluationPath,
    `${JSON.stringify(evaluation, null, 2)}\n`,
    "utf8",
  );

  for (const mode of MODES) {
    const runDirectory = path.join(
      suiteDirectory,
      "runs",
      fixtureId,
      mode,
    );
    const sourceStatePath = path.join(
      runDirectory,
      "source-state.json",
    );
    await writeWrapped(sourceStatePath, sourceState);
    const sourceStateContent = await fs.readFile(sourceStatePath);
    const manifestPath = path.join(runDirectory, "run-manifest.json");
    const manifest = JSON.parse(
      await fs.readFile(manifestPath, "utf8"),
    ) as Record<string, unknown>;
    manifest.sourceState = sourceState;
    const metadata = manifest.metadata as Record<string, unknown>;
    metadata.truthArtifact = {
      fixtureId,
      path: truthArtifactPath,
      fixtureDigestSha256: sourceState.fixtureDigestSha256,
      projectRoot: sourceState.project.root,
      projectDigestSha256:
        sourceState.project.projectDigestSha256,
      evaluatorDigestSha256:
        sourceState.evaluator.evaluatorDigestSha256,
      layoutBindingSha256: sourceState.layoutBindingSha256,
    };
    metadata.projectSnapshot = {
      root: sourceState.project.root,
      projectDigestSha256:
        sourceState.project.projectDigestSha256,
      evaluatorDigestSha256:
        sourceState.evaluator.evaluatorDigestSha256,
      layoutBindingSha256: sourceState.layoutBindingSha256,
    };
    metadata.subjectSnapshot = {
      subjectDigestSha256:
        sourceState.subject.subjectDigestSha256,
      fixtureBindingSha256:
        sourceState.subject.fixtureBindingSha256,
    };
    const artifacts = manifest.artifacts as Array<{
      path: string;
      bytes: number;
      sha256: string;
    }>;
    const sourceStateArtifact = artifacts.find(
      (candidate) => candidate.path === "source-state.json",
    );
    assert.ok(sourceStateArtifact);
    sourceStateArtifact.bytes = sourceStateContent.byteLength;
    sourceStateArtifact.sha256 = sha256(sourceStateContent);
    await writeRehashedRunManifest(
      suiteDirectory,
      mode,
      manifest,
      fixtureId,
    );
  }

  await rehashSuiteArtifact(suiteDirectory, "source-index.json");
  await rehashSuiteArtifact(suiteDirectory, "evaluation.json");
  await rehashSuiteArtifact(suiteDirectory, truthArtifactPath);

  const suiteIndexPath = path.join(suiteDirectory, "suite-index.json");
  const suiteIndex = JSON.parse(
    await fs.readFile(suiteIndexPath, "utf8"),
  ) as {
    fixtureTruth: Array<Record<string, unknown>>;
    indexSha256: string;
    [key: string]: unknown;
  };
  const fixtureTruth = suiteIndex.fixtureTruth.find(
    (candidate) => candidate.fixtureId === fixtureId,
  );
  assert.ok(fixtureTruth, `missing suite fixtureTruth ${fixtureId}`);
  Object.assign(fixtureTruth, {
    artifactSha256: truthArtifactSha256,
    fixtureDigestSha256: sourceState.fixtureDigestSha256,
    projectRoot: sourceState.project.root,
    projectDigestSha256:
      sourceState.project.projectDigestSha256,
    evaluatorDigestSha256:
      sourceState.evaluator.evaluatorDigestSha256,
    layoutBindingSha256: sourceState.layoutBindingSha256,
  });
  suiteIndex.indexSha256 = sha256(
    canonicalJson(withoutTestProperty(suiteIndex, "indexSha256")),
  );
  await fs.writeFile(
    suiteIndexPath,
    `${JSON.stringify(suiteIndex, null, 2)}\n`,
    "utf8",
  );
}

function rebuildStructuralSourceState(
  current: ReturnType<typeof syntheticFixtureContext>["sourceState"],
  files: SyntheticFileRecord[],
): ReturnType<typeof syntheticFixtureContext>["sourceState"] {
  const projectPrefix = "project/";
  const projectFiles = files
    .filter((entry) => entry.path.startsWith(projectPrefix))
    .map((entry) => ({
      ...entry,
      path: entry.path.slice(projectPrefix.length),
    }));
  const evaluatorFiles = files
    .filter((entry) => !entry.path.startsWith(projectPrefix))
    .map((entry) => ({ ...entry }));
  const fixtureDigestSha256 = sha256(prettyCanonicalJson(files));
  const projectDigestSha256 = sha256(
    prettyCanonicalJson(projectFiles),
  );
  const evaluatorDigestSha256 = sha256(
    prettyCanonicalJson(evaluatorFiles),
  );
  const layoutBindingSha256 = sha256(
    canonicalJson({
      projectRoot: "project",
      fixtureDigestSha256,
      projectDigestSha256,
      evaluatorDigestSha256,
    }),
  );
  return {
    schemaVersion: "2.0",
    fixtureId: current.fixtureId,
    pairId: current.pairId,
    variant: current.variant,
    language: current.language,
    files,
    fixtureDigestSha256,
    project: {
      root: "project",
      files: projectFiles,
      projectDigestSha256,
    },
    evaluator: {
      files: evaluatorFiles,
      evaluatorDigestSha256,
    },
    layoutBindingSha256,
    subject: {
      files: projectFiles.map((entry) => ({ ...entry })),
      subjectDigestSha256: projectDigestSha256,
      excludedControlFiles: evaluatorFiles.map(
        (entry) => entry.path,
      ),
      fixtureBindingSha256: layoutBindingSha256,
    },
  };
}

async function mutateEvaluation(
  suiteDirectory: string,
  mutate: (evaluation: SyntheticEvaluationDocument["data"]) => void,
): Promise<void> {
  const evaluationPath = path.join(suiteDirectory, "evaluation.json");
  const document = JSON.parse(
    await fs.readFile(evaluationPath, "utf8"),
  ) as SyntheticEvaluationDocument;
  mutate(document.data);
  await fs.writeFile(
    evaluationPath,
    `${JSON.stringify(document, null, 2)}\n`,
    "utf8",
  );
  await rehashSuiteArtifact(suiteDirectory, "evaluation.json");
}

function applyMatchMetrics(
  run: SyntheticEvaluationRun,
  match: SyntheticMatchResult,
): void {
  const metricsByClass = computeVulnerabilityClassMetrics(match);
  const metrics = applyGroupedF1(
    computeSuiteMetrics([match]),
    metricsByClass,
  );
  const classSummary = computeGroupedMetricSummary(metricsByClass);
  const evaluationCase = run.cases[0]!;
  evaluationCase.matchResult = structuredClone(match);
  evaluationCase.metrics = structuredClone(metrics);
  evaluationCase.metricsByClass = structuredClone(metricsByClass);
  evaluationCase.classSummary = structuredClone(classSummary);
  run.matchResults = [structuredClone(match)];
  run.metrics = structuredClone(metrics);
  run.metricsByClass = structuredClone(metricsByClass);
  run.classSummary = structuredClone(classSummary);
}

async function mutateRunArtifact(
  suiteDirectory: string,
  mode: Mode,
  artifactName: string,
  mutate: (data: unknown) => void,
  fixtureId = "fixture-vulnerable",
): Promise<void> {
  const runDirectory = path.join(
    suiteDirectory,
    "runs",
    fixtureId,
    mode,
  );
  const artifactPath = path.join(runDirectory, artifactName);
  const document = JSON.parse(
    await fs.readFile(artifactPath, "utf8"),
  ) as { data: unknown };
  mutate(document.data);
  await fs.writeFile(
    artifactPath,
    `${JSON.stringify(document, null, 2)}\n`,
    "utf8",
  );
  const manifestPath = path.join(runDirectory, "run-manifest.json");
  const manifest = JSON.parse(
    await fs.readFile(manifestPath, "utf8"),
  ) as {
    artifacts: Array<{ path: string; bytes: number; sha256: string }>;
    [key: string]: unknown;
  };
  const artifact = manifest.artifacts.find(
    (candidate) => candidate.path === artifactName,
  );
  assert.ok(artifact);
  const content = await fs.readFile(artifactPath);
  artifact.bytes = content.byteLength;
  artifact.sha256 = sha256(content);
  await writeRehashedRunManifest(
    suiteDirectory,
    mode,
    manifest,
    fixtureId,
  );
}

function refreshProducerValidation(
  trace: Record<string, unknown>,
): void {
  const {
    producerValidation: _producerValidation,
    ...draftValue
  } = trace;
  const draft =
    draftValue as unknown as Omit<
      ResearchModelCallTrace,
      "producerValidation"
    >;
  draft.traceCompleteness = "complete";
  const initialErrors = validateModelCallTrace(draft);
  if (
    initialErrors.some(
      (error) =>
        error !== "model-call-trace-completeness-invalid",
    )
  ) {
    draft.traceCompleteness = "incomplete";
  }
  const errors = validateModelCallTrace(draft);
  trace.traceCompleteness = draft.traceCompleteness;
  trace.producerValidation = {
    valid: errors.length === 0,
    errors,
  };
}

async function mutateRunManifest(
  suiteDirectory: string,
  mode: Mode,
  mutate: (manifest: Record<string, unknown>) => void,
  fixtureId = "fixture-vulnerable",
): Promise<void> {
  const manifestPath = path.join(
    suiteDirectory,
    "runs",
    fixtureId,
    mode,
    "run-manifest.json",
  );
  const manifest = JSON.parse(
    await fs.readFile(manifestPath, "utf8"),
  ) as Record<string, unknown>;
  mutate(manifest);
  await writeRehashedRunManifest(
    suiteDirectory,
    mode,
    manifest,
    fixtureId,
  );
}

async function writeRehashedRunManifest(
  suiteDirectory: string,
  mode: Mode,
  manifest: Record<string, unknown>,
  fixtureId = "fixture-vulnerable",
): Promise<void> {
  const relativeManifestPath =
    `runs/${fixtureId}/${mode}/run-manifest.json`;
  const manifestPath = path.join(
    suiteDirectory,
    ...relativeManifestPath.split("/"),
  );
  manifest.manifestSha256 = sha256(
    canonicalJson(withoutTestProperty(manifest, "manifestSha256")),
  );
  await fs.writeFile(
    manifestPath,
    `${JSON.stringify(manifest, null, 2)}\n`,
    "utf8",
  );
  const indexPath = path.join(suiteDirectory, "suite-index.json");
  const index = JSON.parse(
    await fs.readFile(indexPath, "utf8"),
  ) as {
    runs: Array<{ path: string; manifestSha256: string }>;
    indexSha256: string;
    [key: string]: unknown;
  };
  const binding = index.runs.find(
    (candidate) => candidate.path === relativeManifestPath,
  );
  assert.ok(binding);
  binding.manifestSha256 = manifest.manifestSha256 as string;
  index.indexSha256 = sha256(
    canonicalJson(withoutTestProperty(index, "indexSha256")),
  );
  await fs.writeFile(indexPath, `${JSON.stringify(index, null, 2)}\n`, "utf8");
}

function withoutTestProperty(
  value: Record<string, unknown>,
  property: string,
): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(value).filter(([key]) => key !== property),
  );
}

async function writeSyntheticSuite(
  suiteDirectory: string,
  _localRoot: string,
  options: {
    execution?: "mock" | "replay" | "live";
    statusByMode?: Partial<Record<Mode, CellStatus>>;
    forceCompleteModes?: ReadonlySet<Mode>;
    claimedCostDeltaMode?: "single-agent" | "moa-low" | "moa-high";
    liveCallsByMode?: Partial<
      Record<PhysicalAgentMode, readonly LiveCall[]>
    >;
    candidateCountByMode?: Partial<
      Record<PhysicalAgentMode, number>
    >;
    manifestModelsByMode?: Partial<Record<Mode, readonly string[]>>;
    fixtureIds?: readonly string[];
    statusByFixtureMode?: Readonly<
      Record<string, Partial<Record<Mode, CellStatus>>>
    >;
    forceCompleteCells?: ReadonlySet<string>;
    evaluatorControlFiles?: readonly string[];
    additionalProjectFiles?: readonly string[];
  } = {},
): Promise<void> {
  await fs.mkdir(suiteDirectory, { recursive: true });
  const execution = options.execution ?? "mock";
  const suiteId = "synthetic-seven-mode";
  const fixtureIds = [
    ...(options.fixtureIds ?? ["fixture-vulnerable"]),
  ].sort();
  assert.ok(fixtureIds.length > 0);
  assert.equal(new Set(fixtureIds).size, fixtureIds.length);
  const fixtures = fixtureIds.map((fixtureId, index) =>
    syntheticFixtureContext(fixtureId, index, {
      ...(options.evaluatorControlFiles
        ? { evaluatorControlFiles: options.evaluatorControlFiles }
        : {}),
      ...(options.additionalProjectFiles
        ? { additionalProjectFiles: options.additionalProjectFiles }
        : {}),
    }),
  );
  for (const fixture of fixtures) {
    await fs.mkdir(
      path.join(suiteDirectory, "truth", fixture.fixtureId),
      { recursive: true },
    );
    await writeWrapped(
      path.join(suiteDirectory, fixture.truthArtifactPath),
      {
        schemaVersion: "1.0",
        fixtureId: fixture.fixtureId,
        pairId: fixture.pairId,
        variant: "vulnerable",
        manifest: fixture.manifest,
        truth: fixture.truth,
        sourceState: fixture.sourceState,
        binding: {
          manifestSha256: sha256(canonicalJson(fixture.manifest)),
          truthSha256: sha256(canonicalJson(fixture.truth)),
          sourceStateSha256: sha256(
            canonicalJson(fixture.sourceState),
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
            fixture.sourceState.subject.subjectDigestSha256,
          subjectFixtureBindingSha256:
            fixture.sourceState.subject.fixtureBindingSha256,
        },
      },
    );
    fixture.truthArtifactSha256 = sha256(
      await fs.readFile(
        path.join(suiteDirectory, fixture.truthArtifactPath),
      ),
    );
  }
  const immutableFindings = immutableActualFindings();
  const modelCallsByMode =
    execution === "live"
      ? await writeLiveLedger(
          suiteDirectory,
          fixtureIds,
          options.liveCallsByMode,
          options.candidateCountByMode,
        )
      : buildNonLiveModelCalls(
          execution,
          options.liveCallsByMode,
          options.candidateCountByMode,
        );
  if (execution !== "live") {
    await fs.writeFile(path.join(suiteDirectory, "cost-ledger.jsonl"), "");
  }
  const cells: Array<Record<string, unknown>> = [];
  const manifestPaths: string[] = [];

  for (const fixture of fixtures) {
    for (const mode of MODES) {
      const status =
        options.statusByFixtureMode?.[fixture.fixtureId]?.[mode] ??
        options.statusByMode?.[mode] ??
        "success";
      const forceComplete =
        options.forceCompleteCells?.has(
          `${fixture.fixtureId}\u0000${mode}`,
        ) ??
        options.forceCompleteModes?.has(mode) ??
        false;
      const cost = cellCost(
        mode,
        execution,
        options.claimedCostDeltaMode,
        options.liveCallsByMode,
        options.candidateCountByMode,
      );
      const completenessInput = completenessInputFor(
        status,
        forceComplete,
      );
      const degradationReasons =
        status === "success" || forceComplete
          ? []
          : [`${status} evidence`];
      const runId =
        fixtures.length === 1
          ? `run-${mode}`
          : `run-${fixture.fixtureId}-${mode}`;
      const derivedFrom = hybridSources(mode);
      const physical = isPhysical(mode);
      const runDirectory = path.join(
        suiteDirectory,
        "runs",
        fixture.fixtureId,
        mode,
      );
      await fs.mkdir(runDirectory, { recursive: true });
      const result = {
        schemaVersion: "1.0",
        runId,
        fixtureId: fixture.fixtureId,
        pairId: fixture.pairId,
        fixtureVariant: "vulnerable",
        mode,
        execution,
        physical,
        derivedFrom,
        status,
        findings: immutableFindings,
        degradationReasons,
        startedAt: "2026-07-25T00:00:00.000Z",
        finishedAt: "2026-07-25T00:00:01.000Z",
      };
      const artifactPaths = [
        "result.json",
        "detector-evidence.json",
        "completeness.json",
        "cost.json",
        "source-state.json",
        "model-calls.json",
      ];
      const candidateCount =
        mode === "single-agent" ||
        mode === "moa-low" ||
        mode === "moa-high"
          ? (options.candidateCountByMode?.[mode] ?? 1)
          : 0;
      const cellModelCalls =
        mode === "single-agent" ||
        mode === "moa-low" ||
        mode === "moa-high"
          ? (modelCallsByMode.get(
              execution === "live"
                ? `${fixture.fixtureId}\u0000${mode}`
                : mode,
            ) ?? [])
          : [];
      const modelCallTrace = modelCallTraceForCell({
        mode,
        execution,
        status,
        runId,
        fixtureId: fixture.fixtureId,
        fixtureDigestSha256:
          fixture.sourceState.fixtureDigestSha256,
        derivedFrom,
        physical,
        candidateCount,
        calls: cellModelCalls,
      });
      await Promise.all([
        writeWrapped(path.join(runDirectory, "result.json"), result),
        writeWrapped(path.join(runDirectory, "detector-evidence.json"), {
          schemaVersion: "1.0",
          rawScannerFindings: [],
          rawAgentFindings: [],
          ...(physical && mode !== "scanner-only"
            ? {
                agentEvidence: syntheticAgentEvidence({
                  mode: mode as PhysicalAgentMode,
                  runId,
                  status: modelCallTrace.detectorStatus,
                  candidateCount,
                  calls: cellModelCalls,
                }),
              }
            : {}),
          finalFindings: immutableFindings,
        }),
        writeWrapped(
          path.join(runDirectory, "completeness.json"),
          completenessInput,
        ),
        writeWrapped(path.join(runDirectory, "cost.json"), cost),
        writeWrapped(
          path.join(runDirectory, "source-state.json"),
          fixture.sourceState,
        ),
        writeWrapped(
          path.join(runDirectory, "model-calls.json"),
          modelCallTrace,
        ),
      ]);
      await createRunManifest(runDirectory, {
        runId,
        suite: suiteId,
        mode,
        execution,
        status,
        startedAt: result.startedAt,
        finishedAt: result.finishedAt,
        harnessVersion: "synthetic-harness-v1",
        promptVersion: "synthetic-prompt-v1",
        sourceState: fixture.sourceState,
        limits: {
          capability: mode,
          globalBudgetUsd: GLOBAL_BUDGET_USD,
          modeBudgetUsd: MODE_BUDGET_USD[mode],
          noModelFallback: true,
        },
        models: manifestModelsForMode(mode, options).map((model) => ({
          provider: "openrouter",
          model,
        })),
        metadata: {
          fixtureId: fixture.fixtureId,
          pairId: fixture.pairId,
          fixtureVariant: "vulnerable",
          physical,
          derivedFrom,
          modelCallTraceSchemaVersion: "1.0",
          modelCallTraceRolePlanVersion: "1.0",
          modelCallTraceCassettePolicy:
            modelCallTrace.cassettePolicy,
          subjectSnapshotSchemaVersion: "2.0",
          projectSnapshotSchemaVersion: "1.0",
          truthArtifact: {
            fixtureId: fixture.fixtureId,
            path: fixture.truthArtifactPath,
            fixtureDigestSha256:
              fixture.sourceState.fixtureDigestSha256,
            projectRoot: fixture.sourceState.project.root,
            projectDigestSha256:
              fixture.sourceState.project.projectDigestSha256,
            evaluatorDigestSha256:
              fixture.sourceState.evaluator.evaluatorDigestSha256,
            layoutBindingSha256:
              fixture.sourceState.layoutBindingSha256,
          },
          projectSnapshot: {
            root: fixture.sourceState.project.root,
            projectDigestSha256:
              fixture.sourceState.project.projectDigestSha256,
            evaluatorDigestSha256:
              fixture.sourceState.evaluator.evaluatorDigestSha256,
            layoutBindingSha256:
              fixture.sourceState.layoutBindingSha256,
          },
          subjectSnapshot: {
            subjectDigestSha256:
              fixture.sourceState.subject.subjectDigestSha256,
            fixtureBindingSha256:
              fixture.sourceState.subject.fixtureBindingSha256,
          },
          cost,
          degradationReasons,
        },
        artifactPaths,
      });
      const manifestPath =
        `runs/${fixture.fixtureId}/${mode}/run-manifest.json`;
      manifestPaths.push(manifestPath);
      cells.push({
        runId,
        fixtureId: fixture.fixtureId,
        mode,
        status,
        physical,
        derivedFrom,
        cost,
        manifestPath,
      });
    }
  }

  const attributedModeCostUsd = Object.fromEntries(
    MODES.map((mode) => [
      mode,
      cells
        .filter((cell) => cell.mode === mode)
        .reduce(
          (total, cell) =>
            total +
            (cell.cost as { attributedCostUsd: number })
              .attributedCostUsd,
          0,
        ),
    ]),
  );
  const physicalCells = cells.filter((cell) => cell.physical === true);
  const summary = {
    schemaVersion: "1.0",
    suiteId,
    execution,
    fixtureIds,
    modes: [...MODES],
    physicalExecutions: {
      scanners: fixtures.length,
      agents: fixtures.length * 3,
      derivedHybrids: fixtures.length * 3,
    },
    actualPhysicalSpendUsd: physicalCells.reduce(
      (total, cell) =>
        total +
        (cell.cost as { actualPhysicalSpendUsd: number })
          .actualPhysicalSpendUsd,
      0,
    ),
    conservativeCommittedUsd: physicalCells.reduce(
      (total, cell) =>
        total +
        (cell.cost as { conservativeCommittedUsd: number })
          .conservativeCommittedUsd,
      0,
    ),
    attributedModeCostUsd,
    cells,
  };
  const evaluation = {
    schemaVersion: "1.0",
    suiteId,
    runs: MODES.map((mode) => {
      const cases = fixtures.map((fixture) => {
        const status =
          options.statusByFixtureMode?.[fixture.fixtureId]?.[mode] ??
          options.statusByMode?.[mode] ??
          "success";
        const forceComplete =
          options.forceCompleteCells?.has(
            `${fixture.fixtureId}\u0000${mode}`,
          ) ??
          options.forceCompleteModes?.has(mode) ??
          false;
        const matchResult = authoritativeMatchResult();
        return {
          fixtureId: fixture.fixtureId,
          fixtureRoot: `fixture://${encodeURIComponent(
            fixture.fixtureId,
          )}`,
          ignoredSecret: "sk-or-v1-not-for-output",
          manifest: fixture.manifest,
          truth: fixture.truth,
          truthArtifact: {
            fixtureId: fixture.fixtureId,
            path: fixture.truthArtifactPath,
            sha256: fixture.truthArtifactSha256,
            fixtureDigestSha256:
              fixture.sourceState.fixtureDigestSha256,
          },
          matchResult,
          metrics: overallMetrics(),
          metricsByClass: classMetrics(),
          classSummary: classSummary(),
          completenessInput: completenessInputFor(
            status,
            forceComplete,
          ),
          completeness: computedCompleteness(
            status,
            forceComplete,
            false,
          ),
        };
      });
      const matchResults = cases.map((entry) => entry.matchResult);
      const runMetrics = authoritativeMetrics(matchResults);
      return {
        runId: `evaluation-${mode}`,
        mode,
        costUsd: attributedModeCostUsd[mode],
        totalTokens: cells
          .filter((cell) => cell.mode === mode)
          .reduce(
            (total, cell) =>
              total +
              (cell.cost as { attributedTokens: number })
                .attributedTokens,
            0,
          ),
        cases,
        matchResults,
        metrics: runMetrics.metrics,
        metricsByClass: runMetrics.metricsByClass,
        classSummary: runMetrics.classSummary,
        completeness: aggregateSyntheticCompleteness(
          cases.map((entry) => ({
            fixtureId: entry.fixtureId,
            input: entry.completenessInput,
          })),
        ),
      };
    }),
    comparisons: {},
  };

  await Promise.all([
    writeWrapped(path.join(suiteDirectory, "experiment-summary.json"), summary),
    writeWrapped(path.join(suiteDirectory, "evaluation.json"), evaluation),
    writeWrapped(path.join(suiteDirectory, "source-index.json"), {
      schemaVersion: "1.0",
      suiteId,
      fixtures: fixtures.map((fixture) => ({
          ...fixture.sourceState,
          truthArtifact: {
            path: fixture.truthArtifactPath,
            fixtureDigestSha256:
              fixture.sourceState.fixtureDigestSha256,
            projectDigestSha256:
              fixture.sourceState.project.projectDigestSha256,
            evaluatorDigestSha256:
              fixture.sourceState.evaluator.evaluatorDigestSha256,
            layoutBindingSha256:
              fixture.sourceState.layoutBindingSha256,
          },
        })),
    }),
  ]);
  await createSuiteIndex(suiteDirectory, {
    suiteId,
    createdAt: "2026-07-25T00:00:02.000Z",
    runManifestPaths: manifestPaths,
    artifactPaths: [
      "evaluation.json",
      "source-index.json",
      "experiment-summary.json",
      "cost-ledger.jsonl",
      ...fixtures.map((fixture) => fixture.truthArtifactPath),
    ],
    fixtureTruth: fixtures.map((fixture) => ({
        fixtureId: fixture.fixtureId,
        pairId: fixture.pairId,
        variant: "vulnerable",
        path: fixture.truthArtifactPath,
        fixtureDigestSha256:
          fixture.sourceState.fixtureDigestSha256,
        projectRoot: fixture.sourceState.project.root,
        projectDigestSha256:
          fixture.sourceState.project.projectDigestSha256,
        evaluatorDigestSha256:
          fixture.sourceState.evaluator.evaluatorDigestSha256,
        layoutBindingSha256:
          fixture.sourceState.layoutBindingSha256,
      })),
  });
}

function syntheticFixtureContext(
  fixtureId: string,
  index: number,
  options: {
    evaluatorControlFiles?: readonly string[];
    additionalProjectFiles?: readonly string[];
  } = {},
) {
  const pairId = index === 0 ? "fixture-pair" : `fixture-pair-${index + 1}`;
  const evaluatorFiles = [
    ...new Set([
      ...(options.evaluatorControlFiles ?? []),
      "truth.json",
    ]),
  ].sort();
  const manifest = {
    ...authoritativeFixtureManifest(),
    id: fixtureId,
    pairId,
    pairedFixtureId: `${fixtureId}-clean`,
    evaluatorFiles,
  };
  const truth = {
    ...authoritativeTruthSet(),
    fixtureId,
  };
  const fixtureSource = `${JSON.stringify(manifest, null, 2)}\n`;
  const truthSource = `${JSON.stringify(truth, null, 2)}\n`;
  const projectPaths = [
    ...new Set([
      "project-data/truth.json",
      "src/index.js",
      ...(options.additionalProjectFiles ?? []),
    ]),
  ].sort();
  const files = [
    {
      path: "fixture.json",
      bytes: Buffer.byteLength(fixtureSource),
      sha256: sha256(fixtureSource),
    },
    ...projectPaths.map((projectPath) => {
      const content = `synthetic-project-${fixtureId}-${projectPath}`;
      return {
        path: `project/${projectPath}`,
        bytes: Buffer.byteLength(content),
        sha256: sha256(content),
      };
    }),
    ...evaluatorFiles.map((evaluatorPath) => {
      const content =
        evaluatorPath === "truth.json"
          ? truthSource
          : `synthetic-evaluator-${fixtureId}-${evaluatorPath}`;
      return {
        path: evaluatorPath,
        bytes: Buffer.byteLength(content),
        sha256: sha256(content),
      };
    }),
  ].sort((left, right) => left.path.localeCompare(right.path));
  const fixtureDigestSha256 = sha256(prettyCanonicalJson(files));
  const projectFiles = files
    .filter((entry) => entry.path.startsWith("project/"))
    .map((entry) => ({
      ...entry,
      path: entry.path.slice("project/".length),
    }));
  const evaluatorFileRecords = files
    .filter((entry) => !entry.path.startsWith("project/"))
    .map((entry) => ({ ...entry }));
  const projectDigestSha256 = sha256(
    prettyCanonicalJson(projectFiles),
  );
  const evaluatorDigestSha256 = sha256(
    prettyCanonicalJson(evaluatorFileRecords),
  );
  const layoutBindingSha256 = sha256(
    canonicalJson({
      projectRoot: "project",
      fixtureDigestSha256,
      projectDigestSha256,
      evaluatorDigestSha256,
    }),
  );
  const sourceState = {
    schemaVersion: "2.0",
    fixtureId,
    pairId,
    variant: "vulnerable" as const,
    language: "javascript",
    files,
    fixtureDigestSha256,
    project: {
      root: "project" as const,
      files: projectFiles,
      projectDigestSha256,
    },
    evaluator: {
      files: evaluatorFileRecords,
      evaluatorDigestSha256,
    },
    layoutBindingSha256,
    subject: {
      files: projectFiles.map((entry) => ({ ...entry })),
      subjectDigestSha256: projectDigestSha256,
      excludedControlFiles: evaluatorFileRecords.map(
        (entry) => entry.path,
      ),
      fixtureBindingSha256: layoutBindingSha256,
    },
  };
  return {
    fixtureId,
    pairId,
    manifest,
    truth,
    sourceState,
    truthArtifactPath: `truth/${fixtureId}/truth-evidence.json`,
    truthArtifactSha256: "",
  };
}

function aggregateSyntheticCompleteness(
  cases: ReadonlyArray<{
    fixtureId: string;
    input: ReturnType<typeof completenessInputFor>;
  }>,
) {
  const plannedComponents = cases.flatMap((entry) =>
    entry.input.plannedComponents.map(
      (component) => `${entry.fixtureId}:${component}`,
    ),
  );
  const completedComponents = cases.flatMap((entry) =>
    entry.input.completedComponents.map(
      (component) => `${entry.fixtureId}:${component}`,
    ),
  );
  const failedComponents = cases.flatMap((entry) =>
    entry.input.failedComponents.map(
      (component) => `${entry.fixtureId}:${component}`,
    ),
  );
  const skippedComponents = cases.flatMap((entry) =>
    entry.input.skippedComponents.map(
      (component) => `${entry.fixtureId}:${component}`,
    ),
  );
  const degradedReasons = cases.flatMap((entry) =>
    entry.input.degradedReasons.map(
      (reason) => `${entry.fixtureId}:${reason}`,
    ),
  );
  const status =
    failedComponents.length > 0 || degradedReasons.length > 0
      ? "degraded"
      : completedComponents.length < plannedComponents.length
        ? "partial"
        : "complete";
  const eligibleFiles = cases.reduce(
    (total, entry) => total + entry.input.eligibleFiles,
    0,
  );
  const inspectedFiles = cases.reduce(
    (total, entry) => total + entry.input.inspectedFiles,
    0,
  );
  return {
    status,
    plannedComponentCount: plannedComponents.length,
    completedComponentCount: completedComponents.length,
    failedComponents,
    skippedComponents,
    componentCompletionRate:
      plannedComponents.length === 0
        ? 1
        : completedComponents.length / plannedComponents.length,
    eligibleFiles,
    inspectedFiles,
    fileCoverage:
      eligibleFiles === 0 ? 1 : inspectedFiles / eligibleFiles,
    inspectedBytes: cases.reduce(
      (total, entry) => total + entry.input.inspectedBytes,
      0,
    ),
    unsupportedLanguages: [],
    degradedReasons,
  };
}

async function writeLiveLedger(
  suiteDirectory: string,
  fixtureIds: readonly string[],
  callsByMode:
    | Partial<Record<PhysicalAgentMode, readonly LiveCall[]>>
    | undefined,
  candidateCountByMode:
    | Partial<Record<PhysicalAgentMode, number>>
    | undefined,
): Promise<Map<string, Array<Record<string, unknown>>>> {
  const ledger = new CostLedger(path.join(suiteDirectory, "cost-ledger.jsonl"));
  const traces = new Map<
    string,
    Array<Record<string, unknown>>
  >();
  for (const fixtureId of fixtureIds) {
  for (const mode of ["single-agent", "moa-low", "moa-high"] as const) {
    const modeTrace: Array<Record<string, unknown>> = [];
    for (const [callIndex, call] of callsForMode(
      mode,
      callsByMode,
      candidateCountByMode,
    ).entries()) {
      const status = call.status ?? "settled";
      const reservation = await ledger.reserve({
        runId:
          fixtureIds.length === 1
            ? `run-${mode}`
            : `run-${fixtureId}-${mode}`,
        mode,
        provider: "openrouter",
        model: call.model,
        amountNanoUsd: call.costNanoUsd,
        globalLimitNanoUsd: GLOBAL_BUDGET_USD * 1_000_000_000,
        modeLimitNanoUsd: MODE_BUDGET_USD[mode] * 1_000_000_000,
        requestFingerprint: sha256(`${mode}:request:${callIndex}`),
        pricingCatalogDigestSha256: "d".repeat(64),
      });
      if (status === "settled") {
        await ledger.settle(reservation.reservationId, {
          actualNanoUsd: call.costNanoUsd,
          promptTokens: Math.floor(call.tokens / 2),
          completionTokens: Math.ceil(call.tokens / 2),
          costSource: "provider-authoritative",
        });
      } else if (status === "failed") {
        await ledger.markFailed(
          reservation.reservationId,
          "synthetic provider failure",
        );
      } else {
        await ledger.markUnknown(
          reservation.reservationId,
          "synthetic provider outcome unknown",
        );
      }
      const completed = status === "settled";
      modeTrace.push({
        ordinal: callIndex + 1,
        role: call.role,
        gapFill: false,
        provider: "openrouter",
        model: call.model,
        requestFingerprint: sha256(`${mode}:request:${callIndex}`),
        fingerprintSource: "metered-replay",
        terminalState: completed ? "succeeded" : "failed",
        ...(completed
          ? {
              responseProvider: "openrouter",
              responseModel: call.model,
            }
          : {
              errorCategory:
                status === "failed" ? "provider" : "unknown",
            }),
      });
    }
    traces.set(`${fixtureId}\u0000${mode}`, modeTrace);
  }
  }
  return traces;
}

function buildNonLiveModelCalls(
  _execution: "mock" | "replay",
  callsByMode:
    | Partial<Record<PhysicalAgentMode, readonly LiveCall[]>>
    | undefined,
  candidateCountByMode:
    | Partial<Record<PhysicalAgentMode, number>>
    | undefined,
): Map<string, Array<Record<string, unknown>>> {
  return new Map(
    (["single-agent", "moa-low", "moa-high"] as const).map((mode) => [
      mode,
      callsForMode(
        mode,
        callsByMode,
        candidateCountByMode,
      ).map((call, callIndex) => ({
        ordinal: callIndex + 1,
        role: call.role,
        gapFill: false,
        provider: "openrouter",
        model: call.model,
        requestFingerprint: sha256(`${mode}:request:${callIndex}`),
        fingerprintSource: "metered-replay",
        terminalState: "succeeded",
        responseProvider: "openrouter",
        responseModel: call.model,
      })),
    ]),
  );
}

function modelCallTraceForCell(input: {
  mode: Mode;
  execution: "mock" | "replay" | "live";
  status: CellStatus;
  runId: string;
  fixtureId: string;
  fixtureDigestSha256: string;
  derivedFrom: Mode[];
  physical: boolean;
  candidateCount: number;
  calls: Array<Record<string, unknown>>;
}) {
  const physicalAgent =
    input.physical && input.mode !== "scanner-only";
  const detectorStatus = physicalAgent
    ? input.status === "success"
      ? "completed"
      : input.status
    : input.status === "failed"
      ? "failed"
      : "not-applicable";
  const candidateCount = physicalAgent ? input.candidateCount : 0;
  const calls =
    physicalAgent && input.execution === "replay"
      ? input.calls.map((call) => {
          if (
            call.terminalState !== "succeeded" ||
            call.cassetteReference
          ) {
            return call;
          }
          const requestFingerprint = String(
            call.requestFingerprint,
          );
          return {
            ...call,
            cassetteReference: {
              requestFingerprint,
              occurrence: 1,
              relativePath: `${requestFingerprint}.000001.json`,
              integritySha256: sha256(
                `synthetic-cassette:${input.runId}:${requestFingerprint}`,
              ),
              scopeIdSha256: sha256(
                `hermsec-replay-scope\u0000${[
                  input.fixtureId,
                  input.fixtureDigestSha256,
                  "synthetic-harness-v1",
                  "synthetic-prompt-v1",
                  input.mode,
                ].join("\u0000")}`,
              ),
            },
          };
        })
      : input.calls;
  const requiredSpecialistRoles: Array<
    ResearchModelCallTrace["rolePlan"]["requiredSpecialistRoles"][number]
  > =
    input.mode === "single-agent"
      ? ["single-agent-inspector"]
      : input.mode === "moa-low"
        ? [
            "injection-and-execution",
            "identity-and-request-security",
            "sensitive-data-and-cryptography",
          ]
        : input.mode === "moa-high"
          ? [
              "injection-and-execution",
              "identity-and-request-security",
              "sensitive-data-and-cryptography",
              "dependencies-and-supply-chain",
              "platform-storage-and-deployment",
            ]
          : [];
  const draft: Omit<ResearchModelCallTrace, "producerValidation"> = {
    schemaVersion: "1.0",
    runId: input.runId,
    mode: input.mode,
    execution: input.execution,
    cassettePolicy:
      physicalAgent && input.execution === "replay"
        ? "replay"
        : "none",
    physical: input.physical,
    derivedFrom: input.derivedFrom,
    detectorStatus,
    candidateCount,
    aggregationDisposition:
      input.mode === "moa-low" || input.mode === "moa-high"
        ? candidateCount > 0
          ? "required"
          : "not-required-no-candidates"
        : "not-applicable",
    rolePlan: {
      status: physicalAgent ? "complete" : "not-applicable",
      requiredSpecialistRoles,
    },
    traceCompleteness: "complete",
    calls: (physicalAgent
      ? calls
      : []) as unknown as ResearchModelCallTrace["calls"],
  };
  const errors = validateModelCallTrace(draft);
  return {
    ...draft,
    producerValidation: {
      valid: errors.length === 0,
      errors,
    },
  };
}

function syntheticAgentEvidence(input: {
  mode: PhysicalAgentMode;
  runId: string;
  status:
    | "completed"
    | "partial"
    | "degraded"
    | "failed"
    | "canceled"
    | "not-applicable";
  candidateCount: number;
  calls: Array<Record<string, unknown>>;
}) {
  const requiredRoles =
    input.mode === "single-agent"
      ? (["single-agent-inspector"] as const)
      : input.mode === "moa-low"
        ? ([
            "injection-and-execution",
            "identity-and-request-security",
            "sensitive-data-and-cryptography",
          ] as const)
        : ([
            "injection-and-execution",
            "identity-and-request-security",
            "sensitive-data-and-cryptography",
            "dependencies-and-supply-chain",
            "platform-storage-and-deployment",
          ] as const);
  const roleStatus =
    input.status === "not-applicable" ? "failed" : input.status;
  return {
    runId: input.runId,
    mode: input.mode === "single-agent" ? "single" : input.mode,
    status: input.status,
    candidates: Array.from(
      { length: input.candidateCount },
      (_, index) => ({ candidateId: `candidate-${index + 1}` }),
    ),
    traces: [],
    coverage:
      input.mode === "single-agent"
        ? {
            kind: "single",
            totalFiles: 1,
            inspectedFiles: ["src/index.js"],
            uninspectedFiles: [],
            coverageRatio: 1,
          }
        : {
            kind: "moa",
            initial: {},
            final: {},
            gapFillExecuted: false,
          },
    roles: requiredRoles.map((role) => ({
      role,
      label: role,
      gapFill: false,
      status: roleStatus,
      candidateIds: [],
      inspectedFiles: ["src/index.js"],
      coveredCategories: [],
      rounds: input.calls.filter((call) => call.role === role).length,
      toolCalls: 0,
      limitations: [],
    })),
    abstentions: [],
    ...(input.mode !== "single-agent" && input.candidateCount > 0
      ? { judgments: [], groups: [] }
      : {}),
  };
}

function cellCost(
  mode: Mode,
  execution: "mock" | "replay" | "live",
  claimedCostDeltaMode: "single-agent" | "moa-low" | "moa-high" | undefined,
  callsByMode:
    | Partial<Record<PhysicalAgentMode, readonly LiveCall[]>>
    | undefined,
  candidateCountByMode:
    | Partial<Record<PhysicalAgentMode, number>>
    | undefined,
) {
  const agentMode = agentModeFor(mode);
  const physical = isPhysical(mode);
  const callSpecs = agentMode
    ? callsForMode(agentMode, callsByMode, candidateCountByMode)
    : [];
  const actualCost =
    execution === "live" && agentMode
      ? callSpecs.reduce(
          (total, call) =>
            total +
            ((call.status ?? "settled") === "settled"
              ? call.costNanoUsd / 1_000_000_000
              : 0),
          0,
        ) +
        (claimedCostDeltaMode === agentMode ? 0.001 : 0)
      : 0;
  const committedCost =
    execution === "live" && agentMode
      ? callSpecs.reduce(
          (total, call) =>
            total +
            ((call.status ?? "settled") === "failed"
              ? 0
              : call.costNanoUsd / 1_000_000_000),
          0,
        ) +
        (claimedCostDeltaMode === agentMode ? 0.001 : 0)
      : 0;
  const completedCallSpecs =
    execution === "live"
      ? callSpecs.filter(
          (call) => (call.status ?? "settled") === "settled",
        )
      : callSpecs;
  const tokens = completedCallSpecs.reduce(
    (total, call) => total + call.tokens,
    0,
  );
  const calls = callSpecs.length;
  const attributedCost = Math.max(actualCost, committedCost);
  return {
    actualPhysicalSpendUsd:
      physical && agentMode && execution === "live" ? actualCost : 0,
    conservativeCommittedUsd:
      physical && agentMode && execution === "live" ? committedCost : 0,
    attributedCostUsd: attributedCost,
    physicalModelCalls: physical ? calls : 0,
    attributedModelCalls: calls,
    physicalTokens: physical ? tokens : 0,
    attributedTokens: tokens,
  };
}

function callsForMode(
  mode: PhysicalAgentMode,
  overrides:
    | Partial<Record<PhysicalAgentMode, readonly LiveCall[]>>
    | undefined,
  candidateCountByMode:
    | Partial<Record<PhysicalAgentMode, number>>
    | undefined,
): readonly LiveCall[] {
  const calls = overrides?.[mode] ?? DEFAULT_LIVE_CALLS[mode];
  if (
    mode !== "single-agent" &&
    (candidateCountByMode?.[mode] ?? 1) === 0
  ) {
    return calls.filter(
      (call) =>
        call.role !== "moa-judge" &&
        call.role !== "moa-aggregator",
    );
  }
  return calls;
}

function manifestModelsForMode(
  mode: Mode,
  options: {
    liveCallsByMode?: Partial<
      Record<PhysicalAgentMode, readonly LiveCall[]>
    >;
    candidateCountByMode?: Partial<
      Record<PhysicalAgentMode, number>
    >;
    manifestModelsByMode?: Partial<Record<Mode, readonly string[]>>;
  },
): string[] {
  const explicit = options.manifestModelsByMode?.[mode];
  if (explicit) {
    return [...explicit];
  }
  const agentMode = agentModeFor(mode);
  return agentMode
    ? [
        ...new Set(
          callsForMode(
            agentMode,
            options.liveCallsByMode,
            options.candidateCountByMode,
          ).map(
            (call) => call.model,
          ),
        ),
      ]
    : [];
}

function agentModeFor(
  mode: Mode,
): "single-agent" | "moa-low" | "moa-high" | undefined {
  switch (mode) {
    case "single-agent":
    case "moa-low":
    case "moa-high":
      return mode;
    case "scanner-single":
      return "single-agent";
    case "scanner-moa-low":
      return "moa-low";
    case "scanner-moa-high":
      return "moa-high";
    case "scanner-only":
      return undefined;
  }
}

function isPhysical(mode: Mode): boolean {
  return (
    mode === "scanner-only" ||
    mode === "single-agent" ||
    mode === "moa-low" ||
    mode === "moa-high"
  );
}

function hybridSources(mode: Mode): Mode[] {
  switch (mode) {
    case "scanner-single":
      return ["scanner-only", "single-agent"];
    case "scanner-moa-low":
      return ["scanner-only", "moa-low"];
    case "scanner-moa-high":
      return ["scanner-only", "moa-high"];
    default:
      return [];
  }
}

function completenessInputFor(status: CellStatus, forceComplete: boolean) {
  const complete = status === "success" || forceComplete;
  const partial = status === "partial" && !forceComplete;
  return {
    plannedComponents: ["component:a", "component:b"],
    completedComponents: complete
      ? ["component:a", "component:b"]
      : ["component:a"],
    failedComponents:
      complete || partial ? [] : ["component:b"],
    skippedComponents: [],
    eligibleFiles: 1,
    inspectedFiles: 1,
    inspectedBytes: 64,
    unsupportedLanguages: [],
    degradedReasons:
      complete || partial ? [] : [`${status} evidence`],
  };
}

function computedCompleteness(
  status: CellStatus,
  forceComplete: boolean,
  aggregate: boolean,
) {
  const complete = status === "success" || forceComplete;
  const partial = status === "partial" && !forceComplete;
  return {
    status: complete ? "complete" : partial ? "partial" : "degraded",
    plannedComponentCount: 2,
    completedComponentCount: complete ? 2 : 1,
    failedComponents:
      complete || partial
        ? []
        : [
            aggregate
              ? "fixture-vulnerable:component:b"
              : "component:b",
          ],
    skippedComponents: [],
    componentCompletionRate: complete ? 1 : 0.5,
    eligibleFiles: 1,
    inspectedFiles: 1,
    fileCoverage: 1,
    inspectedBytes: 64,
    unsupportedLanguages: [],
    degradedReasons:
      complete || partial
        ? []
        : [
            aggregate
              ? `fixture-vulnerable:${status} evidence`
              : `${status} evidence`,
          ],
  };
}

function overallMetrics() {
  return authoritativeMetrics().metrics;
}

function classMetrics() {
  return authoritativeMetrics().metricsByClass;
}

function classSummary() {
  return authoritativeMetrics().classSummary;
}

function authoritativeMetrics(
  matchResults: readonly SyntheticMatchResult[] = [
    authoritativeMatchResult(),
  ],
) {
  const metricsByClass =
    computeVulnerabilityClassMetrics(matchResults);
  return {
    metrics: applyGroupedF1(
      computeSuiteMetrics(matchResults),
      metricsByClass,
    ),
    metricsByClass,
    classSummary: computeGroupedMetricSummary(metricsByClass),
  };
}

function immutableActualFindings(): Finding[] {
  return [
    {
      id: "actual-xss",
      fingerprint: "fingerprint-xss",
      category: "code",
      title: "Reflected XSS",
      severity: "high",
      confidence: "high",
      description: "Synthetic reflected XSS.",
      evidence: "Untrusted query value reaches an HTML response.",
      remediation: "Encode untrusted output.",
      tool: "synthetic",
      ruleId: "synthetic.xss",
      cwe: ["CWE-79"],
      identifiers: emptyIdentifiers(),
      location: {
        file: "$FIXTURE_ROOT/src/index.js",
        startLine: 10,
        endLine: 10,
      },
    },
    {
      id: "actual-xss-duplicate",
      fingerprint: "fingerprint-xss",
      category: "code",
      title: "Reflected XSS",
      severity: "high",
      confidence: "high",
      description: "Synthetic duplicate reflected XSS.",
      evidence: "The same untrusted query value reaches the same HTML response.",
      remediation: "Encode untrusted output.",
      tool: "synthetic",
      ruleId: "synthetic.xss",
      cwe: ["CWE-79"],
      identifiers: emptyIdentifiers(),
      location: {
        file: "$FIXTURE_ROOT/src/index.js",
        startLine: 10,
        endLine: 10,
      },
    },
    {
      id: "actual-sql",
      fingerprint: "fingerprint-sql",
      category: "code",
      title: "SQL injection",
      severity: "critical",
      confidence: "high",
      description: "Synthetic SQL injection.",
      evidence: "Untrusted input is concatenated into a query.",
      remediation: "Use a parameterized query.",
      tool: "synthetic",
      ruleId: "synthetic.sql",
      cwe: ["CWE-89"],
      identifiers: emptyIdentifiers(),
      location: {
        file: "$FIXTURE_ROOT/src/index.js",
        startLine: 20,
        endLine: 20,
      },
    },
    {
      id: "actual-secret",
      fingerprint: "fingerprint-secret",
      category: "secret",
      title: "Hardcoded API key",
      severity: "high",
      confidence: "high",
      description: "Synthetic hardcoded secret.",
      evidence: "A key-like value is committed.",
      remediation: "Rotate and load it from a secret store.",
      tool: "synthetic",
      ruleId: "synthetic.secret",
      cwe: ["CWE-798"],
      identifiers: emptyIdentifiers(),
      location: {
        file: "$FIXTURE_ROOT/src/index.js",
        startLine: 40,
        endLine: 40,
      },
    },
  ];
}

function authoritativeFixtureManifest() {
  return {
    schemaVersion: "2.0",
    id: "fixture-vulnerable",
    pairId: "fixture-pair",
    variant: "vulnerable",
    language: "javascript",
    projectRoot: "project",
    evaluatorFiles: ["truth.json"],
    entrypoints: ["src/index.js"],
    sourceFiles: ["src/index.js"],
    supportedVulnerabilityClasses: [
      "cross-site-scripting",
      "sql-injection",
    ],
    expectedFindingCount: 3,
    pairedFixtureId: "fixture-clean",
    safety: {
      networkRequired: false,
      executionRequired: false,
      containsRealSecrets: false,
      executionPolicy: "never",
      networkPolicy: "deny",
    },
  };
}

function authoritativeTruthSet() {
  return {
    schemaVersion: "2.0",
    fixtureId: "fixture-vulnerable",
    findings: [
      groundTruthFinding({
        id: "truth-xss",
        vulnerabilityClass: "cross-site-scripting",
        title: "Reflected XSS",
        severity: "high",
        cwe: ["CWE-79"],
        line: 10,
      }),
      groundTruthFinding({
        id: "truth-sql-matched",
        vulnerabilityClass: "sql-injection",
        title: "SQL injection in lookup",
        severity: "critical",
        cwe: ["CWE-89"],
        line: 20,
      }),
      groundTruthFinding({
        id: "truth-sql-missed",
        vulnerabilityClass: "sql-injection",
        title: "SQL injection in search",
        severity: "high",
        cwe: ["CWE-89"],
        line: 30,
      }),
    ],
  };
}

function authoritativeMatchResult() {
  return matchFindings(
    authoritativeTruthSet().findings,
    projectFindings(immutableActualFindings(), {
      fixtureRoot: "$FIXTURE_ROOT",
    }),
  );
}

function groundTruthFinding(input: {
  id: string;
  vulnerabilityClass: string;
  title: string;
  severity: "high" | "critical";
  cwe: string[];
  line: number;
}): GroundTruthFinding {
  return {
    id: input.id,
    category: "code",
    vulnerabilityClass: input.vulnerabilityClass,
    title: input.title,
    severity: input.severity,
    cwe: input.cwe,
    identifiers: emptyIdentifiers(),
    location: {
      path: "src/index.js",
      startLine: input.line,
      endLine: input.line,
    },
  };
}

function emptyIdentifiers() {
  return { cve: [], ghsa: [], osv: [] };
}

async function writeWrapped(filePath: string, data: unknown): Promise<void> {
  await fs.writeFile(
    filePath,
    `${JSON.stringify(
      {
        schemaVersion: "1.0",
        redactionMarkers: ["synthetic-redaction"],
        data,
      },
      null,
      2,
    )}\n`,
    "utf8",
  );
}

function runSummary(
  suiteDirectory: string,
  outputDirectory: string,
): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return runProcess(process.execPath, [
    path.resolve("scripts/research/summarize-seven-mode.mjs"),
    "--suite",
    suiteDirectory,
    "--out",
    outputDirectory,
  ]);
}

function runProcess(
  executable: string,
  args: readonly string[],
): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, {
      cwd: process.cwd(),
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk: string) => {
      stderr += chunk;
    });
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}
