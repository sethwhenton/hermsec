import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  loadEvaluationFixture,
  runScoredEvaluationSuite,
  type EvaluationSuiteCaseInput,
  type GroundTruthFinding,
} from "../../../src/eval/index.js";
import type { Finding } from "../../../src/shared/types.js";

const fixtureRoot = path.resolve(
  process.cwd(),
  "tests/fixtures/research",
);
const vulnerableRoot = path.join(fixtureRoot, "micro-js-vulnerable");
const cleanRoot = path.join(fixtureRoot, "micro-js-clean");

test("fixture loader binds manifest identity and count to truth without executing fixture code", async (t) => {
  const temporaryRoot = await createInertFixture();
  t.after(async () => {
    await fs.rm(temporaryRoot, { recursive: true, force: true });
  });

  const loaded = await loadEvaluationFixture(temporaryRoot);

  assert.equal(loaded.manifest.id, loaded.truth.fixtureId);
  assert.equal(
    loaded.manifest.expectedFindingCount,
    loaded.truth.findings.length,
  );
  assert.equal(loaded.manifest.safety.executionPolicy, "never");
  assert.equal(loaded.manifest.safety.networkPolicy, "deny");
  assert.ok(loaded.sourceLines > 0);
  await assert.rejects(
    fs.access(path.join(temporaryRoot, "EXECUTED_SENTINEL")),
  );
});

test("fixture loader rejects truth identity and count drift", async (t) => {
  const temporaryRoot = await createInertFixture();
  t.after(async () => {
    await fs.rm(temporaryRoot, { recursive: true, force: true });
  });

  await writeJson(path.join(temporaryRoot, "truth.json"), {
    schemaVersion: "2.0",
    fixtureId: "wrong-fixture",
    findings: [],
  });
  await assert.rejects(
    loadEvaluationFixture(temporaryRoot),
    /truth fixtureId mismatch/,
  );

  await writeJson(path.join(temporaryRoot, "truth.json"), {
    schemaVersion: "2.0",
    fixtureId: "inert-fixture",
    findings: [],
  });
  const manifest = JSON.parse(
    await fs.readFile(path.join(temporaryRoot, "fixture.json"), "utf8"),
  ) as Record<string, unknown>;
  await writeJson(path.join(temporaryRoot, "fixture.json"), {
    ...manifest,
    variant: "vulnerable",
    expectedFindingCount: 1,
  });
  await assert.rejects(
    loadEvaluationFixture(temporaryRoot),
    /does not match truth count/,
  );
});

test("scored suite emits the full case, run, selective, completeness, and normalized comparison bundle", async () => {
  const vulnerableFixture = await loadEvaluationFixture(vulnerableRoot);
  const predictions = vulnerableFixture.truth.findings.map(
    (truth, index) => {
      const prediction = findingFromTruth(truth);
      return index === 0
        ? {
            ...prediction,
            agent: {
              mode: "single-agent" as const,
              source: "single-agent" as const,
              provider: "test-provider",
              model: "test-model",
              role: "reviewer",
              generatedAt: "2026-01-01T00:00:00.000Z",
              judge: {
                verdict: "needs-review" as const,
                confidence: "medium" as const,
                reason: "Fixture exercises selective evaluation.",
              },
            },
          }
        : prediction;
    },
  );
  const spurious: Finding = {
    id: "SPURIOUS-PATH-TRAVERSAL",
    fingerprint: "spurious-path-traversal",
    title: "Possible path traversal",
    category: "code",
    severity: "medium",
    confidence: "medium",
    description: "Synthetic unsupported-class prediction.",
    evidence: "A test-only false finding.",
    remediation: "Validate paths.",
    tool: "test-agent",
    ruleId: "test.path-traversal",
    cwe: ["CWE-22"],
    location: { file: "src/server.js", startLine: 1 },
  };
  const cases = makeCases(predictions, [spurious]);
  const capability = {
    modelClass: "bounded-test-model",
    maxRoundsPerAgent: 4,
    maxToolCallsPerAgent: 8,
    maxInputTokensPerAgent: 4_000,
    maxOutputTokensPerAgent: 1_000,
  };

  const bundle = await runScoredEvaluationSuite({
    suiteId: "paired-micro-suite",
    runs: [
      {
        runId: "scanner-run",
        mode: "scanner-only",
        cases,
        costUsd: 0.01,
        totalTokens: 0,
        agentCount: 0,
        capability,
      },
      {
        runId: "single-run",
        mode: "scanner-plus-single",
        cases,
        costUsd: 0.012,
        totalTokens: 900,
        agentCount: 1,
        capability,
      },
    ],
    normalization: {
      targetCostUsd: 0.011,
      toleranceUsd: 0.01,
      requiredModes: ["scanner-only", "scanner-plus-single"],
      capabilityReference: capability,
    },
  });

  assert.equal(bundle.schemaVersion, "1.0");
  assert.equal(bundle.runs.length, 2);
  const run = bundle.runs.find(
    (candidate) => candidate.runId === "scanner-run",
  );
  assert.ok(run);
  assert.equal(run?.matchResults.length, 2);
  assert.equal(run?.metrics.truePositive, 4);
  assert.equal(run?.metrics.falsePositive, 1);
  assert.equal(run?.metrics.falseNegative, 0);
  assert.equal(run?.metrics.groupMetricsDefined, true);
  assert.equal(run?.metrics.macroF1, 1);
  assert.equal(run?.metrics.macroF1IncludingSpurious, 0.8);
  assert.equal(run?.metrics.predictionOnlyGroupCount, 1);
  assert.ok((run?.sourceLines ?? 0) > 0);
  assert.ok((run?.metrics.falseFindingsPerKloc ?? 0) > 0);
  assert.equal(run?.metricsByCategory.code.truePositive, 3);
  assert.equal(run?.metricsByCategory.secret.truePositive, 1);
  assert.equal(run?.metricsByClass["path-traversal"]?.falsePositive, 1);
  assert.equal(run?.selective.totalPredictions, 5);
  assert.equal(run?.selective.abstainedPredictions, 1);
  assert.equal(run?.selective.abstentionRate, 0.2);
  assert.equal(run?.selective.selectivePrecision, 0.75);
  assert.equal(run?.selective.acceptedCoverage, 0.75);
  assert.equal(run?.selective.needsReviewRecall, 0.25);
  assert.equal(run?.completeness.status, "complete");
  assert.equal(run?.completeness.fileCoverage, 1);
  assert.equal(bundle.comparisons.capability.rows.length, 2);
  assert.equal(bundle.comparisons.cost.rows.length, 2);
  assert.equal(
    bundle.comparisons.cost.rows.find(
      (row) => row.mode === "scanner-only",
    )?.f1,
    run?.metrics.f1,
  );
});

function makeCases(
  vulnerableFindings: readonly Finding[],
  cleanFindings: readonly Finding[],
): EvaluationSuiteCaseInput[] {
  return [
    {
      fixtureRoot: vulnerableRoot,
      findings: vulnerableFindings,
      completeness: {
        plannedComponents: ["inspect", "evaluate"],
        completedComponents: ["inspect", "evaluate"],
        inspectedFiles: 5,
        inspectedBytes: 1_024,
      },
    },
    {
      fixtureRoot: cleanRoot,
      findings: cleanFindings,
      completeness: {
        plannedComponents: ["inspect", "evaluate"],
        completedComponents: ["inspect", "evaluate"],
        inspectedFiles: 5,
        inspectedBytes: 1_024,
      },
    },
  ];
}

function findingFromTruth(truth: GroundTruthFinding): Finding {
  return {
    id: `PREDICTED-${truth.id}`,
    fingerprint: `predicted-${truth.id.toLowerCase()}`,
    title: truth.title,
    category: truth.category,
    severity: truth.severity,
    confidence: "high",
    description: truth.title,
    evidence: truth.evidence?.description ?? truth.title,
    remediation: "Apply the fixture remediation.",
    tool: "test-agent",
    ...(truth.ruleIds?.[0] ? { ruleId: truth.ruleIds[0] } : {}),
    cwe: [...truth.cwe],
    identifiers: {
      cve: [...truth.identifiers.cve],
      ghsa: [...truth.identifiers.ghsa],
      osv: [...truth.identifiers.osv],
    },
    ...(truth.location
      ? {
          location: {
            file: truth.location.path,
            ...(typeof truth.location.startLine === "number"
              ? { startLine: truth.location.startLine }
              : {}),
            ...(typeof truth.location.endLine === "number"
              ? { endLine: truth.location.endLine }
              : {}),
          },
        }
      : {}),
    ...(truth.evidence?.sourceLocations
      ? {
          sourceLocations: truth.evidence.sourceLocations.map(
            (location) => ({
              file: location.path,
              ...(typeof location.startLine === "number"
                ? { startLine: location.startLine }
                : {}),
              ...(typeof location.endLine === "number"
                ? { endLine: location.endLine }
                : {}),
            }),
          ),
        }
      : {}),
  };
}

async function createInertFixture(): Promise<string> {
  const root = await fs.mkdtemp(
    path.join(os.tmpdir(), "hermsec-eval-inert-"),
  );
  await fs.mkdir(path.join(root, "project", "src"), { recursive: true });
  await fs.writeFile(
    path.join(root, "project", "src", "fixture.js"),
    "export const fixtureValue = 'never execute fixtures';\n",
    "utf8",
  );
  await writeJson(path.join(root, "project", "package.json"), {
    scripts: {
      test: "node -e \"require('fs').writeFileSync('EXECUTED_SENTINEL','bad')\"",
    },
  });
  await writeJson(path.join(root, "fixture.json"), {
    schemaVersion: "2.0",
    id: "inert-fixture",
    pairId: "inert-pair",
    variant: "clean",
    language: "javascript",
    projectRoot: "project",
    evaluatorFiles: ["truth.json"],
    entrypoints: ["src/fixture.js"],
    sourceFiles: ["src/fixture.js"],
    supportedVulnerabilityClasses: ["sql-injection"],
    expectedFindingCount: 0,
    pairedFixtureId: "inert-vulnerable",
    safety: {
      networkRequired: false,
      executionRequired: false,
      containsRealSecrets: false,
      executionPolicy: "never",
      networkPolicy: "deny",
    },
  });
  await writeJson(path.join(root, "truth.json"), {
    schemaVersion: "2.0",
    fixtureId: "inert-fixture",
    findings: [],
  });
  return root;
}

async function writeJson(file: string, value: unknown): Promise<void> {
  await fs.writeFile(file, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}
