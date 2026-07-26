import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  canonicalJson,
  sha256,
} from "../../../src/research/integrity.js";
import {
  createRunManifest,
  createSuiteIndex,
  RESEARCH_INTEGRITY_NOTICE,
  validateRunArtifacts,
  validateSuiteIndex,
} from "../../../src/research/runManifest.js";
import type {
  ResearchModelCallTrace,
} from "../../../src/research/modelCallTrace.js";

test("run manifests are immutable, redacted, tamper-evident, and validate artifacts", async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-run-manifest-"));
  const secret = ["sk", "manifest-secret-value-1234567890"].join("-");
  try {
    await createArtifacts(directory);
    const input = manifestInput(secret, "run-20260725-001");
    const manifest = await createRunManifest(directory, input);
    const raw = await fs.readFile(
      path.join(directory, "run-manifest.json"),
      "utf8",
    );
    const initialValidation = await validateRunArtifacts(directory);

    assert.equal(manifest.schemaVersion, 2);
    assert.equal(manifest.artifacts.length, 2);
    assert.equal(raw.includes(secret), false);
    assert.match(raw, /\[REDACTED\]/);
    assert.deepEqual(manifest.integrity, RESEARCH_INTEGRITY_NOTICE);
    assert.equal(manifest.integrity.authenticated, false);
    assert.match(manifest.integrity.notice, /can recompute/i);
    assert.equal(initialValidation.valid, true);
    await assert.rejects(
      () => createRunManifest(directory, input),
      /EEXIST|exist/i,
    );

    await fs.writeFile(path.join(directory, "unlisted.txt"), "unexpected\n", "utf8");
    const extraValidation = await validateRunArtifacts(directory);
    assert.equal(extraValidation.valid, false);
    assert.ok(
      extraValidation.errors.some((error) =>
        /unlisted artifact.*unlisted\.txt/i.test(error),
      ),
    );
    await fs.rm(path.join(directory, "unlisted.txt"), { force: true });

    const hardLinkAlias = path.join(
      path.dirname(directory),
      `${path.basename(directory)}-cost-hardlink.jsonl`,
    );
    try {
      await fs.link(
        path.join(directory, "cost.jsonl"),
        hardLinkAlias,
      );
      const hardLinkValidation =
        await validateRunArtifacts(directory);
      assert.equal(hardLinkValidation.valid, false);
      assert.ok(
        hardLinkValidation.errors.some((error) =>
          /cost\.jsonl.*single-link|single-link.*cost\.jsonl/iu.test(
            error,
          ),
        ),
      );
    } finally {
      await fs.rm(hardLinkAlias, { force: true });
    }

    await fs.appendFile(path.join(directory, "cost.jsonl"), '{"cost":1}\n', "utf8");
    const changedValidation = await validateRunArtifacts(directory);
    assert.equal(changedValidation.valid, false);
    assert.ok(
      changedValidation.errors.some((error) => /cost\.jsonl/.test(error)),
    );
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test("suite index separately binds valid run manifests and detects later changes", async () => {
  const suiteDirectory = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-suite-index-"));
  try {
    for (const runId of ["run-a", "run-b"]) {
      const runDirectory = path.join(suiteDirectory, runId);
      await createArtifacts(runDirectory);
      await createRunManifest(runDirectory, manifestInput("none", runId));
    }
    const index = await createSuiteIndex(suiteDirectory, {
      suiteId: "micro-seven-mode",
      createdAt: "2026-07-25T02:00:00.000Z",
      runManifestPaths: [
        "run-a/run-manifest.json",
        "run-b/run-manifest.json",
      ],
    });
    const validation = await validateSuiteIndex(suiteDirectory);

    assert.equal(index.schemaVersion, 2);
    assert.equal(index.runs.length, 2);
    assert.equal(index.integrity.authenticated, false);
    assert.equal(validation.valid, true);

    const manifestPath = path.join(
      suiteDirectory,
      "run-a",
      "run-manifest.json",
    );
    const raw = await fs.readFile(manifestPath, "utf8");
    await fs.writeFile(
      manifestPath,
      raw.replace('"runId": "run-a"', '"runId": "run-changed"'),
      "utf8",
    );
    const changed = await validateSuiteIndex(suiteDirectory);
    assert.equal(changed.valid, false);
    assert.ok(
      changed.errors.some((error) => /binding changed|integrity hash/i.test(error)),
    );
  } finally {
    await fs.rm(suiteDirectory, { recursive: true, force: true });
  }
});

test("fresh suite index v3 binds suite artifacts and canonical fixture truth", async () => {
  const suiteDirectory = await fs.mkdtemp(
    path.join(os.tmpdir(), "hermsec-suite-index-v3-"),
  );
  try {
    const runDirectory = path.join(suiteDirectory, "run-a");
    await createArtifacts(runDirectory);
    await createRunManifest(
      runDirectory,
      v3ManifestInput("run-a"),
    );
    const artifactPaths = await createSuiteArtifacts(suiteDirectory);
    const truthPath = "truth/fixture-a/truth-evidence.json";
    const index = await createSuiteIndex(suiteDirectory, {
      suiteId: "micro-seven-mode-v3",
      createdAt: "2026-07-25T02:00:00.000Z",
      runManifestPaths: ["run-a/run-manifest.json"],
      artifactPaths,
      fixtureTruth: [
        {
          fixtureId: "fixture-a",
          pairId: "pair-a",
          variant: "vulnerable",
          path: truthPath,
          fixtureDigestSha256: "a".repeat(64),
        },
      ],
    });
    const validation = await validateSuiteIndex(suiteDirectory);

    assert.equal(index.schemaVersion, 3);
    assert.equal(validation.valid, true, validation.errors.join("\n"));
    if (index.schemaVersion !== 3) {
      assert.fail("Expected a v3 suite index.");
    }
    assert.deepEqual(
      index.artifacts.map((artifact) => artifact.path).sort(),
      [...artifactPaths].sort(),
    );
    assert.deepEqual(index.fixtureTruth, [
      {
        fixtureId: "fixture-a",
        pairId: "pair-a",
        variant: "vulnerable",
        path: truthPath,
        artifactSha256: index.artifacts.find(
          (artifact) => artifact.path === truthPath,
        )?.sha256,
        fixtureDigestSha256: "a".repeat(64),
      },
    ]);

    const evaluationPath = path.join(
      suiteDirectory,
      "evaluation.json",
    );
    const originalEvaluation = await fs.readFile(evaluationPath);
    await fs.appendFile(evaluationPath, "\n");
    const evaluationTamper = await validateSuiteIndex(suiteDirectory);
    assert.equal(evaluationTamper.valid, false);
    assert.ok(
      evaluationTamper.errors.some((error) =>
        /suite artifact.*evaluation\.json/iu.test(error),
      ),
    );
    await fs.writeFile(evaluationPath, originalEvaluation);

    const truthAbsolute = path.join(
      suiteDirectory,
      ...truthPath.split("/"),
    );
    const truthDocument = JSON.parse(
      await fs.readFile(truthAbsolute, "utf8"),
    ) as {
      data: {
        truth: Record<string, unknown>;
      };
    };
    truthDocument.data.truth.tampered = true;
    const tamperedTruth = Buffer.from(
      `${JSON.stringify(truthDocument, null, 2)}\n`,
      "utf8",
    );
    await fs.writeFile(truthAbsolute, tamperedTruth);
    const indexPath = path.join(suiteDirectory, "suite-index.json");
    const rewrittenIndex = JSON.parse(
      await fs.readFile(indexPath, "utf8"),
    ) as {
      artifacts: Array<{
        path: string;
        bytes: number;
        sha256: string;
      }>;
      fixtureTruth: Array<{
        path: string;
        artifactSha256: string;
      }>;
      indexSha256: string;
    };
    const rewrittenTruthHash = sha256(tamperedTruth);
    const truthRecord = rewrittenIndex.artifacts.find(
      (artifact) => artifact.path === truthPath,
    );
    const truthBinding = rewrittenIndex.fixtureTruth.find(
      (binding) => binding.path === truthPath,
    );
    assert.ok(truthRecord);
    assert.ok(truthBinding);
    truthRecord.bytes = tamperedTruth.byteLength;
    truthRecord.sha256 = rewrittenTruthHash;
    truthBinding.artifactSha256 = rewrittenTruthHash;
    const { indexSha256: _oldIndexHash, ...rewrittenUnsigned } =
      rewrittenIndex;
    rewrittenIndex.indexSha256 = sha256(
      canonicalJson(rewrittenUnsigned),
    );
    await fs.writeFile(
      indexPath,
      `${JSON.stringify(rewrittenIndex, null, 2)}\n`,
      "utf8",
    );
    const truthTamper = await validateSuiteIndex(suiteDirectory);
    assert.equal(truthTamper.valid, false);
    assert.ok(
      truthTamper.errors.some((error) =>
        /truth internal content binding|finding-count binding/iu.test(
          error,
        ),
      ),
    );
  } finally {
    await fs.rm(suiteDirectory, { recursive: true, force: true });
  }
});

test("suite index v3 rejects artifact path escapes and symbolic links", async (t) => {
  const suiteDirectory = await fs.mkdtemp(
    path.join(os.tmpdir(), "hermsec-suite-index-v3-escape-"),
  );
  const outside = path.join(
    path.dirname(suiteDirectory),
    `${path.basename(suiteDirectory)}-outside.json`,
  );
  try {
    const runDirectory = path.join(suiteDirectory, "run-a");
    await createArtifacts(runDirectory);
    await createRunManifest(
      runDirectory,
      v3ManifestInput("run-a"),
    );
    const artifactPaths = await createSuiteArtifacts(suiteDirectory);
    await fs.writeFile(outside, "{}\n", "utf8");
    await assert.rejects(
      () =>
        createSuiteIndex(suiteDirectory, {
          suiteId: "escape-v3",
          createdAt: "2026-07-25T02:00:00.000Z",
          runManifestPaths: ["run-a/run-manifest.json"],
          artifactPaths: [
            ...artifactPaths,
            `..${path.sep}${path.basename(outside)}`,
          ],
          fixtureTruth: [
            {
              fixtureId: "fixture-a",
              pairId: "pair-a",
              variant: "vulnerable",
              path: "truth/fixture-a/truth-evidence.json",
              fixtureDigestSha256: "a".repeat(64),
            },
          ],
        }),
      /escapes the run directory/iu,
    );

    const hardLinkPath = path.join(
      suiteDirectory,
      "hard-linked-outside.json",
    );
    await fs.link(outside, hardLinkPath);
    await assert.rejects(
      () =>
        createSuiteIndex(suiteDirectory, {
          suiteId: "hard-link-v3",
          createdAt: "2026-07-25T02:00:00.000Z",
          runManifestPaths: ["run-a/run-manifest.json"],
          artifactPaths: [
            ...artifactPaths,
            "hard-linked-outside.json",
          ],
          fixtureTruth: [
            {
              fixtureId: "fixture-a",
              pairId: "pair-a",
              variant: "vulnerable",
              path: "truth/fixture-a/truth-evidence.json",
              fixtureDigestSha256: "a".repeat(64),
            },
          ],
        }),
      /regular files|single-link|links/iu,
    );
    await fs.rm(hardLinkPath, { force: true });

    const linkPath = path.join(suiteDirectory, "linked-outside.json");
    try {
      await fs.symlink(outside, linkPath, "file");
    } catch (error) {
      if (
        error instanceof Error &&
        "code" in error &&
        ["EPERM", "EACCES", "ENOTSUP"].includes(String(error.code))
      ) {
        t.diagnostic(
          "Symbolic-link creation is unavailable; path-escape coverage still ran.",
        );
        return;
      }
      throw error;
    }
    await assert.rejects(
      () =>
        createSuiteIndex(suiteDirectory, {
          suiteId: "link-v3",
          createdAt: "2026-07-25T02:00:00.000Z",
          runManifestPaths: ["run-a/run-manifest.json"],
          artifactPaths: [...artifactPaths, "linked-outside.json"],
          fixtureTruth: [
            {
              fixtureId: "fixture-a",
              pairId: "pair-a",
              variant: "vulnerable",
              path: "truth/fixture-a/truth-evidence.json",
              fixtureDigestSha256: "a".repeat(64),
            },
          ],
        }),
      /regular files|links|outside/iu,
    );
  } finally {
    await fs.rm(suiteDirectory, { recursive: true, force: true });
    await fs.rm(outside, { force: true });
  }
});

test("run manifests reject artifacts outside immutable run directory", async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-run-escape-"));
  const outside = path.join(
    path.dirname(directory),
    `${path.basename(directory)}-outside.json`,
  );
  try {
    await fs.writeFile(outside, "{}\n", "utf8");
    await assert.rejects(
      () =>
        createRunManifest(directory, {
          ...manifestInput("none", "escape-run"),
          artifactPaths: [`..${path.sep}${path.basename(outside)}`],
        }),
      /escapes the run directory/i,
    );
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
    await fs.rm(outside, { force: true });
  }
});

test("run manifests strictly validate model-call v2 producer and schema bindings", async () => {
  const mutations: Array<{
    name: string;
    mutateDocument?: (document: Record<string, unknown>) => void;
    mutateManifest?: (manifest: Record<string, unknown>) => void;
    expected: RegExp;
  }> = [
    {
      name: "errors-not-array",
      mutateDocument(document) {
        const trace = document.data as {
          producerValidation: Record<string, unknown>;
        };
        trace.producerValidation.errors = "not-an-array";
      },
      expected: /model-call trace schema is invalid/iu,
    },
    {
      name: "errors-not-strings",
      mutateDocument(document) {
        const trace = document.data as {
          producerValidation: Record<string, unknown>;
        };
        trace.producerValidation.errors = [42];
      },
      expected: /model-call trace schema is invalid/iu,
    },
    {
      name: "manifest-version-mismatch",
      mutateManifest(manifest) {
        const metadata = manifest.metadata as Record<string, unknown>;
        metadata.modelCallTraceSchemaVersion = "1.0";
      },
      expected: /model-call trace schema binding is unsupported/iu,
    },
  ];

  for (const mutation of mutations) {
    const directory = await fs.mkdtemp(
      path.join(os.tmpdir(), `hermsec-run-trace-${mutation.name}-`),
    );
    try {
      const runId = `trace-${mutation.name}`;
      const tracePath = path.join(directory, "model-calls.json");
      await fs.writeFile(
        tracePath,
        `${JSON.stringify(validModelCallTraceDocument(runId), null, 2)}\n`,
        "utf8",
      );
      await createRunManifest(directory, {
        ...manifestInput("none", runId),
        metadata: {
          physical: true,
          derivedFrom: [],
          modelCallTraceSchemaVersion: "2.0",
          modelCallTraceRolePlanVersion: "2.0",
          modelCallTraceCassettePolicy: "none",
        },
        artifactPaths: ["model-calls.json"],
      });
      const initial = await validateRunArtifacts(directory);
      assert.equal(initial.valid, true, initial.errors.join("\n"));

      const document = JSON.parse(
        await fs.readFile(tracePath, "utf8"),
      ) as Record<string, unknown>;
      mutation.mutateDocument?.(document);
      if (mutation.mutateDocument) {
        await fs.writeFile(
          tracePath,
          `${JSON.stringify(document, null, 2)}\n`,
          "utf8",
        );
      }
      await rehashRunManifest(
        directory,
        mutation.mutateManifest,
      );

      const validation = await validateRunArtifacts(directory);
      assert.equal(validation.valid, false);
      assert.match(validation.errors.join("\n"), mutation.expected);
    } finally {
      await fs.rm(directory, { recursive: true, force: true });
    }
  }
});

async function createArtifacts(directory: string): Promise<void> {
  await fs.mkdir(path.join(directory, "findings"), { recursive: true });
  await fs.writeFile(
    path.join(directory, "findings", "canonical.json"),
    '{"findings":[]}\n',
    "utf8",
  );
  await fs.writeFile(path.join(directory, "cost.jsonl"), '{"cost":0}\n', "utf8");
}

function validModelCallTraceDocument(runId: string): {
  schemaVersion: "1.0";
  redactionMarkers: string[];
  data: ResearchModelCallTrace;
} {
  return {
    schemaVersion: "1.0",
    redactionMarkers: [],
    data: {
      schemaVersion: "2.0",
      runId,
      mode: "single-agent",
      execution: "mock",
      cassettePolicy: "none",
      physical: true,
      derivedFrom: [],
      detectorStatus: "completed",
      candidateCount: 0,
      aggregationDisposition: "not-applicable",
      rolePlan: {
        status: "complete",
        requiredSpecialistRoles: ["single-agent-inspector"],
      },
      traceCompleteness: "complete",
      calls: [{
        ordinal: 1,
        role: "single-agent-inspector",
        gapFill: false,
        provider: "openrouter",
        model: "deepseek/deepseek-v4-flash",
        requestFingerprint: "a".repeat(64),
        fingerprintSource: "metered-replay",
        terminalState: "succeeded",
        responseProvider: "openrouter",
        responseModel: "deepseek/deepseek-v4-flash",
      }],
      producerValidation: {
        valid: true,
        errors: [],
      },
    },
  };
}

async function rehashRunManifest(
  directory: string,
  mutate?: (manifest: Record<string, unknown>) => void,
): Promise<void> {
  const manifestPath = path.join(directory, "run-manifest.json");
  const manifest = JSON.parse(
    await fs.readFile(manifestPath, "utf8"),
  ) as Record<string, unknown> & {
    artifacts: Array<{
      path: string;
      bytes: number;
      sha256: string;
    }>;
    manifestSha256: string;
  };
  const traceArtifact = manifest.artifacts.find(
    (artifact) => artifact.path === "model-calls.json",
  );
  assert.ok(traceArtifact);
  const traceContent = await fs.readFile(
    path.join(directory, "model-calls.json"),
  );
  traceArtifact.bytes = traceContent.byteLength;
  traceArtifact.sha256 = sha256(traceContent);
  mutate?.(manifest);
  const { manifestSha256: _oldHash, ...unsigned } = manifest;
  manifest.manifestSha256 = sha256(canonicalJson(unsigned));
  await fs.writeFile(
    manifestPath,
    `${JSON.stringify(manifest, null, 2)}\n`,
    "utf8",
  );
}

async function createSuiteArtifacts(
  suiteDirectory: string,
): Promise<string[]> {
  const artifacts = [
    "evaluation.json",
    "source-index.json",
    "experiment-summary.json",
    "cost-ledger.jsonl",
    "truth/fixture-a/truth-evidence.json",
  ];
  for (const relativePath of artifacts) {
    const absolute = path.join(
      suiteDirectory,
      ...relativePath.split("/"),
    );
    await fs.mkdir(path.dirname(absolute), { recursive: true });
    if (relativePath === "cost-ledger.jsonl") {
      await fs.writeFile(absolute, "", "utf8");
    } else if (relativePath.endsWith("truth-evidence.json")) {
      const manifest = {
        id: "fixture-a",
        expectedFindingCount: 0,
      };
      const truth = { fixtureId: "fixture-a", findings: [] };
      const sourceState = {
        fixtureId: "fixture-a",
        fixtureDigestSha256: "a".repeat(64),
      };
      await fs.writeFile(
        absolute,
        `${JSON.stringify(
          {
            schemaVersion: "1.0",
            redactionMarkers: [],
            data: {
              schemaVersion: "1.0",
              fixtureId: "fixture-a",
              pairId: "pair-a",
              variant: "vulnerable",
              manifest,
              truth,
              sourceState,
              binding: {
                manifestSha256: sha256(canonicalJson(manifest)),
                truthSha256: sha256(canonicalJson(truth)),
                sourceStateSha256: sha256(
                  canonicalJson(sourceState),
                ),
                fixtureDigestSha256: "a".repeat(64),
              },
            },
          },
          null,
          2,
        )}\n`,
        "utf8",
      );
    } else {
      await fs.writeFile(
        absolute,
        `${JSON.stringify({ artifact: relativePath })}\n`,
        "utf8",
      );
    }
  }
  return artifacts;
}

function manifestInput(secret: string, runId: string) {
  return {
    runId,
    suite: "micro",
    mode: "single-agent",
    execution: "mock" as const,
    status: "success" as const,
    startedAt: "2026-07-25T01:00:00.000Z",
    finishedAt: "2026-07-25T01:01:00.000Z",
    harnessVersion: "tool-agent-v1",
    promptVersion: "single-v1",
    sourceState: { commit: "a".repeat(40), dirty: false },
    limits: { maxRounds: 5, globalBudgetUsd: 3.25 },
    models: [
      { provider: "openrouter", model: "deepseek/deepseek-v4-flash" },
    ],
    metadata: {
      authorization: `Bearer ${secret}`,
      apiKey: secret,
    },
    artifactPaths: ["findings/canonical.json", "cost.jsonl"],
  };
}

function v3ManifestInput(runId: string) {
  return {
    ...manifestInput("none", runId),
    sourceState: {
      fixtureId: "fixture-a",
      fixtureDigestSha256: "a".repeat(64),
    },
    metadata: {
      fixtureId: "fixture-a",
      truthArtifact: {
        fixtureId: "fixture-a",
        path: "truth/fixture-a/truth-evidence.json",
        fixtureDigestSha256: "a".repeat(64),
      },
    },
  };
}
