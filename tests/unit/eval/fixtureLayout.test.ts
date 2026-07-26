import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { loadEvaluationFixture } from "../../../src/eval/suite.js";

test("fixture layout keeps arbitrary evaluator files outside project while allowing legitimate project truth data", async (t) => {
  const root = await createStructuralFixture();
  t.after(() => fs.rm(root, { recursive: true, force: true }));

  const fixture = await loadEvaluationFixture(root);

  assert.equal(fixture.manifest.projectRoot, "project");
  assert.deepEqual(fixture.layout.evaluatorFiles, [
    "evaluation.json",
    "fixture.json",
    "labels.json",
    "oracle.json",
    "truth.json",
  ]);
  assert.ok(
    fixture.layout.projectFiles.some(
      (file) => file.projectPath === "project-data/truth.json",
    ),
  );
  assert.equal(
    await fs.readFile(
      path.join(fixture.projectRoot, "project-data", "truth.json"),
      "utf8",
    ),
    '{"purpose":"legitimate application data"}\n',
  );
});

test("fixture layout rejects unclassified or misplaced root files", async (t) => {
  const root = await createStructuralFixture();
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  await fs.writeFile(
    path.join(root, "unclassified.json"),
    "{}\n",
    "utf8",
  );

  await assert.rejects(
    loadEvaluationFixture(root),
    /unclassified file outside project/u,
  );
});

test("fixture manifests reject path aliases before loading source", async (t) => {
  const root = await createStructuralFixture();
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const manifestPath = path.join(root, "fixture.json");
  const manifest = JSON.parse(
    await fs.readFile(manifestPath, "utf8"),
  ) as Record<string, unknown>;
  manifest.evaluatorFiles = [
    "evaluation.json",
    "labels.json",
    "oracle.json",
    "./truth.json",
  ];
  await writeJson(manifestPath, manifest);

  await assert.rejects(
    loadEvaluationFixture(root),
    /canonical relative path/u,
  );
});

async function createStructuralFixture(): Promise<string> {
  const root = await fs.mkdtemp(
    path.join(os.tmpdir(), "hermsec-layout-"),
  );
  await fs.mkdir(path.join(root, "project", "src"), {
    recursive: true,
  });
  await fs.mkdir(path.join(root, "project", "project-data"), {
    recursive: true,
  });
  await fs.writeFile(
    path.join(root, "project", "src", "app.js"),
    "export const value = 1;\n",
    "utf8",
  );
  await fs.writeFile(
    path.join(root, "project", "project-data", "truth.json"),
    '{"purpose":"legitimate application data"}\n',
    "utf8",
  );
  await writeJson(path.join(root, "fixture.json"), {
    schemaVersion: "2.0",
    id: "structural-fixture",
    pairId: "structural-pair",
    variant: "clean",
    language: "javascript",
    projectRoot: "project",
    evaluatorFiles: [
      "evaluation.json",
      "labels.json",
      "oracle.json",
      "truth.json",
    ],
    entrypoints: ["src/app.js"],
    sourceFiles: ["src/app.js"],
    supportedVulnerabilityClasses: ["sql-injection"],
    expectedFindingCount: 0,
    pairedFixtureId: "structural-vulnerable",
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
    fixtureId: "structural-fixture",
    findings: [],
  });
  await writeJson(path.join(root, "labels.json"), {
    expected: ["answer-key"],
  });
  await writeJson(path.join(root, "oracle.json"), {
    oracle: true,
  });
  await writeJson(path.join(root, "evaluation.json"), {
    score: 1,
  });
  return root;
}

async function writeJson(file: string, value: unknown): Promise<void> {
  await fs.writeFile(
    file,
    `${JSON.stringify(value, null, 2)}\n`,
    "utf8",
  );
}
