import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import {
  validateFixtureManifestV2,
  validateTruthSetV2,
} from "../../../src/eval/index.js";

const fixtureRoot = path.resolve(
  process.cwd(),
  "tests/fixtures/research",
);
const vulnerableRoot = path.join(fixtureRoot, "micro-js-vulnerable");
const cleanRoot = path.join(fixtureRoot, "micro-js-clean");

test("paired micro fixtures expose identical source structure and explicit truth", async () => {
  const [vulnerableManifest, cleanManifest, vulnerableTruth, cleanTruth] =
    await Promise.all([
      readManifest(vulnerableRoot),
      readManifest(cleanRoot),
      readTruth(vulnerableRoot),
      readTruth(cleanRoot),
    ]);

  assert.equal(vulnerableManifest.pairedFixtureId, cleanManifest.id);
  assert.equal(cleanManifest.pairedFixtureId, vulnerableManifest.id);
  assert.equal(vulnerableManifest.pairId, cleanManifest.pairId);
  assert.deepEqual(
    vulnerableManifest.sourceFiles,
    cleanManifest.sourceFiles,
  );
  assert.deepEqual(
    vulnerableManifest.supportedVulnerabilityClasses,
    cleanManifest.supportedVulnerabilityClasses,
  );
  assert.equal(vulnerableTruth.findings.length, 4);
  assert.equal(cleanTruth.findings.length, 0);
  assert.equal(vulnerableManifest.expectedFindingCount, 4);
  assert.equal(cleanManifest.expectedFindingCount, 0);
  assert.equal(vulnerableManifest.safety.executionPolicy, "never");
  assert.equal(cleanManifest.safety.executionPolicy, "never");
  assert.equal(vulnerableManifest.safety.networkPolicy, "deny");
  assert.equal(cleanManifest.safety.networkPolicy, "deny");

  for (const sourceFile of vulnerableManifest.sourceFiles) {
    await Promise.all([
      fs.access(path.join(vulnerableRoot, "project", sourceFile)),
      fs.access(path.join(cleanRoot, "project", sourceFile)),
    ]);
  }
});

test("the vulnerable truth has exactly one SQLi, command injection, reflected XSS, and fake secret", async () => {
  const truth = await readTruth(vulnerableRoot);

  assert.deepEqual(
    truth.findings
      .map((finding) => finding.vulnerabilityClass)
      .sort(),
    [
      "command-injection",
      "hardcoded-secret",
      "reflected-xss",
      "sql-injection",
    ],
  );
  assert.deepEqual(
    truth.findings.map((finding) => finding.id).sort(),
    [
      "MICRO-JS-CMDI-001",
      "MICRO-JS-SECRET-001",
      "MICRO-JS-SQLI-001",
      "MICRO-JS-XSS-001",
    ],
  );
});

test("every labelled primary location resolves to a concrete fixture line", async () => {
  const truth = await readTruth(vulnerableRoot);

  for (const finding of truth.findings) {
    assert.ok(finding.location);
    assert.ok(finding.location?.startLine);
    const source = await fs.readFile(
      path.join(vulnerableRoot, "project", finding.location?.path ?? ""),
      "utf8",
    );
    const line = source.split(/\r?\n/)[
      (finding.location?.startLine ?? 1) - 1
    ];
    assert.ok(line?.trim(), `${finding.id} must reference a non-empty line`);
  }
});

async function readManifest(root: string) {
  const parsed = JSON.parse(
    await fs.readFile(path.join(root, "fixture.json"), "utf8"),
  ) as unknown;
  return validateFixtureManifestV2(parsed);
}

async function readTruth(root: string) {
  const parsed = JSON.parse(
    await fs.readFile(path.join(root, "truth.json"), "utf8"),
  ) as unknown;
  return validateTruthSetV2(parsed, path.join(root, "project"));
}
