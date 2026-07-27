import assert from "node:assert/strict";
import test from "node:test";
import {
  parseGroundTruthDocument,
  validateFixtureManifestV2,
  validateTruthSetV2,
} from "../../../src/eval/index.js";

test("truth schema 2.0 validates explicit class, evidence, and policy", () => {
  const truth = validateTruthSetV2({
    schemaVersion: "2.0",
    fixtureId: "fixture",
    findings: [validFinding()],
  });

  assert.equal(truth.findings.length, 1);
  assert.equal(truth.findings[0]?.vulnerabilityClass, "sql-injection");
  assert.equal(truth.findings[0]?.location?.path, "src/db.js");
});

test("truth schema 2.0 rejects missing vulnerability class and evidence", () => {
  const withoutClass = { ...validFinding() };
  delete (withoutClass as { vulnerabilityClass?: string }).vulnerabilityClass;
  assert.throws(
    () =>
      validateTruthSetV2({
        schemaVersion: "2.0",
        fixtureId: "fixture",
        findings: [withoutClass],
      }),
    /vulnerabilityClass is required/,
  );

  const withoutEvidence = { ...validFinding() };
  delete (withoutEvidence as { evidence?: unknown }).evidence;
  assert.throws(
    () =>
      validateTruthSetV2({
        schemaVersion: "2.0",
        fixtureId: "fixture",
        findings: [withoutEvidence],
      }),
    /evidence is required/,
  );
});

test("truth schema 2.0 rejects duplicate finding IDs", () => {
  assert.throws(
    () =>
      validateTruthSetV2({
        schemaVersion: "2.0",
        fixtureId: "fixture",
        findings: [validFinding(), validFinding()],
      }),
    /finding id must be unique/,
  );
});

test("legacy truth arrays remain readable", () => {
  const findings = parseGroundTruthDocument([
    {
      id: "legacy",
      category: "code",
      title: "SQL injection",
      severity: "high",
      cwe: ["cwe-089"],
      identifiers: { cve: [], ghsa: [], osv: [] },
      location: { file: "src/db.js", startLine: 3 },
    },
  ]);

  assert.equal(findings[0]?.cwe[0], "CWE-89");
  assert.equal(findings[0]?.location?.path, "src/db.js");
});

test("fixture manifests require explicit safety and zero clean findings", () => {
  const manifest = validateFixtureManifestV2({
    schemaVersion: "2.0",
    id: "clean",
    pairId: "pair",
    variant: "clean",
    language: "javascript",
    projectRoot: "project",
    evaluatorFiles: ["truth.json"],
    entrypoints: ["src/server.js"],
    sourceFiles: ["src/server.js"],
    supportedVulnerabilityClasses: ["sql-injection"],
    expectedFindingCount: 0,
    pairedFixtureId: "vulnerable",
    safety: {
      networkRequired: false,
      executionRequired: false,
      containsRealSecrets: false,
      executionPolicy: "never",
      networkPolicy: "deny",
    },
  });

  assert.equal(manifest.variant, "clean");
  assert.throws(
    () =>
      validateFixtureManifestV2({
        ...manifest,
        expectedFindingCount: 1,
      }),
    /clean fixture expectedFindingCount must be zero/,
  );
  assert.throws(
    () =>
      validateFixtureManifestV2({
        ...manifest,
        safety: {
          ...manifest.safety,
          executionPolicy: "allowed",
        },
      }),
    /deny execution and network access/,
  );
});

test("schema 2.0 rejects escaping fixture paths and invalid line ranges", () => {
  assert.throws(
    () =>
      validateTruthSetV2({
        schemaVersion: "2.0",
        fixtureId: "fixture",
        findings: [
          {
            ...validFinding(),
            location: { path: "../outside.js", startLine: 3 },
          },
        ],
      }),
    /repository-relative/,
  );
  assert.throws(
    () =>
      validateTruthSetV2({
        schemaVersion: "2.0",
        fixtureId: "fixture",
        findings: [
          {
            ...validFinding(),
            location: {
              path: "src/db.js",
              startLine: 10,
              endLine: 2,
            },
          },
        ],
      }),
    /endLine cannot precede startLine/,
  );
});

function validFinding() {
  return {
    id: "GT-SQLI",
    category: "code",
    vulnerabilityClass: "sql-injection",
    title: "SQL injection",
    severity: "high",
    cwe: ["CWE-89"],
    identifiers: { cve: [], ghsa: [], osv: [] },
    location: { path: "src/db.js", startLine: 3 },
    evidence: { type: "primary-location" },
    matchPolicy: {
      category: "exact",
      vulnerabilityClass: "compatible",
      location: "required",
      line: "required",
      evidence: "primary-location",
    },
  };
}
