import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { loadEvaluationFixture } from "../../../src/eval/suite.js";

const reposRoot = path.resolve("tests/fixtures/repos");
const fixtureIds = [
  "node-express-vulnerable",
  "node-express-clean",
  "python-flask-vulnerable",
  "python-flask-clean",
] as const;

const pairExpectations = [
  {
    vulnerable: "node-express-vulnerable",
    clean: "node-express-clean",
    pairId: "medium-node-express-security-pair",
  },
  {
    vulnerable: "python-flask-vulnerable",
    clean: "python-flask-clean",
    pairId: "medium-python-flask-security-pair",
  },
] as const;

const truthExpectations = {
  "NODE-EXPRESS-SQLI-001": {
    vulnerabilityClass: "sql-injection",
    cwe: "CWE-89",
    path: "src/routes/search.js",
    line: 14,
    evidenceType: "primary-location",
    fragment: "SELECT * FROM users WHERE display_name",
  },
  "NODE-EXPRESS-CMDI-001": {
    vulnerabilityClass: "command-injection",
    cwe: "CWE-78",
    path: "src/routes/search.js",
    line: 19,
    evidenceType: "primary-location",
    fragment: "exec(`echo ${String(req.query.host",
  },
  "NODE-EXPRESS-PATH-001": {
    vulnerabilityClass: "path-traversal",
    cwe: "CWE-22",
    path: "src/routes/search.js",
    line: 26,
    evidenceType: "primary-location",
    fragment: "fs.readFileSync(filePath",
  },
  "NODE-EXPRESS-XSS-001": {
    vulnerabilityClass: "reflected-xss",
    cwe: "CWE-79",
    path: "src/routes/search.js",
    line: 33,
    evidenceType: "primary-location",
    fragment: "res.send(`<h1>${name}</h1>",
  },
  "NODE-EXPRESS-CRYPTO-001": {
    vulnerabilityClass: "weak-cryptography",
    cwe: "CWE-328",
    path: "src/routes/search.js",
    line: 32,
    evidenceType: "primary-location",
    fragment: 'crypto.createHash("md5")',
  },
  "NODE-EXPRESS-SECRET-001": {
    vulnerabilityClass: "hardcoded-secret",
    cwe: "CWE-798",
    path: "src/routes/search.js",
    line: 7,
    evidenceType: "secret-location",
    fragment: "HERMSEC_FAKE_TEST_TOKEN_DO_NOT_USE_NODE_FIXTURE",
  },
  "PYTHON-FLASK-SQLI-001": {
    vulnerabilityClass: "sql-injection",
    cwe: "CWE-89",
    path: "app.py",
    line: 15,
    evidenceType: "primary-location",
    fragment: "SELECT * FROM users WHERE display_name",
  },
  "PYTHON-FLASK-CMDI-001": {
    vulnerabilityClass: "command-injection",
    cwe: "CWE-78",
    path: "app.py",
    line: 22,
    evidenceType: "primary-location",
    fragment: "subprocess.check_output",
  },
  "PYTHON-FLASK-PATH-001": {
    vulnerabilityClass: "path-traversal",
    cwe: "CWE-22",
    path: "app.py",
    line: 30,
    evidenceType: "primary-location",
    fragment: "with open(file_path",
  },
  "PYTHON-FLASK-XSS-001": {
    vulnerabilityClass: "reflected-xss",
    cwe: "CWE-79",
    path: "app.py",
    line: 38,
    evidenceType: "primary-location",
    fragment: "render_template_string(f",
  },
  "PYTHON-FLASK-CRYPTO-001": {
    vulnerabilityClass: "weak-cryptography",
    cwe: "CWE-328",
    path: "app.py",
    line: 37,
    evidenceType: "primary-location",
    fragment: "hashlib.md5",
  },
  "PYTHON-FLASK-SECRET-001": {
    vulnerabilityClass: "hardcoded-secret",
    cwe: "CWE-798",
    path: "app.py",
    line: 9,
    evidenceType: "secret-location",
    fragment: "HERMSEC_FAKE_TEST_TOKEN_DO_NOT_USE_PYTHON_FIXTURE",
  },
} as const;

test("medium research fixtures load through the strict inert fixture contract", async () => {
  const fixtures = await Promise.all(
    fixtureIds.map((fixtureId) =>
      loadEvaluationFixture(path.join(reposRoot, fixtureId)),
    ),
  );
  const byId = new Map(
    fixtures.map((fixture) => [fixture.manifest.id, fixture]),
  );

  assert.deepEqual(
    fixtures.map((fixture) => fixture.manifest.id),
    [...fixtureIds],
  );
  assert.equal(
    fixtures.reduce(
      (total, fixture) => total + fixture.truth.findings.length,
      0,
    ),
    12,
  );
  assert.equal(
    byId.get("node-express-vulnerable")?.truth.findings.length,
    6,
  );
  assert.equal(
    byId.get("python-flask-vulnerable")?.truth.findings.length,
    6,
  );
  assert.equal(byId.get("node-express-clean")?.truth.findings.length, 0);
  assert.equal(byId.get("python-flask-clean")?.truth.findings.length, 0);

  for (const fixture of fixtures) {
    assert.equal(fixture.manifest.safety.executionPolicy, "never");
    assert.equal(fixture.manifest.safety.networkPolicy, "deny");
    assert.equal(fixture.manifest.safety.containsRealSecrets, false);
    assert.ok(fixture.sourceLines > 0);
  }

  for (const expected of pairExpectations) {
    const vulnerable = byId.get(expected.vulnerable)?.manifest;
    const clean = byId.get(expected.clean)?.manifest;
    assert.ok(vulnerable);
    assert.ok(clean);
    assert.equal(vulnerable.pairId, expected.pairId);
    assert.equal(clean.pairId, expected.pairId);
    assert.equal(vulnerable.variant, "vulnerable");
    assert.equal(clean.variant, "clean");
    assert.equal(vulnerable.pairedFixtureId, clean.id);
    assert.equal(clean.pairedFixtureId, vulnerable.id);
    assert.deepEqual(vulnerable.sourceFiles, clean.sourceFiles);
    assert.deepEqual(
      vulnerable.supportedVulnerabilityClasses,
      clean.supportedVulnerabilityClasses,
    );
  }
});

test("every medium truth label is pinned to its intended class and source construct", async () => {
  const seen = new Set<string>();
  for (const fixtureId of [
    "node-express-vulnerable",
    "python-flask-vulnerable",
  ] as const) {
    const fixtureRoot = path.join(reposRoot, fixtureId);
    const fixture = await loadEvaluationFixture(fixtureRoot);
    for (const finding of fixture.truth.findings) {
      const expected =
        truthExpectations[finding.id as keyof typeof truthExpectations];
      assert.ok(expected, `unexpected medium truth finding ${finding.id}`);
      assert.equal(finding.vulnerabilityClass, expected.vulnerabilityClass);
      assert.deepEqual(finding.cwe, [expected.cwe]);
      if (!finding.evidence) {
        assert.fail(`${finding.id} must include an evidence descriptor`);
      }
      assert.equal(finding.evidence.type, expected.evidenceType);
      assert.ok(finding.location, `${finding.id} must have a primary location`);
      const location = finding.location;
      assert.equal(location.path, expected.path);
      assert.equal(location.startLine, expected.line);
      assert.ok(
        Number.isInteger(location.startLine) && (location.startLine ?? 0) > 0,
        `${finding.id} must have a positive source line`,
      );
      const startLine = location.startLine as number;
      const source = await fs.readFile(
        path.join(fixture.projectRoot, location.path),
        "utf8",
      );
      const line = source.split(/\r?\n/u)[startLine - 1];
      if (!line?.trim()) {
        assert.fail(`${finding.id} must resolve to non-empty source`);
      }
      assert.ok(
        line.includes(expected.fragment),
        `${finding.id} must remain anchored to ${JSON.stringify(expected.fragment)}`,
      );
      assert.ok(
        fixture.manifest.sourceFiles.includes(location.path),
        `${finding.id} must reference a declared source file`,
      );
      seen.add(finding.id);
    }
  }
  assert.deepEqual(
    [...seen].sort(),
    Object.keys(truthExpectations).sort(),
  );
});
