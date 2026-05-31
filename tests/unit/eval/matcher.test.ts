import assert from "node:assert/strict";
import test from "node:test";
import {
  categoryMatrix,
  computeCategoryMetrics,
  computeMetrics,
  matchFindings,
  normalizeCve,
  normalizeEvalPath,
  scoreCandidate,
  type ActualFindingProjection,
  type GroundTruthFinding,
} from "../../../src/eval/index.js";

test("evaluation matcher accepts a high-confidence code finding match", () => {
  const expected = makeCodeGroundTruth();
  const actual = makeActualCodeFinding();

  const candidate = scoreCandidate(expected, actual);

  assert.equal(candidate.expectedId, "GT-CODE-SQLI");
  assert.equal(candidate.actualFingerprint, "actual-code-sqli");
  assert.ok(candidate.score >= 60);
  assert.deepEqual(
    candidate.signals.map((signal) => signal.name),
    ["category", "location", "rule", "cwe", "severity"],
  );
});

test("evaluation metrics report precision, recall, and F1 from one-to-one matches", () => {
  const expected: GroundTruthFinding[] = [
    makeCodeGroundTruth(),
    {
      ...makeCodeGroundTruth(),
      id: "GT-CODE-CMD",
      cwe: ["CWE-78"],
      title: "Command injection",
      location: { path: "src/routes/search.js", startLine: 50 },
      ruleIds: ["semgrep.command-injection"],
    },
  ];
  const actual: ActualFindingProjection[] = [
    makeActualCodeFinding(),
    {
      ...makeActualCodeFinding(),
      id: "ACTUAL-SPURIOUS",
      fingerprint: "actual-spurious",
      title: "Spurious low finding",
      severity: "low" as const,
      cwe: ["CWE-327"],
      location: { path: "src/other.js", startLine: 5 },
      ruleIds: ["semgrep.weak-crypto"],
    },
  ];

  const result = matchFindings(expected, actual);
  const metrics = computeMetrics(result);

  assert.equal(result.matches.length, 1);
  assert.equal(result.falsePositives.length, 1);
  assert.equal(result.falseNegatives.length, 1);
  assert.equal(metrics.truePositive, 1);
  assert.equal(metrics.falsePositive, 1);
  assert.equal(metrics.falseNegative, 1);
  assert.equal(metrics.precision, 0.5);
  assert.equal(metrics.recall, 0.5);
  assert.equal(metrics.f1, 0.5);
});

test("dependency findings require package and advisory evidence for a strong match", () => {
  const expected: GroundTruthFinding = {
    id: "GT-DEP-LODASH",
    category: "dependency",
    title: "Vulnerable lodash fixture dependency",
    severity: "high",
    cwe: [],
    identifiers: { cve: ["CVE-2021-23337"], ghsa: ["GHSA-35jh-r3h4-6jhm"], osv: [] },
    package: { ecosystem: "npm", name: "lodash", installedVersion: "4.17.20" },
    ruleIds: ["npm-audit"],
  };
  const actual: ActualFindingProjection = {
    id: "ACTUAL-DEP-LODASH",
    fingerprint: "actual-dep-lodash",
    category: "dependency",
    title: "lodash advisory",
    severity: "high",
    cwe: [],
    identifiers: { cve: ["cve-2021-23337"], ghsa: [], osv: [] },
    package: { ecosystem: "NPM", name: "lodash", installedVersion: "4.17.20" },
    ruleIds: ["npm-audit"],
  };

  const result = matchFindings([expected], [actual]);

  assert.equal(result.matches.length, 1);
  assert.ok((result.matches[0]?.score ?? 0) >= 100);
});

test("normalizers canonicalize identifiers and paths for stable matching", () => {
  assert.equal(normalizeCve("cve_2021_23337"), "CVE-2021-23337");
  assert.equal(
    normalizeEvalPath("E:\\Programming\\Security insider II\\Hermsec Proj\\tests\\fixtures\\repos\\node\\src\\app.js"),
    "E:/Programming/Security insider II/Hermsec Proj/tests/fixtures/repos/node/src/app.js",
  );
});

test("category matrices include missed and spurious buckets", () => {
  const result = matchFindings([makeCodeGroundTruth()], []);
  const matrix = categoryMatrix(result);
  const byCategory = computeCategoryMetrics(result);

  assert.equal(matrix.code?.["<missed>"], 1);
  assert.equal(byCategory.code.falseNegative, 1);
  assert.equal(byCategory.code.recall, 0);
});

function makeCodeGroundTruth(): GroundTruthFinding {
  return {
    id: "GT-CODE-SQLI",
    category: "code",
    title: "SQL injection in fixture search route",
    severity: "high",
    cwe: ["CWE-89"],
    identifiers: { cve: [], ghsa: [], osv: [] },
    location: { path: "src/routes/search.js", startLine: 14 },
    ruleIds: ["semgrep.sql-injection"],
    matchHints: { lineTolerance: 3 },
  };
}

function makeActualCodeFinding(): ActualFindingProjection {
  return {
    id: "ACTUAL-CODE-SQLI",
    fingerprint: "actual-code-sqli",
    category: "code",
    title: "Possible SQL injection",
    severity: "high",
    cwe: ["cwe-089"],
    identifiers: { cve: [], ghsa: [], osv: [] },
    location: { path: "src/routes/search.js", startLine: 15 },
    ruleIds: ["SEMgrep.SQL-Injection"],
    tool: "semgrep",
  };
}
