import assert from "node:assert/strict";
import test from "node:test";
import { validateModelExplanation, type ModelExplanation } from "../../src/agent/structuredOutput.js";
import type { Finding } from "../../src/shared/types.js";

const baseFinding: Finding = {
  id: "finding-1",
  title: "Prototype pollution in lodash",
  category: "dependency",
  severity: "high",
  confidence: "confirmed",
  description: "lodash 4.17.20 is vulnerable.",
  evidence: "npm audit reported CVE-2021-23337 for lodash.",
  remediation: "Upgrade lodash to a fixed version.",
  tool: "npm-audit",
  ruleId: "npm-audit:lodash",
  cwe: ["CWE-79"],
  identifiers: {
    cve: ["CVE-2021-23337"],
  },
  package: {
    ecosystem: "npm",
    name: "lodash",
    installedVersion: "4.17.20",
  },
  fingerprint: "test-finding-1",
};

const baseExplanation: ModelExplanation = {
  title: "Lodash dependency vulnerability",
  impact: "This affects code that consumes the vulnerable lodash package.",
  evidenceSummary: "The scanner reported CVE-2021-23337 for lodash.",
  suggestedFix: "Upgrade lodash using the project's approved dependency workflow.",
  confidenceReason: "The finding is based on a known vulnerability reported for a specific package version.",
  safeNextSteps: ["Review the dependency change.", "Run Hermsec again after the fix."],
  cveUsage: "from_evidence",
};

test("model explanation validation allows generic package wording", () => {
  const result = validateModelExplanation(baseFinding, baseExplanation);

  assert.equal(result.ok, true);
});

test("model explanation validation allows the package from finding evidence", () => {
  const result = validateModelExplanation(baseFinding, {
    ...baseExplanation,
    confidenceReason: "The scanner identified package lodash and supplied the CVE evidence.",
  });

  assert.equal(result.ok, true);
});

test("model explanation validation rejects invented package mentions", () => {
  const result = validateModelExplanation(baseFinding, {
    ...baseExplanation,
    confidenceReason: "The scanner identified package express and supplied the CVE evidence.",
  });

  assert.equal(result.ok, false);
  assert.ok(result.violations.includes("invented package name: package express"));
});

test("model explanation validation rejects invented CWE identifiers", () => {
  const result = validateModelExplanation(baseFinding, {
    ...baseExplanation,
    evidenceSummary: "The scanner reported CVE-2021-23337 and CWE-89 for lodash.",
  });

  assert.equal(result.ok, false);
  assert.ok(result.violations.includes("invented CWE identifier: CWE-89"));
});

test("model explanation validation rejects invented scanner ids", () => {
  const result = validateModelExplanation(baseFinding, {
    ...baseExplanation,
    confidenceReason: "This was confirmed by semgrep.",
  });

  assert.equal(result.ok, false);
  assert.ok(result.violations.includes("invented scanner id: semgrep"));
});

test("model explanation validation rejects invented finding ids", () => {
  const result = validateModelExplanation(baseFinding, {
    ...baseExplanation,
    evidenceSummary: "This explanation applies to finding id finding-999.",
  });

  assert.equal(result.ok, false);
  assert.ok(result.violations.includes("invented finding id: finding-999"));
});

test("model explanation validation does not treat defensive slash phrases as file paths", () => {
  const { package: _ignoredPackage, ...findingWithoutPackage } = baseFinding;
  const result = validateModelExplanation({
    ...findingWithoutPackage,
    category: "code",
    location: {
      file: "src/app.js",
      startLine: 5,
    },
  }, {
    ...baseExplanation,
    evidenceSummary: "The scanner found dynamic SQL construction in src/app.js at line 5.",
    suggestedFix: "Use parameterized queries or a query builder.",
    confidenceReason: "The scanner identified a risky source pattern.",
    safeNextSteps: [
      "Refactor the SQL query to use parameterized statements or an ORM/query builder to prevent injection.",
    ],
    cveUsage: "not_present",
  });

  assert.equal(result.ok, true);
});
