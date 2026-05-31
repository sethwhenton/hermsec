import assert from "node:assert/strict";
import test from "node:test";
import { evaluateFindings } from "../../src/eval/metrics.js";
import type { Finding } from "../../src/shared/types.js";

const finding: Finding = {
  id: "finding-1",
  title: "SQL query appears to include user-controlled input",
  category: "code",
  severity: "high",
  confidence: "medium",
  description: "test",
  evidence: "SELECT + req.query",
  remediation: "parameterize",
  tool: "hermsec-offline",
  cwe: ["CWE-89"],
  location: { file: "src/app.js", startLine: 8 },
  fingerprint: "fp-1",
};

test("evaluation computes precision recall and f1", () => {
  const metrics = evaluateFindings(
    [{ id: "truth-1", category: "code", severity: "high", cwe: ["CWE-89"], location: { file: "src/app.js", startLine: 8 } }],
    [finding],
  );
  assert.equal(metrics.truePositive, 1);
  assert.equal(metrics.falsePositive, 0);
  assert.equal(metrics.falseNegative, 0);
  assert.equal(metrics.f1, 1);
});
