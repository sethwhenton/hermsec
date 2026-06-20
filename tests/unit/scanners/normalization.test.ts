import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { normalizeFindings } from "../../../src/scanners/normalization.js";
import type { Finding } from "../../../src/shared/types.js";

test("finding normalization fills required fields and normalizes repo paths", () => {
  const repoRoot = path.join(os.tmpdir(), "Hermsec Normalization Repo");
  const raw = {
    id: "",
    title: "",
    category: "code",
    severity: "medium",
    confidence: "medium",
    description: "",
    evidence: "",
    remediation: "",
    tool: "",
    location: {
      file: path.join(repoRoot, "src", "app.js"),
      startLine: 4,
    },
    fingerprint: "",
  } as Finding;

  const [finding] = normalizeFindings([raw], repoRoot);

  assert.ok(finding?.id.startsWith("finding-"));
  assert.equal(finding?.tool, "hermsec");
  assert.equal(finding?.ruleId, "hermsec.code.finding");
  assert.equal(finding?.location?.file, "src/app.js");
  assert.ok(finding?.title);
  assert.ok(finding?.description);
  assert.ok(finding?.evidence);
  assert.ok(finding?.remediation);
  assert.ok(finding?.fingerprint.startsWith("fp-"));
});

test("finding normalization keeps fingerprints stable for equivalent findings", () => {
  const repoRoot = path.join(os.tmpdir(), "Hermsec Stable Normalization Repo");
  const base: Finding = {
    id: "",
    title: "Dynamic SQL",
    category: "code",
    severity: "high",
    confidence: "high",
    description: "SQL risk",
    evidence: "src/App.java:10 SQL risk",
    remediation: "Use parameters.",
    tool: "semgrep",
    ruleId: "java.sql",
    location: { file: "src/App.java", startLine: 10 },
    fingerprint: "",
  };

  const [first] = normalizeFindings([base], repoRoot);
  const [second] = normalizeFindings([{ ...base }], repoRoot);

  assert.equal(first?.fingerprint, second?.fingerprint);
  assert.equal(first?.id, second?.id);
});
