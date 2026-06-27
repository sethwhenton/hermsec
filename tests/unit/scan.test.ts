import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { runScan } from "../../src/core/scan.js";
import type { Finding, ScanProgressEvent } from "../../src/shared/types.js";

const fixtureRoot = path.resolve("tests/fixtures/repos");

test("offline scan finds toy vulnerable Node findings", async () => {
  const run = await runScan({ target: path.join(fixtureRoot, "node-express-vulnerable"), mode: "offline" });
  assert.equal(run.summary.critical >= 1, true);
  assert.equal(run.findings.some((finding) => finding.cwe?.includes("CWE-89")), true);
  assert.equal(run.findings.some((finding) => finding.category === "secret"), true);
  assert.equal(run.findings.some((finding) => finding.evidence.includes("DO_NOT_USE_123")), false);
});

test("clean fixture has no high or critical findings", async () => {
  const run = await runScan({ target: path.join(fixtureRoot, "node-express-clean"), mode: "offline" });
  assert.equal(run.summary.critical, 0);
  assert.equal(run.summary.high, 0);
});

test("offline scan covers Hermsec MVP vulnerable test projects with measurable recall", async () => {
  const labs = [
    path.resolve("Test projects/hermsec-node-express-vuln-lab"),
    path.resolve("Test projects/hermsec-python-flask-vuln-lab"),
  ];

  for (const lab of labs) {
    const expected = await readExpectedFindings(lab);
    const run = await runScan({ target: lab, mode: "offline" });
    const matched = expected.filter((item) =>
      run.findings.some((finding) => matchesExpectedFinding(finding, item)),
    );
    const recall = matched.length / expected.length;

    assert.equal(run.summary.total > 0, true, `${path.basename(lab)} should produce findings`);
    assert.equal(
      recall >= 0.5,
      true,
      `${path.basename(lab)} recall ${recall.toFixed(2)} was below MVP threshold`,
    );
  }
});

test("offline scan emits structured repository and heuristic progress", async () => {
  const events: ScanProgressEvent[] = [];
  const run = await runScan({
    target: path.join(fixtureRoot, "node-express-vulnerable"),
    mode: "offline",
    onProgress: (event) => events.push(event),
  });

  assert.equal(run.summary.total > 0, true);
  assert.equal(events.some((event) => event.schemaVersion === "1.0" && event.stage === "repository" && event.status === "running"), true);
  assert.equal(events.some((event) => event.stage === "repository" && event.status === "completed"), true);
  assert.equal(events.some((event) => event.stage === "scanner" && event.scannerId === "hermsec-heuristics" && event.status === "completed"), true);
  assert.equal(events.every((event) => typeof event.timestamp === "string" && event.timestamp.length > 0), true);
});

test("agent-only scan mode performs repository discovery without scanner execution", async () => {
  const events: ScanProgressEvent[] = [];
  const run = await runScan({
    target: path.join(fixtureRoot, "node-express-vulnerable"),
    mode: "online",
    assistMode: "moa-assisted",
    scannerMode: "none",
    onProgress: (event) => events.push(event),
  });

  assert.equal(run.summary.total, 0);
  assert.deepEqual(run.findings, []);
  assert.deepEqual(run.scannerStatuses.map((status) => status.id), ["repository-discovery"]);
  assert.equal(events.some((event) => event.stage === "repository" && event.status === "completed"), true);
  assert.equal(events.some((event) => event.stage === "scanner"), false);
});

type ExpectedFinding = {
  category: string;
  cwe?: string[];
  location?: {
    file?: string;
  };
  ruleIds?: string[];
};

async function readExpectedFindings(lab: string): Promise<ExpectedFinding[]> {
  const raw = await fs.readFile(path.join(lab, "expected-findings.json"), "utf8");
  const parsed = JSON.parse(raw) as { expectedFindings?: ExpectedFinding[] };
  assert.ok(Array.isArray(parsed.expectedFindings));
  return parsed.expectedFindings;
}

function matchesExpectedFinding(finding: Finding, expected: ExpectedFinding): boolean {
  const categoryMatches = finding.category === expected.category;
  const cweMatches =
    expected.cwe === undefined ||
    expected.cwe.some((cwe) => finding.cwe?.includes(cwe) === true);
  const locationMatches =
    expected.location?.file === undefined ||
    finding.location?.file.replace(/\\/g, "/").endsWith(expected.location.file) === true;
  const ruleMatches =
    expected.ruleIds === undefined ||
    expected.ruleIds.some((ruleId) => finding.ruleId === ruleId || finding.tool === ruleId);

  return categoryMatches && locationMatches && (cweMatches || ruleMatches);
}
