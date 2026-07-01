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
    path.resolve("Test projects/primary_tests/nodejs-express-app"),
    path.resolve("Test projects/primary_tests/python-flask-app"),
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
      recall >= 0.4,
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
  ruleIds?: string[];
  location?: {
    file?: string;
  };
};

async function readExpectedFindings(lab: string): Promise<ExpectedFinding[]> {
  const raw = await fs.readFile(path.join(lab, "ground-truth.json"), "utf8");
  const parsed = JSON.parse(raw) as {
    vulnerabilities?: Array<{
      category: string;
      cwe?: string;
      file?: string;
    }>;
  };
  assert.ok(Array.isArray(parsed.vulnerabilities));
  return parsed.vulnerabilities.map((item) => {
    const finding: ExpectedFinding = {
      category: normalizeExpectedCategory(item.category),
    };
    if (item.cwe) {
      finding.cwe = [item.cwe];
    }
    if (item.file) {
      finding.location = { file: item.file };
    }
    return finding;
  });
}

function matchesExpectedFinding(finding: Finding, expected: ExpectedFinding): boolean {
  const categoryMatches = finding.category === expected.category || normalizeExpectedCategory(finding.category) === expected.category;
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

function normalizeExpectedCategory(category: string): string {
  if (category === "hardcoded-secret") return "secret";
  if (category === "supply-chain") return "supply-chain";
  if (category === "dependency") return "dependency";
  if (category === "config") return "config";
  if (
    category === "sql-injection" ||
    category === "command-injection" ||
    category === "code-injection" ||
    category === "xss" ||
    category === "path-traversal" ||
    category === "tls-disabled" ||
    category === "deserialization" ||
    category === "weak-crypto" ||
    category === "debug-enabled"
  ) {
    return "code";
  }
  return category;
}
