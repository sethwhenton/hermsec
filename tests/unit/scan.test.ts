import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import { runScan } from "../../src/core/scan.js";

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
