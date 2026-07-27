import assert from "node:assert/strict";
import test from "node:test";
import {
  executeScanProjectRequest,
  validateScanProjectRequest,
} from "../src/main/scanRequestValidation.ts";

const hash = "a".repeat(64);
const capturedAt = "2026-07-25T00:00:00.000Z";

test("scan request validation defaults to scanner-only and derives useModel", () => {
  const scanner = validateScanProjectRequest({
    targetPath: "C:\\repo",
    reportDir: "C:\\reports",
  });
  assert.equal(scanner.ok, true);
  if (scanner.ok) {
    assert.equal(scanner.request.mode, "online");
    assert.equal(scanner.request.assistMode, "scanner-only");
    assert.equal(scanner.request.useModel, false);
  }

  const agent = validateScanProjectRequest({
    targetPath: "C:\\repo",
    assistMode: "scanner-moa-high",
    useModel: false,
  });
  assert.equal(agent.ok, true);
  if (agent.ok) {
    assert.equal(agent.request.assistMode, "scanner-moa-high");
    assert.equal(agent.request.useModel, true);
  }
});

test("scan request validation accepts a safe project fingerprint clone", () => {
  const result = validateScanProjectRequest({
    runId: "renderer-safe.1",
    targetPath: "C:\\repo",
    mode: "online",
    assistMode: "scanner-single",
    useModel: true,
    skipIfUnchanged: true,
    previousProjectState: {
      kind: "git",
      fingerprint: hash,
      gitHead: "abc123",
      gitBranch: "main",
      gitDirty: false,
      gitStatusHash: hash,
      capturedAt,
    },
  });

  assert.equal(result.ok, true);
  if (result.ok) {
    assert.deepEqual(result.request.previousProjectState, {
      kind: "git",
      fingerprint: hash,
      gitHead: "abc123",
      gitBranch: "main",
      gitDirty: false,
      gitStatusHash: hash,
      capturedAt,
    });
  }
});

test("scan request validation rejects malformed IPC fields without throwing", () => {
  const invalidRequests: unknown[] = [
    null,
    [],
    "scan",
    { unexpected: true },
    { runId: 42 },
    { runId: "bad run id" },
    { targetPath: 42 },
    { targetPath: "C:\\repo\u0000bad" },
    { reportDir: "" },
    { mode: "offline" },
    { assistMode: "deep-assisted" },
    { useModel: "yes" },
    { skipIfUnchanged: 1 },
    { previousProjectState: null },
    { previousProjectState: { kind: "git", fingerprint: "short", capturedAt } },
    { previousProjectState: { kind: "other", fingerprint: hash, capturedAt } },
    { previousProjectState: { kind: "git", fingerprint: hash, capturedAt: "yesterday" } },
    { previousProjectState: { kind: "git", fingerprint: hash, capturedAt, extra: true } },
  ];

  for (const request of invalidRequests) {
    assert.doesNotThrow(() => validateScanProjectRequest(request));
    const result = validateScanProjectRequest(request);
    assert.equal(result.ok, false);
    if (!result.ok) {
      assert.equal(result.result.ok, false);
      assert.equal(result.result.error, "invalid-scan-request");
      assert.equal(result.result.assistMode, "scanner-only");
      assert.equal(result.result.terminalStatus, "failed");
    }
  }
});

test("scan IPC execution never leaks executor throws across the boundary", async () => {
  let called = false;
  const invalid = await executeScanProjectRequest(null, async () => {
    called = true;
    throw new Error("should not run");
  });
  assert.equal(called, false);
  assert.equal(invalid.error, "invalid-scan-request");

  const failed = await executeScanProjectRequest(
    { runId: "run-safe", targetPath: "C:\\repo", assistMode: "single-agent" },
    async () => {
      throw new Error("sensitive internal failure");
    },
  );
  assert.equal(failed.ok, false);
  assert.equal(failed.error, "scan-handler-failed");
  assert.equal(failed.runId, "run-safe");
  assert.equal(failed.assistMode, "single-agent");
  assert.doesNotMatch(failed.message, /sensitive/u);
});
