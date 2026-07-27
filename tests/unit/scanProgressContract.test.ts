import assert from "node:assert/strict";
import test from "node:test";
import { assistModeFrom, emitScanProgress } from "../../src/core/progress.js";
import type { ScanProgressEvent, ScanTerminalStatus } from "../../src/shared/types.js";

test("progress events preserve run-scoped tool metadata", () => {
  let observed: ScanProgressEvent | undefined;
  emitScanProgress((event) => {
    observed = event;
  }, {
    runId: "run-123",
    id: "tool-call-2",
    stage: "tool",
    componentId: "single-agent-inspector",
    roleId: "single-agent-inspector",
    round: 2,
    toolName: "read_file_snippet",
    label: "Read file snippet",
    status: "completed",
    resultCount: 1,
    bytesRead: 480,
    assistMode: "single-agent",
  });

  assert.equal(observed?.runId, "run-123");
  assert.equal(observed?.stage, "tool");
  assert.equal(observed?.round, 2);
  assert.equal(observed?.toolName, "read_file_snippet");
  assert.equal(observed?.bytesRead, 480);
  assert.equal(observed?.message, "Read file snippet");
});

test("terminal scan status distinguishes partial and degraded completion", () => {
  const values: ScanTerminalStatus[] = [
    "success",
    "partial",
    "degraded",
    "canceled",
    "failed",
    "unchanged",
  ];
  assert.equal(new Set(values).size, 6);
});

test("progress preserves canonical modes and migrates legacy input aliases", () => {
  assert.equal(assistModeFrom("scanner-only"), "scanner-only");
  assert.equal(assistModeFrom("single-agent"), "single-agent");
  assert.equal(assistModeFrom("scanner-single"), "scanner-single");
  assert.equal(assistModeFrom("moa-low"), "moa-low");
  assert.equal(assistModeFrom("moa-high"), "moa-high");
  assert.equal(assistModeFrom("scanner-moa-low"), "scanner-moa-low");
  assert.equal(assistModeFrom("scanner-moa-high"), "scanner-moa-high");
  assert.equal(assistModeFrom("deep-assisted"), "scanner-only");
  assert.equal(assistModeFrom("moa-assisted"), "moa-low");
});
