import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import type {
  CanonicalAgentDetectorInput,
  CanonicalAgentDetectorResult,
} from "../../src/agent/canonicalHarness.js";
import { fuseFindings } from "../../src/agent/findingFusion.js";
import {
  runCanonicalScanOrchestration,
  type CanonicalAgentDetectorRunner,
  type CanonicalScannerRunner,
} from "../../src/core/canonicalOrchestrator.js";
import type {
  Finding,
  ScanProgressEvent,
  ScanRun,
} from "../../src/shared/types.js";

const fixtureRoot = path.resolve(
  "tests/fixtures/research/micro-js-vulnerable",
  "project",
);

test("scanner-only dispatches no model path and needs no resolver", async () => {
  let detectorCalls = 0;
  let scannerMode: string | undefined;
  const result = await runCanonicalScanOrchestration({
    target: fixtureRoot,
    assistMode: "scanner-only",
    runId: "scanner-only-run",
    scannerRunner: async (options) => {
      scannerMode = options.scannerMode;
      return scanRun([finding("scanner-1", "scanner")]);
    },
    agentDetectorRunner: async () => {
      detectorCalls += 1;
      throw new Error("detector must not run");
    },
    now: fixedClock(),
  });

  assert.equal(scannerMode, "full");
  assert.equal(detectorCalls, 0);
  assert.equal(result.mode, "scanner-only");
  assert.equal(result.terminalStatus, "success");
  assert.deepEqual(result.findings.map((item) => item.id), ["scanner-1"]);
});

test("agent-only mode uses repository discovery without reporting scanner findings", async () => {
  let scannerMode: string | undefined;
  let detectorMode: string | undefined;
  const agentFinding = finding("agent-1", "agent");
  const result = await runCanonicalScanOrchestration({
    target: fixtureRoot,
    assistMode: "single-agent",
    runId: "single-run",
    resolveModel: () => undefined,
    scannerRunner: async (options) => {
      scannerMode = options.scannerMode;
      return scanRun([finding("must-not-leak", "scanner")]);
    },
    agentDetectorRunner: async (input) => {
      detectorMode = input.mode;
      return agentResult("completed", [agentFinding]);
    },
    now: fixedClock(),
  });

  assert.equal(scannerMode, "none");
  assert.equal(detectorMode, "single");
  assert.equal(result.terminalStatus, "success");
  assert.deepEqual(result.scannerFindings, []);
  assert.deepEqual(result.findings.map((item) => item.id), ["agent-1"]);
});

test("hybrid paths preserve both raw detectors and fuse only afterward", async () => {
  const scannerFinding = finding("scanner-copy", "scanner");
  const agentFinding = {
    ...finding("agent-copy", "agent"),
    title: scannerFinding.title,
    fingerprint: scannerFinding.fingerprint,
  };
  const result = await runCanonicalScanOrchestration({
    target: fixtureRoot,
    assistMode: "scanner-single",
    runId: "hybrid-run",
    resolveModel: () => undefined,
    scannerRunner: async () => scanRun([scannerFinding]),
    agentDetectorRunner: async () =>
      agentResult("completed", [agentFinding]),
    now: fixedClock(),
  });

  assert.equal(result.terminalStatus, "success");
  assert.equal(result.scannerFindings.length, 1);
  assert.equal(result.agentFindings.length, 1);
  assert.equal(result.findings.length, 1);
  assert.ok(result.fusion);
  const provenance = result.fusion.sidecar.canonicalSources[0];
  assert.deepEqual(provenance?.scannerSourceIds, [
    `scanner:${scannerFinding.id}`,
  ]);
  assert.deepEqual(provenance?.agentSourceIds, [`agent:${agentFinding.id}`]);
  assert.ok(Object.isFrozen(result));
  assert.ok(Object.isFrozen(result.scannerFindings));
  assert.ok(Object.isFrozen(result.fusion.sidecar.canonicalSources));
});

test("hybrid agent failure is explicit and cannot erase scanner evidence", async () => {
  const scannerFinding = finding("scanner-survives", "scanner");
  const result = await runCanonicalScanOrchestration({
    target: fixtureRoot,
    assistMode: "scanner-moa-high",
    runId: "partial-run",
    resolveModel: () => undefined,
    scannerRunner: async () => scanRun([scannerFinding]),
    agentDetectorRunner: async () => {
      throw new Error("provider unavailable");
    },
    now: fixedClock(),
  });

  assert.equal(result.mode, "scanner-moa-high");
  assert.equal(result.terminalStatus, "partial");
  assert.deepEqual(result.findings.map((item) => item.id), [
    "scanner-survives",
  ]);
  assert.match(result.degradationReasons.join(" "), /provider unavailable/u);
});

test("pre-cancellation dispatches neither scanner nor agent", async () => {
  const controller = new AbortController();
  controller.abort(new Error("stop"));
  let calls = 0;
  const result = await runCanonicalScanOrchestration({
    target: fixtureRoot,
    assistMode: "scanner-moa-low",
    runId: "canceled-run",
    signal: controller.signal,
    scannerRunner: async () => {
      calls += 1;
      return scanRun([]);
    },
    agentDetectorRunner: async () => {
      calls += 1;
      return agentResult("completed", []);
    },
    now: fixedClock(),
  });

  assert.equal(calls, 0);
  assert.equal(result.terminalStatus, "canceled");
  assert.equal(result.scan.terminalStatus, "canceled");
});

test("progress is canonical, run-scoped, and ignores late scanner events", async () => {
  const events: ScanProgressEvent[] = [];
  let sendLateProgress: (() => void) | undefined;
  const scannerRunner: CanonicalScannerRunner = async (options) => {
    const event = scannerProgress("legacy-run");
    options.onProgress?.(event);
    sendLateProgress = () => options.onProgress?.({
      ...event,
      id: "late-event",
      timestamp: new Date().toISOString(),
    });
    return scanRun([]);
  };

  await runCanonicalScanOrchestration({
    target: fixtureRoot,
    assistMode: "scanner-only",
    runId: "canonical-run",
    scannerRunner,
    onProgress: (event) => events.push(event),
    now: fixedClock(),
  });
  const countAtCompletion = events.length;
  sendLateProgress?.();

  assert.ok(countAtCompletion > 0);
  assert.equal(events.length, countAtCompletion);
  assert.ok(events.every((event) => event.runId === "canonical-run"));
  assert.ok(events.every((event) => event.assistMode === "scanner-only"));
});

function scanRun(findings: Finding[]): ScanRun {
  return {
    schemaVersion: "1.0",
    id: "scanner-internal-run",
    target: fixtureRoot,
    mode: "online",
    startedAt: "2026-07-25T00:00:00.000Z",
    finishedAt: "2026-07-25T00:00:01.000Z",
    durationMs: 1_000,
    scannerStatuses: [
      {
        id: "fixture-scanner",
        label: "Fixture scanner",
        status: "completed",
        message: "Fixture scanner completed.",
      },
    ],
    findings,
    summary: {
      total: findings.length,
      critical: 0,
      high: findings.length,
      medium: 0,
      low: 0,
      info: 0,
    },
  };
}

function finding(id: string, tool: string): Finding {
  return {
    id,
    title: "User input reaches an unsafe SQL sink",
    category: "code",
    severity: "high",
    confidence: "high",
    description: "A controlled fixture finding.",
    evidence: "db.query(userSql)",
    remediation: "Use a parameterized query.",
    tool,
    ruleId: "fixture.sql-injection",
    cwe: ["CWE-89"],
    location: {
      file: "src/db/users.js",
      startLine: 3,
      endLine: 3,
    },
    sourceLocations: [
      {
        file: "src/server.js",
        startLine: 4,
        endLine: 4,
      },
    ],
    fingerprint: "fixture-shared-sql-fingerprint",
  };
}

function agentResult(
  status: CanonicalAgentDetectorResult["status"],
  findings: Finding[],
): Readonly<CanonicalAgentDetectorResult> {
  return {
    schemaVersion: "1.0",
    runId: "agent-internal-run",
    mode: "single",
    status,
    startedAt: "2026-07-25T00:00:00.000Z",
    finishedAt: "2026-07-25T00:00:01.000Z",
    profile: {
      schemaVersion: "1.0",
      repoRoot: fixtureRoot,
      files: [],
      fileSummary: {
        total: 0,
        source: 0,
        manifest: 0,
        lockfile: 0,
        config: 0,
        text: 0,
        bytes: 0,
        truncated: false,
      },
      languages: [],
      ecosystems: [],
      manifests: [],
      technologies: [],
      frameworks: [],
      capabilities: [],
      limitations: [],
    },
    findings,
    rawFindings: findings,
    candidates: [],
    agentFindingFusion: fuseFindings(
      findings.map((item) => ({
        finding: item,
        sourceKind: "agent",
      })),
      { repoRoot: fixtureRoot },
    ),
    traces: [],
    usages: [],
    coverage: {
      kind: "single",
      totalFiles: 0,
      inspectedFiles: [],
      uninspectedFiles: [],
      coverageRatio: 1,
    },
    limitations: [],
    roles: [],
    abstentions: [],
  };
}

function scannerProgress(runId: string): ScanProgressEvent {
  return {
    schemaVersion: "1.0",
    runId,
    id: "fixture-progress",
    stage: "scanner",
    label: "Fixture scanner",
    status: "running",
    message: "Fixture scanner is running.",
    assistMode: "deep-assisted",
    timestamp: new Date().toISOString(),
  };
}

function fixedClock(): () => Date {
  const values = [
    new Date("2026-07-25T00:00:00.000Z"),
    new Date("2026-07-25T00:00:01.000Z"),
    new Date("2026-07-25T00:00:02.000Z"),
  ];
  let index = 0;
  return () => values[Math.min(index++, values.length - 1)] as Date;
}

const _typeChecks: [
  CanonicalScannerRunner,
  CanonicalAgentDetectorRunner,
  CanonicalAgentDetectorInput,
] | undefined = undefined;
void _typeChecks;
