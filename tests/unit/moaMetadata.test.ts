import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { renderReport } from "../../src/reports/reportRenderer.js";
import type { AgentSummary } from "../../src/reports/schema.js";
import type { ScanRun } from "../../src/shared/types.js";

test("MoA judge status and aggregation metadata survive report rendering", async () => {
  const reportRoot = await fs.mkdtemp(path.join(os.tmpdir(), "hermsec-moa-report-"));
  const metadata = {
    judge: {
      status: "completed",
      provider: "openai-compatible",
      model: "judge-model",
    },
    aggregation: {
      strategy: "majority-vote",
      candidateCount: 3,
      acceptedFindingIds: ["finding-moa-1"],
      rejectedCandidateIds: ["agent-b"],
    },
  };

  try {
    const result = await renderReport({
      scanRun: scanRun(),
      workspaceId: "workspace-moa",
      workspaceName: "MoA Workspace",
      configuredReportDir: reportRoot,
      formats: ["json"],
      generatedAt: "2026-06-27T00:00:01.000Z",
      indexPath: path.join(reportRoot, "index.json"),
      agentSummary: {
        provider: "moa-assisted",
        executiveSummary: "MoA judge accepted agent candidate evidence.",
        priorityActions: ["Fix finding-moa-1."],
        moa: metadata,
      } as Partial<AgentSummary> & { moa: typeof metadata },
    });

    const agentSummary = JSON.parse(await fs.readFile(result.artifacts.agentSummaryPath, "utf8")) as {
      moa?: typeof metadata;
    };

    assert.equal(agentSummary.moa?.judge.status, "completed");
    assert.deepEqual(agentSummary.moa?.aggregation, metadata.aggregation);
  } finally {
    await fs.rm(reportRoot, { recursive: true, force: true });
  }
});

function scanRun(): ScanRun {
  return {
    schemaVersion: "1.0",
    id: "scan-moa",
    target: path.resolve("tests/fixtures/repos/node-express-clean/project"),
    mode: "offline",
    startedAt: "2026-06-27T00:00:00.000Z",
    finishedAt: "2026-06-27T00:00:01.000Z",
    durationMs: 1000,
    scannerStatuses: [
      {
        id: "semgrep",
        label: "Semgrep",
        status: "completed",
        message: "fixture scan completed",
      },
    ],
    findings: [
      {
        id: "finding-moa-1",
        title: "Dynamic SQL construction",
        category: "code",
        severity: "high",
        confidence: "high",
        description: "Scanner found dynamic SQL construction.",
        evidence: "src/routes/search.js:7 dynamic SQL construction",
        remediation: "Use parameterized queries.",
        tool: "semgrep",
        ruleId: "javascript.sql-injection",
        cwe: ["CWE-89"],
        location: {
          file: "src/routes/search.js",
          startLine: 7,
        },
        fingerprint: "fp-moa-1",
      },
    ],
    summary: {
      total: 1,
      critical: 0,
      high: 1,
      medium: 0,
      low: 0,
      info: 0,
    },
  };
}
