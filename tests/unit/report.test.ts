import assert from "node:assert/strict";
import test from "node:test";
import { renderHtmlReport } from "../../src/reports/htmlRenderer.js";
import { renderMarkdownReport } from "../../src/reports/markdownRenderer.js";
import type { ReportDocument } from "../../src/reports/schema.js";

const document: ReportDocument = {
  schemaVersion: "1.0",
  scanId: "scan-test",
  workspaceId: "workspace-test",
  workspaceName: "fixture",
  generatedAt: "2026-05-31T00:00:01.000Z",
  target: {
    kind: "local-path",
    value: "fixture",
  },
  run: {
    id: "scan-test",
    mode: "offline",
    startedAt: "2026-05-31T00:00:00.000Z",
    finishedAt: "2026-05-31T00:00:01.000Z",
    durationMs: 1000,
  },
  tools: [],
  summary: {
    total: 1,
    critical: 0,
    high: 1,
    medium: 0,
    low: 0,
    info: 0,
    secrets: 1,
    confirmedCves: 0,
    knownExploited: 0,
    scannerFailures: 0,
    generatedWithModel: false,
  },
  findings: [
    {
      id: "finding-test",
      title: "Possible hardcoded secret",
      category: "secret",
      severity: "high",
      confidence: "confirmed",
      description: "test",
      evidence: "API_KEY=HERMSEC_FAKE_TEST_TOKEN_[REDACTED]",
      remediation: "rotate",
      tool: "hermsec-offline",
      fingerprint: "fp-test",
    },
  ],
  explanations: {},
  evidence: {
    bundleId: "bundle-test",
    redactionApplied: true,
    rawArtifacts: [],
    findingEvidence: {},
  },
  limitations: [],
};

test("reports render redacted fake secret values", () => {
  assert.equal(renderMarkdownReport(document).includes("DO_NOT_USE_123"), false);
  assert.equal(renderHtmlReport(document).includes("DO_NOT_USE_123"), false);
});
