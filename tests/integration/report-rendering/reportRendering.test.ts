import assert from "node:assert/strict";
import test from "node:test";
import { renderHtmlReport } from "../../../src/reports/htmlRenderer.js";
import { renderMarkdownReport } from "../../../src/reports/markdownRenderer.js";
import type { ReportDocument } from "../../../src/reports/schema.js";

test("report renderers escape HTML and keep Markdown finding content complete", () => {
  const document = makeReportDocument();
  const renderedHtml = renderHtmlReport(document);
  const renderedMarkdown = renderMarkdownReport(document);

  assert.doesNotMatch(renderedHtml, /<script>alert/);
  assert.match(renderedHtml, /&lt;script&gt;alert/);
  assert.match(renderedMarkdown, /Unsafe fixture title/);
  assert.match(renderedMarkdown, /Scanner-only explanation unavailable/);
  assert.match(renderedMarkdown, /Gitleaks/);
});

function makeReportDocument(): ReportDocument {
  return {
    schemaVersion: "1.0",
    scanId: "scan-report-test",
    workspaceId: "workspace-report-test",
    workspaceName: "Report Test Workspace",
    generatedAt: "2026-01-01T00:00:01.000Z",
    target: {
      kind: "local-path",
      value: "tests/fixtures/repos/node-express-vulnerable",
    },
    run: {
      id: "scan-report-test",
      mode: "offline",
      startedAt: "2026-01-01T00:00:00.000Z",
      finishedAt: "2026-01-01T00:00:01.000Z",
      durationMs: 1000,
    },
    tools: [
      {
        id: "semgrep",
        label: "Semgrep",
        status: "completed",
        message: "fixture scan completed",
      },
    ],
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
        id: "finding-report-test",
        title: "Unsafe fixture title <script>alert(1)</script>",
        category: "secret",
        severity: "high",
        confidence: "confirmed",
        description: "Fake token was redacted before rendering.",
        evidence: "HERMSEC_FAKE_TEST_TOKEN_[REDACTED]",
        remediation: "Use a local fake secret fixture only.",
        tool: "gitleaks",
        ruleId: "hermsec-fake-secret",
        cwe: ["CWE-798"],
        location: {
          file: "src/routes/search.js",
          startLine: 7,
        },
        fingerprint: "report-test-fingerprint",
      },
    ],
    explanations: {},
    evidence: {
      bundleId: "evidence-report-test",
      redactionApplied: true,
      rawArtifacts: [],
      findingEvidence: {},
    },
    limitations: ["Fixture report rendering test."],
  };
}
