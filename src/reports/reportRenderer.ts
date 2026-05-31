import fs from "node:fs/promises";
import { redactForReport } from "../agent/redaction.js";
import type { ModelExplanation } from "../agent/structuredOutput.js";
import type { Finding, ScanRun, ScannerStatus } from "../shared/types.js";
import { createReportArtifactPaths, type ReportArtifactPaths } from "./artifactPaths.js";
import { buildDeltaReport } from "./delta.js";
import { storeEvidenceBundle, type RawEvidenceInput } from "./evidenceBundle.js";
import { defaultReportCss, renderHtmlReport } from "./htmlRenderer.js";
import { renderJsonArtifacts } from "./jsonRenderer.js";
import { renderMarkdownReport } from "./markdownRenderer.js";
import { appendReportIndexEntry, latestReportForWorkspace } from "./reportIndex.js";
import { resolveReportDestination } from "./reportStore.js";
import {
  assertReportDocument,
  buildReportSummary,
  compareFindings,
  type AgentSummary,
  type ReportDocument,
  type ReportFormat,
  type ScanTarget
} from "./schema.js";

export type RenderReportInput = {
  scanRun: ScanRun;
  workspaceId: string;
  workspaceName: string;
  target?: ScanTarget;
  configuredReportDir?: string;
  formats?: readonly ReportFormat[];
  explanations?: Record<string, ModelExplanation | undefined>;
  agentSummary?: Partial<AgentSummary>;
  rawEvidence?: readonly RawEvidenceInput[];
  limitations?: readonly string[];
  generatedAt?: string;
  indexPath?: string;
};

export type RenderReportResult = {
  document: ReportDocument;
  paths: ReportArtifactPaths;
  artifacts: {
    htmlPath?: string;
    markdownPath?: string;
    summaryPath: string;
    findingsPath: string;
    evidencePath: string;
    runPath: string;
    agentSummaryPath: string;
    deltaPath: string;
    documentPath: string;
  };
};

export async function renderReport(input: RenderReportInput): Promise<RenderReportResult> {
  const generatedAt = input.generatedAt ?? input.scanRun.finishedAt;
  const destination = await resolveReportDestination(input.configuredReportDir);
  const paths = createReportArtifactPaths(destination.actualReportRoot, input.workspaceName, generatedAt);
  const formats = new Set(input.formats ?? ["html", "markdown", "json"]);
  await fs.mkdir(paths.reportDir, { recursive: true });

  const previousEntry = await latestReportForWorkspace(input.workspaceId, input.indexPath);
  const previousFindings = previousEntry ? await readPreviousFindings(previousEntry.summaryPath.replace(/summary\.json$/, "findings.json")) : undefined;
  const evidence = await storeEvidenceBundle({
    scanId: input.scanRun.id,
    findings: input.scanRun.findings,
    rawDir: paths.rawDir,
    ...(input.rawEvidence ? { rawEvidence: input.rawEvidence } : {})
  });

  const explanations = input.explanations ?? {};
  const generatedWithModel = Object.values(explanations).some((explanation) => explanation !== undefined);
  const document: ReportDocument = {
    schemaVersion: "1.0",
    scanId: input.scanRun.id,
    workspaceId: input.workspaceId,
    workspaceName: input.workspaceName,
    generatedAt,
    target: input.target ?? { kind: "local-path", value: input.scanRun.target, displayName: input.workspaceName },
    run: {
      id: input.scanRun.id,
      mode: input.scanRun.mode,
      startedAt: input.scanRun.startedAt,
      finishedAt: input.scanRun.finishedAt,
      durationMs: input.scanRun.durationMs,
      ...(input.scanRun.git ? { git: input.scanRun.git } : {}),
      fallback: {
        used: destination.fallbackUsed,
        ...(destination.configuredReportDir ? { configuredReportDir: destination.configuredReportDir } : {}),
        actualReportDir: paths.reportDir,
        ...(destination.fallbackReason ? { reason: destination.fallbackReason } : {})
      }
    },
    tools: sortTools(input.scanRun.scannerStatuses),
    summary: buildReportSummary(input.scanRun.findings, input.scanRun.scannerStatuses, generatedWithModel),
    findings: [...input.scanRun.findings].sort(compareFindings),
    explanations,
    evidence,
    delta: buildDeltaReport(
      input.scanRun.id,
      input.scanRun.findings,
      previousEntry && previousFindings ? { scanId: previousEntry.scanId, findings: previousFindings } : undefined
    ),
    limitations: [
      ...(input.limitations ?? []),
      "Hermsec reports only scanner and advisory evidence supplied to this run.",
      "Model or fallback explanations cannot add CVEs, file paths, package names, versions, or line numbers."
    ]
  };

  const redactedDocument = redactForReport(document).value as ReportDocument;
  assertReportDocument(redactedDocument);

  const agentSummary: AgentSummary = {
    generatedWithModel,
    provider: input.agentSummary?.provider ?? (generatedWithModel ? "configured-model" : "none"),
    ...(input.agentSummary?.model ? { model: input.agentSummary.model } : {}),
    ...(input.agentSummary?.fallbackReason ? { fallbackReason: input.agentSummary.fallbackReason } : {}),
    executiveSummary: input.agentSummary?.executiveSummary ?? buildExecutiveSummary(redactedDocument),
    priorityActions: input.agentSummary?.priorityActions ?? buildPriorityActions(redactedDocument),
    explanations: redactedDocument.explanations
  };

  const json = renderJsonArtifacts(redactedDocument, agentSummary);
  await writeRequiredJson(paths, json);

  if (formats.has("markdown")) {
    await fs.writeFile(paths.markdownPath, renderMarkdownReport(redactedDocument), "utf8");
  }
  if (formats.has("html")) {
    await fs.writeFile(paths.htmlPath, renderHtmlReport(redactedDocument), "utf8");
    await fs.writeFile(paths.cssPath, defaultReportCss, "utf8");
  }

  await appendReportIndexEntry(
    {
      scanId: redactedDocument.scanId,
      workspaceId: redactedDocument.workspaceId,
      generatedAt: redactedDocument.generatedAt,
      reportDir: paths.reportDir,
      htmlPath: paths.htmlPath,
      markdownPath: paths.markdownPath,
      summaryPath: paths.summaryPath,
      totals: redactedDocument.summary,
      ...(redactedDocument.run.git?.commit ? { commitSha: redactedDocument.run.git.commit } : {}),
      ...(previousEntry ? { previousScanId: previousEntry.scanId } : {})
    },
    input.indexPath
  );

  return {
    document: redactedDocument,
    paths,
    artifacts: {
      ...(formats.has("html") ? { htmlPath: paths.htmlPath } : {}),
      ...(formats.has("markdown") ? { markdownPath: paths.markdownPath } : {}),
      summaryPath: paths.summaryPath,
      findingsPath: paths.findingsPath,
      evidencePath: paths.evidencePath,
      runPath: paths.runPath,
      agentSummaryPath: paths.agentSummaryPath,
      deltaPath: paths.deltaPath,
      documentPath: paths.documentPath
    }
  };
}

async function writeRequiredJson(paths: ReportArtifactPaths, json: ReturnType<typeof renderJsonArtifacts>): Promise<void> {
  await fs.writeFile(paths.summaryPath, json.summaryJson, "utf8");
  await fs.writeFile(paths.findingsPath, json.findingsJson, "utf8");
  await fs.writeFile(paths.evidencePath, json.evidenceJson, "utf8");
  await fs.writeFile(paths.runPath, json.runJson, "utf8");
  await fs.writeFile(paths.agentSummaryPath, json.agentSummaryJson, "utf8");
  await fs.writeFile(paths.deltaPath, json.deltaJson, "utf8");
  await fs.writeFile(paths.documentPath, json.documentJson, "utf8");
}

async function readPreviousFindings(filePath: string): Promise<Finding[] | undefined> {
  try {
    const raw = await fs.readFile(filePath, "utf8");
    const parsed = JSON.parse(raw) as Finding[];
    return Array.isArray(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}

function sortTools(tools: readonly ScannerStatus[]): ScannerStatus[] {
  return [...tools].sort((left, right) => left.id.localeCompare(right.id));
}

function buildExecutiveSummary(document: ReportDocument): string {
  if (document.summary.total === 0) {
    return "No findings were reported by the configured scanners.";
  }
  return `${document.summary.total} finding(s): ${document.summary.critical} critical, ${document.summary.high} high, ${document.summary.medium} medium, ${document.summary.low} low, ${document.summary.info} info.`;
}

function buildPriorityActions(document: ReportDocument): string[] {
  return document.findings.slice(0, 5).map((finding) => `${finding.id}: ${finding.remediation}`);
}

export function renderMarkdown(run: ScanRun): string {
  const lines = [
    "# Hermsec Report",
    "",
    `- Run ID: \`${run.id}\``,
    `- Target: \`${run.target}\``,
    `- Mode: \`${run.mode}\``,
    "",
    "## Summary",
    "",
    `Total findings: ${run.summary.total}`,
    `Critical: ${run.summary.critical}`,
    `High: ${run.summary.high}`,
    `Medium: ${run.summary.medium}`,
    `Low: ${run.summary.low}`,
    `Info: ${run.summary.info}`,
    "",
    "## Findings",
    "",
  ];
  if (run.findings.length === 0) {
    lines.push("No findings were detected by the enabled checks.");
  }
  for (const finding of run.findings) {
    lines.push(
      `### ${finding.title}`,
      "",
      `- Severity: \`${finding.severity}\``,
      `- Category: \`${finding.category}\``,
      finding.location ? `- Location: \`${finding.location.file}${finding.location.startLine ? `:${finding.location.startLine}` : ""}\`` : "",
      "",
      "```text",
      redactForReport(finding.evidence).value as string,
      "```",
      "",
      finding.remediation,
      "",
    );
  }
  return `${lines.filter((line) => line !== "").join("\n")}\n`;
}

export function renderHtml(run: ScanRun): string {
  const findings = run.findings.length
    ? run.findings
        .map(
          (finding) => `<section class="finding ${escapeHtml(finding.severity)}">
<h2>${escapeHtml(finding.title)}</h2>
<p>${escapeHtml(finding.severity)} / ${escapeHtml(finding.category)}</p>
<pre>${escapeHtml(String(redactForReport(finding.evidence).value))}</pre>
<p>${escapeHtml(finding.remediation)}</p>
</section>`,
        )
        .join("\n")
    : "<section><h2>No findings detected</h2></section>";
  return `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Hermsec Report</title></head>
<body><main><h1>Hermsec Report</h1><p>${escapeHtml(run.target)}</p>${findings}</main></body>
</html>
`;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
