import type { Finding } from "../shared/types.js";
import type { ReportDocument } from "./schema.js";
import { compareFindings, severityOrder } from "./schema.js";

export function renderMarkdownReport(document: ReportDocument): string {
  const sections = [
    "# Hermsec Security Report",
    renderMetadata(document),
    renderSummary(document),
    renderPriorityActions(document),
    renderDelta(document),
    renderFindings(document),
    renderScannerStatus(document),
    renderEvidenceBundle(document),
    renderLimitations(document)
  ];
  return `${sections.join("\n\n")}\n`;
}

function renderMetadata(document: ReportDocument): string {
  const lines = [
    "## Scan Metadata",
    "",
    `- Scan ID: \`${escapeMarkdown(document.scanId)}\``,
    `- Workspace: ${escapeMarkdown(document.workspaceName)} (\`${escapeMarkdown(document.workspaceId)}\`)`,
    `- Generated: ${escapeMarkdown(document.generatedAt)}`,
    `- Target: \`${escapeMarkdown(document.target.value)}\``,
    `- Mode: ${escapeMarkdown(document.run.mode)}`,
    `- Redaction applied: ${document.evidence.redactionApplied ? "yes" : "no"}`
  ];
  if (document.run.git?.commit) {
    lines.push(`- Commit: \`${escapeMarkdown(document.run.git.commit)}\``);
  }
  return lines.join("\n");
}

function renderSummary(document: ReportDocument): string {
  return [
    "## Executive Summary",
    "",
    `- Total: ${document.summary.total}`,
    `- Critical: ${document.summary.critical}`,
    `- High: ${document.summary.high}`,
    `- Medium: ${document.summary.medium}`,
    `- Low: ${document.summary.low}`,
    `- Info: ${document.summary.info}`,
    `- Secrets: ${document.summary.secrets}`,
    `- Confirmed CVEs from evidence: ${document.summary.confirmedCves}`,
    `- Scanner failures: ${document.summary.scannerFailures}`,
    `- Model explanations: ${document.summary.generatedWithModel ? "generated from supplied evidence" : "scanner-only explanation unavailable"}`
  ].join("\n");
}

function renderPriorityActions(document: ReportDocument): string {
  const findings = [...document.findings].sort(compareFindings).slice(0, 5);
  const actions = findings.map((finding, index) => {
    const explanation = document.explanations[finding.id];
    return `${index + 1}. ${escapeMarkdown(finding.title)}: ${escapeMarkdown(explanation?.suggestedFix ?? finding.remediation)}`;
  });
  return ["## Priority Actions", "", ...(actions.length > 0 ? actions : ["No findings require action."])].join("\n");
}

function renderDelta(document: ReportDocument): string {
  const delta = document.delta;
  if (!delta) {
    return ["## Delta Since Previous Scan", "", "No previous scan was available for comparison."].join("\n");
  }
  return [
    "## Delta Since Previous Scan",
    "",
    escapeMarkdown(delta.summaryText ?? "Delta was calculated from stable finding fingerprints."),
    "",
    `- New: ${formatIds(delta.newFindingIds)}`,
    `- Fixed: ${formatIds(delta.fixedFindingIds)}`,
    `- Unchanged: ${formatIds(delta.unchangedFindingIds)}`,
    `- Worsened: ${formatIds(delta.worsenedFindingIds)}`,
    `- Improved: ${formatIds(delta.improvedFindingIds)}`
  ].join("\n");
}

function renderFindings(document: ReportDocument): string {
  const lines = ["## Findings"];
  for (const severity of severityOrder) {
    const findings = document.findings.filter((finding) => finding.severity === severity).sort(compareFindings);
    if (findings.length === 0) {
      continue;
    }
    lines.push("", `### ${severity.toUpperCase()}`);
    for (const finding of findings) {
      lines.push("", renderFinding(document, finding));
    }
  }
  if (lines.length === 1) {
    lines.push("", "No findings were reported by the configured scanners.");
  }
  return lines.join("\n");
}

function renderFinding(document: ReportDocument, finding: Finding): string {
  const explanation = document.explanations[finding.id];
  const location = finding.location
    ? `${finding.location.file}${finding.location.startLine ? `:${finding.location.startLine}` : ""}`
    : "No source location";
  const identifiers = [
    ...(finding.identifiers?.cve ?? []),
    ...(finding.identifiers?.ghsa ?? []),
    ...(finding.identifiers?.osv ?? []),
    ...(finding.cwe ?? [])
  ];
  return [
    `#### ${escapeMarkdown(finding.title)}`,
    "",
    `- ID: \`${escapeMarkdown(finding.id)}\``,
    `- Tool: ${escapeMarkdown(finding.tool)}`,
    `- Confidence: ${escapeMarkdown(finding.confidence)}`,
    `- Location: \`${escapeMarkdown(location)}\``,
    identifiers.length > 0 ? `- Identifiers from evidence: ${identifiers.map((id) => `\`${escapeMarkdown(id)}\``).join(", ")}` : undefined,
    "",
    `Evidence: ${escapeMarkdown(finding.evidence)}`,
    "",
    `Description: ${escapeMarkdown(finding.description)}`,
    "",
    `Explanation: ${escapeMarkdown(explanation?.evidenceSummary ?? "Scanner-only explanation unavailable.")}`,
    "",
    `Suggested fix: ${escapeMarkdown(explanation?.suggestedFix ?? finding.remediation)}`
  ]
    .filter((line): line is string => line !== undefined)
    .join("\n");
}

function renderScannerStatus(document: ReportDocument): string {
  const rows = document.tools.map((tool) => {
    return `| ${escapeTable(tool.label)} | ${escapeTable(tool.status)} | ${tool.durationMs ?? ""} | ${escapeTable(tool.message)} |`;
  });
  return ["## Scanner Status", "", "| Tool | Status | Duration ms | Message |", "| --- | --- | ---: | --- |", ...rows].join("\n");
}

function renderEvidenceBundle(document: ReportDocument): string {
  const rows = document.evidence.rawArtifacts.map((artifact) => {
    return `| ${escapeTable(artifact.scanner)} | ${escapeTable(artifact.path)} | ${escapeTable(artifact.status)} | ${artifact.sizeBytes} | \`${artifact.sha256}\` |`;
  });
  return [
    "## Evidence Bundle",
    "",
    `- Bundle ID: \`${escapeMarkdown(document.evidence.bundleId)}\``,
    `- Redaction applied: ${document.evidence.redactionApplied ? "yes" : "no"}`,
    "",
    "| Scanner | Local artifact | Status | Bytes | SHA-256 |",
    "| --- | --- | --- | ---: | --- |",
    ...(rows.length > 0 ? rows : ["| None | None | missing | 0 |  |"])
  ].join("\n");
}

function renderLimitations(document: ReportDocument): string {
  return ["## Limitations", "", ...document.limitations.map((limitation) => `- ${escapeMarkdown(limitation)}`)].join("\n");
}

function formatIds(ids: readonly string[]): string {
  return ids.length > 0 ? ids.map((id) => `\`${escapeMarkdown(id)}\``).join(", ") : "None";
}

function escapeTable(value: string): string {
  return escapeMarkdown(value).replace(/\|/g, "\\|");
}

function escapeMarkdown(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/`/g, "\\`").replace(/\*/g, "\\*").replace(/_/g, "\\_");
}
