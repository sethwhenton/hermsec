import { displayScannerName } from "./displayNames.js";
import type { ReportDocument, ReportFinding } from "./schema.js";
import { compareFindings, severityOrder } from "./schema.js";

export function renderMarkdownReport(document: ReportDocument): string {
  const sections = [
    "# Hermsec Security Report",
    renderMetadata(document),
    renderSummary(document),
    renderAgentMode(document),
    renderPriorityActions(document),
    renderIntelligence(document),
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
    `- Mode: ${escapeMarkdown(document.run.modeLabel ?? document.run.mode)}`,
    document.agentMode?.modeLabel ? `- Agent mode: ${escapeMarkdown(document.agentMode.modeLabel)}` : undefined,
    `- Redaction applied: ${document.evidence.redactionApplied ? "yes" : "no"}`
  ].filter((line): line is string => line !== undefined);
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
    `- Known exploited matches: ${document.summary.knownExploited}`,
    `- Scanner failures: ${document.summary.scannerFailures}`,
    `- Model explanations: ${document.summary.generatedWithModel ? "generated from supplied evidence" : "scanner-only explanation unavailable"}`
  ].join("\n");
}

function renderAgentMode(document: ReportDocument): string {
  const metadata = document.agentMode;
  if (!metadata) {
    return "";
  }

  const lines = [
    "## Agent Mode",
    "",
    `- Mode: ${escapeMarkdown(metadata.modeLabel ?? metadata.mode ?? document.run.modeLabel ?? document.run.mode)}`,
    metadata.scanMode ? `- Scan mode: ${escapeMarkdown(metadata.scanMode)}` : undefined,
    metadata.candidateFindingCount !== undefined ? `- Candidate findings: ${metadata.candidateFindingCount}` : undefined,
    metadata.acceptedFindingCount !== undefined ? `- Accepted findings: ${metadata.acceptedFindingCount}` : undefined,
    metadata.rejectedFindingCount !== undefined ? `- Rejected findings: ${metadata.rejectedFindingCount}` : undefined,
    metadata.needsHumanReviewCount !== undefined ? `- Needs human review: ${metadata.needsHumanReviewCount}` : undefined,
    metadata.aggregatorModel ?? formatAggregator(metadata.aggregator)
      ? `- Aggregator model: ${escapeMarkdown(metadata.aggregatorModel ?? formatAggregator(metadata.aggregator) ?? "")}`
      : undefined,
    metadata.totalAgentRuntimeMs !== undefined ? `- Total agent runtime: ${formatDuration(metadata.totalAgentRuntimeMs)}` : undefined
  ].filter((line): line is string => line !== undefined);

  if ((metadata.agents ?? []).length > 0) {
    lines.push("", "| Agent | Role | Provider / Model | Runtime |", "| --- | --- | --- | ---: |");
    for (const agent of metadata.agents ?? []) {
      const providerModel = [agent.provider, agent.model].filter(Boolean).join(" / ") || "not recorded";
      lines.push(
        `| ${escapeTable(agent.label ?? agent.id)} | ${escapeTable(agent.role ?? "agent")} | ${escapeTable(providerModel)} | ${escapeTable(formatDuration(agent.runtimeMs))} |`
      );
    }
  }

  return lines.join("\n");
}

function renderPriorityActions(document: ReportDocument): string {
  const findings = [...document.findings].sort(compareFindings).slice(0, 5);
  const actions = findings.map((finding, index) => {
    const explanation = document.explanations[finding.id];
    return `${index + 1}. ${escapeMarkdown(finding.title)}: ${escapeMarkdown(explanation?.suggestedFix ?? finding.remediation)}`;
  });
  return ["## Priority Actions", "", ...(actions.length > 0 ? actions : ["No findings require action."])].join("\n");
}

function renderIntelligence(document: ReportDocument): string {
  if (document.intelligence.length === 0) {
    return [
      "## Vulnerability Intelligence",
      "",
      "No KEV or advisory intelligence matched the scanned dependency inventory or scanner identifiers for this run."
    ].join("\n");
  }
  const lines = ["## Vulnerability Intelligence"];
  for (const item of document.intelligence) {
    const identifiers = [
      ...item.identifiers.cve,
      ...item.identifiers.ghsa,
      ...item.identifiers.osv,
      ...item.identifiers.cwe
    ];
    const itemLines: Array<string | undefined> = [
      "",
      `### ${escapeMarkdown(item.title)}`,
      "",
      `- Source: ${escapeMarkdown(item.source)}`,
      `- Priority: ${escapeMarkdown(item.priority)}${item.knownExploited ? " (known exploited)" : ""}`,
      `- Severity: ${escapeMarkdown(item.severity)}`,
      `- Package: ${escapeMarkdown(item.packageLabel)}`,
      identifiers.length > 0 ? `- Identifiers: ${identifiers.map((id) => `\`${escapeMarkdown(id)}\``).join(", ")}` : undefined,
      item.fixVersion ? `- Fixed version: \`${escapeMarkdown(item.fixVersion)}\`` : undefined,
      item.findingIds.length > 0 ? `- Related findings: ${item.findingIds.map((id) => `\`${escapeMarkdown(id)}\``).join(", ")}` : undefined,
      `- Advisory: ${escapeMarkdown(item.url)}`,
      "",
      `Why it matters: ${escapeMarkdown(item.whyItMatters)}`,
      "",
      item.reasons.length > 0
        ? `Match reasons: ${item.reasons.map((reason) => escapeMarkdown(reason)).join("; ")}`
        : undefined
    ];
    lines.push(...itemLines.filter((line): line is string => line !== undefined));
  }
  return lines.filter((line): line is string => line !== undefined).join("\n");
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

function renderFinding(document: ReportDocument, finding: ReportFinding): string {
  const explanation = document.explanations[finding.id];
  const agent = findingAgentMetadata(document, finding);
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
    `- Tool: ${escapeMarkdown(displayScannerName(finding.tool))}`,
    `- Confidence: ${escapeMarkdown(finding.confidence)}`,
    `- Location: \`${escapeMarkdown(location)}\``,
    agent.sourceLabels.length > 0 ? `- Source labels: ${agent.sourceLabels.map((label) => escapeMarkdown(labelize(label))).join(", ")}` : undefined,
    agent.judgeStatus ? `- Judge status: ${escapeMarkdown(labelize(agent.judgeStatus))}` : undefined,
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
    return `| ${escapeTable(displayScannerName(tool.label))} | ${escapeTable(tool.status)} | ${tool.durationMs ?? ""} | ${escapeTable(tool.message)} |`;
  });
  return ["## Scanner Status", "", "| Tool | Status | Duration ms | Message |", "| --- | --- | ---: | --- |", ...rows].join("\n");
}

function renderEvidenceBundle(document: ReportDocument): string {
  const rows = document.evidence.rawArtifacts.map((artifact) => {
    return `| ${escapeTable(displayScannerName(artifact.scanner))} | ${escapeTable(artifact.path)} | ${escapeTable(artifact.status)} | ${artifact.sizeBytes} | \`${artifact.sha256}\` |`;
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

function findingAgentMetadata(
  document: ReportDocument,
  finding: ReportFinding
): { sourceLabels: string[]; judgeStatus?: string } {
  const mapped = document.agentMode?.findings?.[finding.id];
  const sourceLabels = unique([
    ...arrayValue(finding.sourceLabels),
    ...arrayValue(finding.sourceLabel),
    ...arrayValue(mapped?.sourceLabels),
    ...arrayValue(mapped?.sourceLabel)
  ]);
  const judgeStatus = firstNonEmpty(finding.judgeStatus, mapped?.judgeStatus);
  return {
    sourceLabels,
    ...(judgeStatus ? { judgeStatus } : {})
  };
}

function formatAggregator(value: { agentId?: string; provider?: string; model?: string; label?: string } | undefined): string | undefined {
  if (!value) {
    return undefined;
  }
  const providerModel = [value.provider, value.model].filter(Boolean).join(" / ");
  return firstNonEmpty(providerModel, value.label, value.agentId);
}

function formatDuration(durationMs: number | undefined): string {
  if (durationMs === undefined) {
    return "n/a";
  }
  if (durationMs >= 1000) {
    const seconds = durationMs / 1000;
    return `${seconds >= 10 ? seconds.toFixed(0) : seconds.toFixed(1)} s`;
  }
  return `${durationMs} ms`;
}

function arrayValue(value: string | readonly string[] | undefined): string[] {
  if (!value) {
    return [];
  }
  return (Array.isArray(value) ? value : [value]).map((item) => item.trim()).filter(Boolean);
}

function unique(values: readonly string[]): string[] {
  return [...new Set(values)].sort((left, right) => left.localeCompare(right));
}

function firstNonEmpty(...values: Array<string | undefined>): string | undefined {
  return values.find((value) => value !== undefined && value.trim().length > 0);
}

function labelize(value: string): string {
  return value
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\b\w/g, (match) => match.toUpperCase());
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
