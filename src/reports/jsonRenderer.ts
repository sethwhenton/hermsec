import type {
  AgentSummary,
  EvidenceBundle,
  ReportDocument,
  ReportSummary
} from "./schema.js";

export type JsonReportArtifacts = {
  summaryJson: string;
  findingsJson: string;
  evidenceJson: string;
  runJson: string;
  agentSummaryJson: string;
  deltaJson: string;
  documentJson: string;
};

export function stableStringify(value: unknown): string {
  return `${stringifySorted(value, 0)}\n`;
}

export function renderJsonArtifacts(
  document: ReportDocument,
  agentSummary: AgentSummary
): JsonReportArtifacts {
  return {
    summaryJson: stableStringify(toSummaryJson(document.summary, document)),
    findingsJson: stableStringify(document.findings),
    evidenceJson: stableStringify(document.evidence),
    runJson: stableStringify(document.run),
    agentSummaryJson: stableStringify(agentSummary),
    deltaJson: stableStringify(document.delta ?? emptyDelta(document.scanId)),
    documentJson: stableStringify(document)
  };
}

function toSummaryJson(summary: ReportSummary, document: ReportDocument): Record<string, unknown> {
  return {
    schemaVersion: document.schemaVersion,
    scanId: document.scanId,
    workspaceId: document.workspaceId,
    workspaceName: document.workspaceName,
    generatedAt: document.generatedAt,
    target: document.target,
    summary,
    report: {
      generatedWithModel: summary.generatedWithModel,
      redactionApplied: document.evidence.redactionApplied
    }
  };
}

function emptyDelta(scanId: string): Record<string, unknown> {
  return {
    currentScanId: scanId,
    newFindingIds: [],
    fixedFindingIds: [],
    unchangedFindingIds: [],
    worsenedFindingIds: [],
    improvedFindingIds: []
  };
}

function stringifySorted(value: unknown, depth: number): string {
  if (value === undefined) {
    return "null";
  }
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value) ?? "null";
  }

  if (Array.isArray(value)) {
    if (value.length === 0) {
      return "[]";
    }
    const items = value.map((item) => `${indent(depth + 1)}${stringifySorted(item, depth + 1)}`);
    return `[\n${items.join(",\n")}\n${indent(depth)}]`;
  }

  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, entryValue]) => entryValue !== undefined)
    .sort(([left], [right]) => left.localeCompare(right));

  if (entries.length === 0) {
    return "{}";
  }

  const rendered = entries.map(([key, entryValue]) => {
    return `${indent(depth + 1)}${JSON.stringify(key)}: ${stringifySorted(entryValue, depth + 1)}`;
  });
  return `{\n${rendered.join(",\n")}\n${indent(depth)}}`;
}

function indent(depth: number): string {
  return "  ".repeat(depth);
}

export function evidenceBundleToJson(bundle: EvidenceBundle): string {
  return stableStringify(bundle);
}
