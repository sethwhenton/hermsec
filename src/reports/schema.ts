import type { Finding, ScanMode, ScannerStatus, Severity } from "../shared/types.js";
import type { ModelExplanation } from "../agent/structuredOutput.js";

export type ReportFormat = "html" | "markdown" | "json";

export type ScanTarget = {
  kind: "local-path" | "github-url" | "unknown";
  value: string;
  displayName?: string;
};

export type ScanRunSummary = {
  id: string;
  mode: ScanMode;
  startedAt: string;
  finishedAt: string;
  durationMs: number;
  git?: {
    branch?: string;
    commit?: string;
    dirty?: boolean;
  };
  fallback?: {
    used: boolean;
    configuredReportDir?: string;
    actualReportDir: string;
    reason?: string;
  };
};

export type ReportSummary = {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  secrets: number;
  confirmedCves: number;
  knownExploited: number;
  scannerFailures: number;
  generatedWithModel: boolean;
};

export type EvidenceReference = {
  scanner: string;
  artifactPath?: string;
  ruleId?: string;
  message?: string;
  location?: {
    file: string;
    startLine?: number;
    endLine?: number;
  };
};

export type EvidenceArtifact = {
  scanner: string;
  path: string;
  sha256: string;
  sizeBytes: number;
  status: "stored" | "missing" | "redacted";
};

export type EvidenceBundle = {
  bundleId: string;
  redactionApplied: boolean;
  rawArtifacts: EvidenceArtifact[];
  findingEvidence: Record<string, EvidenceReference[]>;
};

export type DeltaReport = {
  baseScanId?: string;
  currentScanId: string;
  newFindingIds: string[];
  fixedFindingIds: string[];
  unchangedFindingIds: string[];
  worsenedFindingIds: string[];
  improvedFindingIds: string[];
  summaryText?: string;
};

export type ReportDocument = {
  schemaVersion: "1.0";
  scanId: string;
  workspaceId: string;
  workspaceName: string;
  generatedAt: string;
  target: ScanTarget;
  run: ScanRunSummary;
  tools: ScannerStatus[];
  summary: ReportSummary;
  findings: Finding[];
  explanations: Record<string, ModelExplanation | undefined>;
  evidence: EvidenceBundle;
  delta?: DeltaReport;
  limitations: string[];
};

export type ReportIndexEntry = {
  scanId: string;
  workspaceId: string;
  generatedAt: string;
  reportDir: string;
  htmlPath: string;
  markdownPath: string;
  summaryPath: string;
  totals: ReportSummary;
  commitSha?: string;
  previousScanId?: string;
  missing?: boolean;
};

export type AgentSummary = {
  generatedWithModel: boolean;
  provider: string;
  model?: string;
  fallbackReason?: string;
  executiveSummary: string;
  priorityActions: string[];
  explanations: Record<string, ModelExplanation | undefined>;
};

export const severityOrder: Severity[] = ["critical", "high", "medium", "low", "info"];

const severityRank: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4
};

const confidenceRank: Record<Finding["confidence"], number> = {
  confirmed: 0,
  high: 1,
  medium: 2,
  low: 3
};

export function compareFindings(a: Finding, b: Finding): number {
  return (
    severityRank[a.severity] - severityRank[b.severity] ||
    confidenceRank[a.confidence] - confidenceRank[b.confidence] ||
    a.title.localeCompare(b.title) ||
    a.id.localeCompare(b.id)
  );
}

export function buildReportSummary(
  findings: readonly Finding[],
  tools: readonly ScannerStatus[],
  generatedWithModel: boolean
): ReportSummary {
  const summary: ReportSummary = {
    total: findings.length,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    secrets: 0,
    confirmedCves: 0,
    knownExploited: 0,
    scannerFailures: tools.filter((tool) => tool.status === "failed").length,
    generatedWithModel
  };

  for (const finding of findings) {
    summary[finding.severity] += 1;
    if (finding.category === "secret") {
      summary.secrets += 1;
    }
    if ((finding.identifiers?.cve?.length ?? 0) > 0) {
      summary.confirmedCves += finding.identifiers?.cve?.length ?? 0;
    }
  }

  return summary;
}

export function assertReportDocument(value: ReportDocument): void {
  if (value.schemaVersion !== "1.0") {
    throw new Error("Unsupported report schema version.");
  }
  if (!value.scanId || !value.workspaceId || !value.generatedAt) {
    throw new Error("Report document is missing required metadata.");
  }
  if (value.summary.total !== value.findings.length) {
    throw new Error("Report summary total does not match finding count.");
  }
  for (const finding of value.findings) {
    if (!finding.id || !finding.title || !finding.fingerprint) {
      throw new Error("Report finding is missing required identity fields.");
    }
  }
}
