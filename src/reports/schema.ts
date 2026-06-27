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
  modeLabel?: string;
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

export type ReportFindingSourceLabel =
  | "scanner-backed"
  | "single-agent-inspected"
  | "moa-specialist"
  | "moa-aggregated";

export type ReportAgentDescriptor = {
  id: string;
  label?: string;
  role?: string;
  provider?: string;
  model?: string;
  runtimeMs?: number;
  status?: string;
};

export type ReportAggregatorDescriptor = {
  agentId?: string;
  provider?: string;
  model?: string;
  label?: string;
};

export type ReportFindingAgentMetadata = {
  sourceLabel?: ReportFindingSourceLabel | string;
  sourceLabels?: Array<ReportFindingSourceLabel | string>;
  judgeStatus?: string;
  judgeReason?: string;
  agentIds?: string[];
};

export type ReportAgentModeMetadata = {
  mode?: string;
  scanMode?: string;
  modeLabel?: string;
  agents?: ReportAgentDescriptor[];
  agentsUsed?: string[];
  candidateFindingCount?: number;
  acceptedFindingCount?: number;
  rejectedFindingCount?: number;
  needsHumanReviewCount?: number;
  aggregatorModel?: string;
  aggregator?: ReportAggregatorDescriptor;
  totalAgentRuntimeMs?: number;
  findings?: Record<string, ReportFindingAgentMetadata>;
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

export type ReportIntelligenceItem = {
  id: string;
  title: string;
  source: string;
  severity: Severity | "unknown";
  knownExploited: boolean;
  ecosystem: string;
  packageName?: string;
  installedVersion?: string;
  packageLabel: string;
  cve?: string;
  identifiers: {
    cve: string[];
    ghsa: string[];
    osv: string[];
    cwe: string[];
  };
  publishedAt?: string;
  modifiedAt?: string;
  url: string;
  whyItMatters: string;
  matchedPackages: string[];
  findingIds: string[];
  reasons: string[];
  priority: "urgent" | "high" | "normal" | "watch";
  fixVersion?: string;
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

export type ReportFinding = Finding & ReportFindingAgentMetadata;

export type ReportDocument = {
  schemaVersion: "1.0";
  scanId: string;
  workspaceId: string;
  workspaceName: string;
  generatedAt: string;
  target: ScanTarget;
  run: ScanRunSummary;
  agentMode?: ReportAgentModeMetadata;
  tools: ScannerStatus[];
  summary: ReportSummary;
  intelligence: ReportIntelligenceItem[];
  findings: ReportFinding[];
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
  agentMode?: ReportAgentModeMetadata;
  executiveSummary: string;
  priorityActions: string[];
  explanations: Record<string, ModelExplanation | undefined>;
} & Record<string, unknown>;

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
  generatedWithModel: boolean,
  intelligence: readonly ReportIntelligenceItem[] = []
): ReportSummary {
  const confirmedCves = new Set<string>();
  const summary: ReportSummary = {
    total: findings.length,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    secrets: 0,
    confirmedCves: 0,
    knownExploited: intelligence.filter((item) => item.knownExploited).length,
    scannerFailures: tools.filter((tool) => tool.status === "failed").length,
    generatedWithModel
  };

  for (const finding of findings) {
    summary[finding.severity] += 1;
    if (finding.category === "secret") {
      summary.secrets += 1;
    }
    for (const cve of finding.identifiers?.cve ?? []) {
      confirmedCves.add(cve);
    }
  }

  for (const item of intelligence) {
    for (const cve of item.identifiers.cve) {
      confirmedCves.add(cve);
    }
  }
  summary.confirmedCves = confirmedCves.size;

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
  if (!Array.isArray(value.intelligence)) {
    throw new Error("Report document is missing vulnerability intelligence.");
  }
  for (const finding of value.findings) {
    if (!finding.id || !finding.title || !finding.fingerprint) {
      throw new Error("Report finding is missing required identity fields.");
    }
  }
}
