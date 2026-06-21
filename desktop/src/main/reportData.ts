import { existsSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import type { ProjectStateFingerprint } from "./projectState";
import { SCAN_ASSIST_FILE, type ScanAssistArtifact } from "./scanAssist";
import { SCAN_METADATA_FILE, type LocalScanMetadata } from "./scanMetadata";

type Severity = "critical" | "high" | "medium" | "low" | "info";
type ScannerStatus = "completed" | "running" | "waiting" | "skipped" | "failed";

interface HermsecDocument {
  generatedAt?: string;
  scanId?: string;
  workspaceName?: string;
  target?: {
    displayName?: string;
    value?: string;
  };
  run?: {
    id?: string;
    mode?: string;
    startedAt?: string;
    finishedAt?: string;
    durationMs?: number;
    git?: {
      branch?: string;
      commit?: string;
      dirty?: boolean;
    };
  };
  summary?: Partial<Record<Severity | "total" | "secrets" | "scannerFailures" | "confirmedCves" | "knownExploited", number>>;
  findings?: HermsecFinding[];
  explanations?: Record<string, ModelExplanation | undefined>;
  intelligence?: HermsecIntelligence[];
  tools?: HermsecTool[];
  evidence?: {
    findingEvidence?: Record<string, Array<{ scanner?: string; message?: string }>>;
    rawArtifacts?: string[];
    redactionApplied?: boolean;
  };
  limitations?: string[];
}

interface HermsecFinding {
  id?: string;
  title?: string;
  severity?: string;
  confidence?: string;
  category?: string;
  tool?: string;
  ruleId?: string;
  cwe?: string[];
  cve?: string[];
  ghsa?: string[];
  osv?: string[];
  identifiers?: {
    cve?: string[];
    ghsa?: string[];
    osv?: string[];
  };
  package?: string | {
    ecosystem?: string;
    name?: string;
    installedVersion?: string;
    version?: string;
  };
  version?: string;
  description?: string;
  evidence?: string;
  remediation?: string;
  references?: string[];
  fingerprint?: string;
  location?: {
    file?: string;
    startLine?: number;
  };
}

interface HermsecIntelligence {
  id?: string;
  title?: string;
  source?: string;
  severity?: string;
  knownExploited?: boolean;
  ecosystem?: string;
  packageName?: string;
  installedVersion?: string;
  packageLabel?: string;
  cve?: string;
  identifiers?: {
    cve?: string[];
    ghsa?: string[];
    osv?: string[];
    cwe?: string[];
  };
  publishedAt?: string;
  modifiedAt?: string;
  url?: string;
  whyItMatters?: string;
  matchedPackages?: string[];
  findingIds?: string[];
  reasons?: string[];
  priority?: string;
  fixVersion?: string;
}

interface HermsecTool {
  id?: string;
  label?: string;
  message?: string;
  status?: string;
  durationMs?: number;
}

export interface DashboardReport {
  scan: {
    id: string;
    scanId: string;
    project: string;
    projectName: string;
    targetPath: string;
    projectPath: string;
    mode: string;
    scanMode: string;
    assistMode: string;
    assistModeLabel: string;
    generatedAt: string;
    startedAt: string;
    finishedAt: string;
    reportGeneratedAt: string;
    durationMs: number;
    duration: string;
    branch: string;
    gitBranch: string;
    commit: string;
    gitCommit: string;
    dirty: boolean;
    dirtyWorkingTree: boolean;
  };
  summary: {
    totalFindings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    secrets: number;
    confirmedCves: number;
    knownExploited: number;
    scannerFailures: number;
  };
  posture: {
    label: string;
    grade: string;
    className: string;
    class: string;
    headline: string;
    detail: string;
    recommendation: string;
  };
  scanners: Array<{
    id: string;
    name: string;
    status: ScannerStatus;
    findings: number;
    durationMs?: number;
    message: string;
  }>;
  findings: Array<{
    id: string;
    title: string;
    severity: Severity;
    confidence: string;
    category: string;
    tool: string;
    ruleId: string;
    cwe: string[];
    cve: string[];
    ghsa: string[];
    osv: string[];
    package: string;
    version: string;
    file: string;
    line?: number;
    evidence: string;
    description: string;
    impact: string;
    remediation: string;
    references: string[];
    fingerprint: string;
  }>;
  adjudications: Array<{
    findingId: string;
    verdict: string;
    reasoning: string;
    priority: string;
    fixFirst: boolean;
    trustBoundary: string;
    assumptions: string[];
  }>;
  threatModel: {
    assets: string[];
    entryPoints: string[];
    trustBoundaries: string[];
    attackerCapabilities: string[];
    abusePaths: string[];
    mitigations: string[];
    unresolvedAssumptions: string[];
  };
  intelligence: Array<{
    title: string;
    source: string;
    severity: string;
    knownExploited: boolean;
    ecosystem: string;
    package: string;
    cve: string;
    published: string;
    whyItMatters: string;
    url: string;
    findingIds: string[];
    identifiers: {
      cve: string[];
      ghsa: string[];
      osv: string[];
      cwe: string[];
    };
    matchedPackages: string[];
    reasons: string[];
    priority: string;
    fixVersion: string;
  }>;
  fixPlan: {
    fixNow: FixPlanItem[];
    fixThisWeek: FixPlanItem[];
    monitor: FixPlanItem[];
    needsContext: FixPlanItem[];
  };
  evidence: {
    rawOutputs: Array<{ scanner: string; content: string }>;
    failedScanners: Array<{ name: string; reason: string }>;
    artifactPaths: string[];
    limitations: string[];
    redactionNote: string;
  };
  assist: ScanAssistArtifact & {
    available: boolean;
  };
}

interface ModelExplanation {
  title?: string;
  impact?: string;
  evidenceSummary?: string;
  suggestedFix?: string;
  confidenceReason?: string;
  safeNextSteps?: string[];
  cveUsage?: string;
}

interface FixPlanItem {
  title: string;
  findingIds: string[];
  owner: string;
  effort: string;
  validation: string;
  command: string;
}

const severityRank: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export function buildDashboardReport(reportDir: string): DashboardReport {
  const dir = path.resolve(reportDir);
  const document = readReportDocument(dir);
  const metadata = readJson<LocalScanMetadata>(path.join(dir, SCAN_METADATA_FILE));
  const assist = readScanAssist(dir, metadata);
  const projectState = readJson<ProjectStateFingerprint>(path.join(dir, "project-state.json"));
  const findings = normalizeFindings(document.findings ?? readLooseFindings(dir));
  const sortedFindings = [...findings].sort(
    (a, b) => (severityRank[a.severity] ?? 5) - (severityRank[b.severity] ?? 5),
  );
  const intelligence = buildIntelligence(document.intelligence, sortedFindings);
  const summary = normalizeSummary(document.summary, findings, document.tools ?? [], intelligence);
  const targetPath = metadata?.projectPath ?? document.target?.value ?? path.dirname(dir);
  const project = document.target?.displayName ?? document.workspaceName ?? path.basename(targetPath);
  const reportGeneratedAt =
    validIso(document.generatedAt) ??
    validIso(metadata?.reportGeneratedAt) ??
    validIso(document.run?.finishedAt) ??
    reportMtimeIso(dir);
  const startedAt = validIso(document.run?.startedAt) ?? validIso(metadata?.startedAt) ?? reportGeneratedAt;
  const finishedAt = validIso(document.run?.finishedAt) ?? validIso(metadata?.finishedAt) ?? reportGeneratedAt;
  const durationMs = Number(document.run?.durationMs ?? metadata?.durationMs ?? 0);
  const branch =
    document.run?.git?.branch ??
    metadata?.gitBranch ??
    projectState?.gitBranch ??
    (projectState?.kind === "filesystem" || metadata?.projectStateKind === "filesystem" ? "filesystem" : "unknown");
  const commit =
    document.run?.git?.commit ??
    metadata?.gitCommit ??
    projectState?.gitHead ??
    metadata?.projectFingerprint?.slice(0, 12) ??
    projectState?.fileStateHash?.slice(0, 12) ??
    "not recorded";
  const dirty = Boolean(document.run?.git?.dirty ?? metadata?.dirtyWorkingTree ?? projectState?.gitDirty ?? false);
  const scanId = document.scanId ?? document.run?.id ?? metadata?.scanId ?? `scan-${Date.parse(reportGeneratedAt) || Date.now()}`;
  const scanMode = document.run?.mode ?? metadata?.mode ?? "online";
  const assistMode = metadata?.assistMode ?? assist.mode;
  const assistModeLabel = metadata?.assistModeLabel ?? assist.label;

  return {
    scan: {
      id: scanId,
      scanId,
      project,
      projectName: project,
      targetPath,
      projectPath: targetPath,
      mode: scanMode,
      scanMode,
      assistMode,
      assistModeLabel,
      generatedAt: reportGeneratedAt,
      startedAt,
      finishedAt,
      reportGeneratedAt,
      durationMs,
      duration: formatDuration(durationMs),
      branch,
      gitBranch: branch,
      commit,
      gitCommit: commit,
      dirty,
      dirtyWorkingTree: dirty,
    },
    summary,
    posture: buildPosture(summary),
    scanners: normalizeScanners(document.tools ?? [], findings),
    findings: sortedFindings,
    adjudications: buildAdjudications(sortedFindings, document.explanations ?? {}),
    threatModel: buildThreatModel(sortedFindings, targetPath),
    intelligence,
    fixPlan: buildFixPlan(sortedFindings),
    evidence: {
      rawOutputs: buildRawOutputs(document),
      failedScanners: (document.tools ?? [])
        .filter((tool) => normalizeScannerStatus(tool.status) === "failed")
        .map((tool) => ({
          name: displayScannerName(tool.label ?? tool.id),
          reason: tool.message ?? "Scanner failed during this run.",
        })),
      artifactPaths: buildArtifactPaths(dir, document),
      limitations: document.limitations ?? [
        "Hermsec reports only scanner and advisory evidence supplied to this run.",
        "Agent review may prioritize findings, but raw scanner evidence remains visible.",
      ],
      redactionNote: document.evidence?.redactionApplied
        ? "Potential secrets were redacted in the evidence bundle."
        : "Hermsec did not apply additional redaction metadata for this run.",
    },
    assist,
  };
}

function readScanAssist(reportDir: string, metadata: LocalScanMetadata | null): DashboardReport["assist"] {
  const artifact = readJson<ScanAssistArtifact>(path.join(reportDir, SCAN_ASSIST_FILE));
  if (artifact) {
    return { ...artifact, available: true };
  }

  const mode = metadata?.assistMode ?? "scanner-model-summary";
  const label = metadata?.assistModeLabel ?? (mode === "deep-assisted" ? "Deep assisted scan" : "Scanner + model summary");
  return {
    schemaVersion: "1.0",
    generatedAt: metadata?.reportGeneratedAt ?? new Date().toISOString(),
    mode,
    label,
    available: false,
    summary: {
      groups: 0,
      mergedGroups: 0,
      singleScannerGroups: 0,
      scannerEvidenceItems: 0,
      note: "No scanner evidence merge artifact was written for this report.",
    },
    groups: [],
    matchingPairs: [],
  };
}

function readReportDocument(reportDir: string): HermsecDocument {
  const document = readJson<HermsecDocument>(path.join(reportDir, "report-document.json"));
  if (document) return document;

  const summary = readJson<Partial<HermsecDocument>>(path.join(reportDir, "summary.json")) ?? {};
  return {
    ...summary,
    findings: readLooseFindings(reportDir),
    tools: readJson<HermsecTool[]>(path.join(reportDir, "tools.json")) ?? [],
  };
}

function readLooseFindings(reportDir: string): HermsecFinding[] {
  const value = readJson<unknown>(path.join(reportDir, "findings.json"));
  if (Array.isArray(value)) return value as HermsecFinding[];
  if (value && typeof value === "object" && Array.isArray((value as { findings?: unknown }).findings)) {
    return (value as { findings: HermsecFinding[] }).findings;
  }
  return [];
}

function readJson<T>(filePath: string): T | null {
  if (!existsSync(filePath)) return null;
  return JSON.parse(readFileSync(filePath, "utf8")) as T;
}

function validIso(value?: string): string | undefined {
  if (!value) return undefined;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) ? new Date(timestamp).toISOString() : undefined;
}

function reportMtimeIso(reportDir: string): string {
  try {
    return new Date(statSync(path.join(reportDir, "report-document.json")).mtimeMs).toISOString();
  } catch {
    try {
      return new Date(statSync(reportDir).mtimeMs).toISOString();
    } catch {
      return new Date().toISOString();
    }
  }
}

function formatDuration(durationMs: number): string {
  if (!Number.isFinite(durationMs) || durationMs <= 0) return "not recorded";
  if (durationMs < 1000) return `${Math.round(durationMs)}ms`;
  const seconds = durationMs / 1000;
  if (seconds < 60) return `${seconds.toFixed(seconds >= 10 ? 0 : 1)}s`;
  const minutes = Math.floor(seconds / 60);
  const remaining = Math.round(seconds % 60);
  return `${minutes}m ${remaining}s`;
}

function normalizeSummary(
  summary: HermsecDocument["summary"],
  findings: DashboardReport["findings"],
  tools: HermsecTool[],
  intelligence: DashboardReport["intelligence"],
): DashboardReport["summary"] {
  const count = (severity: Severity) => findings.filter((finding) => finding.severity === severity).length;
  const value = (key: keyof DashboardReport["summary"], fallback: number) => {
    const raw = summary?.[key as keyof typeof summary];
    const parsed = Number(raw);
    return Number.isFinite(parsed) ? parsed : fallback;
  };

  const confirmedCves = new Set([
    ...findings.flatMap((finding) => finding.cve),
    ...intelligence.flatMap((item) => item.identifiers.cve),
  ]);
  return {
    totalFindings: value("totalFindings", value("total" as keyof DashboardReport["summary"], findings.length)),
    critical: value("critical", count("critical")),
    high: value("high", count("high")),
    medium: value("medium", count("medium")),
    low: value("low", count("low")),
    info: value("info", count("info")),
    secrets: value("secrets", findings.filter((finding) => finding.category === "secret").length),
    confirmedCves: value("confirmedCves", confirmedCves.size),
    knownExploited: value("knownExploited", intelligence.filter((item) => item.knownExploited).length),
    scannerFailures: value(
      "scannerFailures",
      tools.filter((tool) => normalizeScannerStatus(tool.status) === "failed").length,
    ),
  };
}

function normalizeFindings(findings: HermsecFinding[]): DashboardReport["findings"] {
  return findings.map((finding, index) => {
    const severity = normalizeSeverity(finding.severity);
    const category = finding.category || categoryFromFinding(finding);
    const file = finding.location?.file ?? "";
    const packageName = packageNameForFinding(finding);
    const packageVersion = packageVersionForFinding(finding);
    return {
      id: finding.id ?? `finding-${index + 1}`,
      title: finding.title ?? "Security finding",
      severity,
      confidence: finding.confidence ?? "medium",
      category,
      tool: displayScannerName(finding.tool),
      ruleId: finding.ruleId ?? "hermsec.finding",
      cwe: arrayValue(finding.cwe),
      cve: arrayValue(finding.cve ?? finding.identifiers?.cve),
      ghsa: arrayValue(finding.ghsa ?? finding.identifiers?.ghsa),
      osv: arrayValue(finding.osv ?? finding.identifiers?.osv),
      package: packageName,
      version: packageVersion,
      file,
      ...(finding.location?.startLine ? { line: finding.location.startLine } : {}),
      evidence: finding.evidence ?? "",
      description: finding.description ?? "",
      impact: impactForFinding(severity, category),
      remediation: finding.remediation ?? "Review the evidence, patch the affected code path, and rerun Hermsec.",
      references: arrayValue(finding.references),
      fingerprint: finding.fingerprint ?? finding.id ?? `fp-${index + 1}`,
    };
  });
}

function displayScannerName(value: string | undefined): string {
  const key = value?.trim();
  if (!key) return "HermSec";
  const displayNames = new Map<string, string>([
    ["hermsec-offline", "HermSec heuristics"],
    ["hermsec-heuristics", "HermSec heuristics"],
    ["hermsec", "HermSec"],
    ["semgrep", "Semgrep"],
    ["gitleaks", "Gitleaks"],
    ["trufflehog", "TruffleHog"],
    ["osv-scanner", "OSV-Scanner"],
    ["trivy", "Trivy"],
    ["checkov", "Checkov"],
    ["bandit", "Bandit"],
    ["pip-audit", "pip-audit"],
    ["pmg", "SafeDep PMG npm audit"],
    ["npm-audit", "SafeDep PMG npm audit"],
    ["retire", "Retire.js"],
    ["spotbugs", "FindSecBugs / SpotBugs"],
    ["dependency-check", "OWASP Dependency-Check"],
    ["psalm", "Psalm taint analysis"],
    ["composer", "Composer audit"],
    ["gosec", "gosec"],
    ["govulncheck", "govulncheck"],
    ["cargo", "cargo-audit"],
    ["brakeman", "Brakeman"],
    ["flawfinder", "Flawfinder"],
    ["cppcheck", "Cppcheck"],
    ["dotnet", ".NET vulnerable packages"],
  ]);
  return displayNames.get(key.toLowerCase()) ?? key;
}

function normalizeScanners(
  tools: HermsecTool[],
  findings: DashboardReport["findings"],
): DashboardReport["scanners"] {
  if (tools.length === 0) {
    return [
      {
        id: "hermsec",
        name: "HermSec scan",
        status: "completed",
        findings: findings.length,
        message: "HermSec generated scanner evidence for this report.",
      },
    ];
  }

  return tools.map((tool) => {
    const id = tool.id ?? tool.label ?? "scanner";
    const label = displayScannerName(tool.label ?? id);
    return {
      id,
      name: label,
      status: normalizeScannerStatus(tool.status),
      findings: countToolFindings(id, tool.label, tool.message, findings),
      ...(tool.durationMs ? { durationMs: tool.durationMs } : {}),
      message: tool.message ?? "Scanner status recorded by HermSec.",
    };
  });
}

function normalizeScannerStatus(status?: string): ScannerStatus {
  if (status === "completed" || status === "running" || status === "waiting" || status === "skipped" || status === "failed") {
    return status;
  }
  if (status === "ready") return "completed";
  return "waiting";
}

function countToolFindings(
  toolId: string,
  toolLabel: string | undefined,
  message: string | undefined,
  findings: DashboardReport["findings"],
): number {
  const displayLabel = displayScannerName(toolLabel ?? toolId);
  const lowered = [toolId, toolLabel ?? "", displayLabel].join(" ").toLowerCase();
  const direct = findings.filter((finding) => lowered.includes(finding.tool.toLowerCase())).length;
  if (direct > 0) return direct;
  const match = message?.match(/completed with\s+(\d+)\s+finding/i);
  return match ? Number(match[1]) : 0;
}

function buildPosture(summary: DashboardReport["summary"]): DashboardReport["posture"] {
  if (summary.critical > 0 || summary.high > 0 || summary.secrets > 0) {
    return {
      label: "At Risk",
      grade: "At Risk",
      className: "at-risk",
      class: "at-risk",
      headline: `${summary.critical + summary.high} high-priority issues need attention`,
      detail: `${summary.totalFindings} findings were produced across the configured scanner stack.`,
      recommendation: "Fix command execution, exposed secret, and injection findings first, then rerun the scan.",
    };
  }

  if (summary.medium > 0) {
    return {
      label: "Review Needed",
      grade: "Review Needed",
      className: "review",
      class: "review",
      headline: "No critical blockers, but medium-risk work remains",
      detail: `${summary.medium} medium findings should be reviewed before release.`,
      recommendation: "Patch medium severity findings and keep the scheduled scan active.",
    };
  }

  return {
    label: "Stable",
    grade: "Stable",
    className: "stable",
    class: "stable",
    headline: "No urgent findings in this scan",
    detail: "Hermsec did not find critical, high, or medium evidence in the latest run.",
    recommendation: "Keep monitoring dependencies, secrets, and risky code paths on a schedule.",
  };
}

function buildAdjudications(
  findings: DashboardReport["findings"],
  explanations: Record<string, ModelExplanation | undefined>,
): DashboardReport["adjudications"] {
  return findings.slice(0, 12).map((finding) => {
    const fixFirst = finding.severity === "critical" || finding.severity === "high" || finding.category === "secret";
    const explanation = explanations[finding.id];
    return {
      findingId: finding.id,
      verdict: finding.confidence === "confirmed" ? "confirmed" : fixFirst ? "likely exploitable" : "needs review",
      reasoning:
        explanation?.evidenceSummary ||
        explanation?.confidenceReason ||
        finding.description ||
        `Hermsec scanner evidence flagged ${finding.ruleId}. The raw evidence remains available in the appendix.`,
      priority: fixFirst ? "Fix before shipping" : finding.severity === "medium" ? "Fix this week" : "Monitor",
      fixFirst,
      trustBoundary: trustBoundaryForFinding(finding),
      assumptions: [
        "Hermsec used scanner evidence from this run only.",
        explanation
          ? "Model explanation text was accepted only when supported by supplied scanner evidence."
          : "No accepted model explanation was available for this finding.",
        "Human review should confirm business context before accepting residual risk.",
      ],
    };
  });
}

function buildThreatModel(findings: DashboardReport["findings"], targetPath: string): DashboardReport["threatModel"] {
  const categories = new Set(findings.map((finding) => finding.category));
  return {
    assets: [
      "Source code and project configuration",
      "Dependency manifests and lockfiles",
      "Application secrets, tokens, and environment variables",
      "User data reachable through application endpoints",
    ],
    entryPoints: [
      "HTTP request handlers and API routes",
      "Package installation and dependency update workflows",
      "Developer machines and local configuration files",
      `Repository path: ${targetPath}`,
    ],
    trustBoundaries: [
      "User input crossing into application code",
      "Third-party packages crossing into local execution",
      "Secrets crossing from local development into source control",
    ],
    attackerCapabilities: [
      "Submit crafted inputs to web endpoints",
      "Influence dependency versions or package metadata",
      "Search public or shared repositories for committed credentials",
    ],
    abusePaths: [
      categories.has("secret")
        ? "Committed secrets can be copied and reused outside the project."
        : "Secrets were not highlighted, but credential hygiene still matters.",
      categories.has("code")
        ? "Risky code paths can turn untrusted input into execution, injection, or XSS."
        : "No risky code pattern category dominated this scan.",
      categories.has("supply-chain")
        ? "Unpinned or vulnerable dependencies can introduce supply-chain compromise."
        : "Dependency risk should still be watched as versions change.",
    ],
    mitigations: [
      "Patch high-priority findings first and rerun Hermsec.",
      "Move secrets into environment-managed storage and rotate exposed values.",
      "Commit lockfiles and review dependency updates through the scanner stack.",
    ],
    unresolvedAssumptions: [
      "Runtime secrets and production traffic were not inspected by this local scan.",
      "Exploitability depends on deployed configuration and reachable routes.",
    ],
  };
}

function buildIntelligence(
  intelligence: HermsecDocument["intelligence"],
  findings: DashboardReport["findings"],
): DashboardReport["intelligence"] {
  if (intelligence && intelligence.length > 0) {
    return intelligence.map((item) => {
      const identifiers = {
        cve: arrayValue(item.identifiers?.cve),
        ghsa: arrayValue(item.identifiers?.ghsa),
        osv: arrayValue(item.identifiers?.osv),
        cwe: arrayValue(item.identifiers?.cwe),
      };
      const cve = item.cve ?? identifiers.cve[0] ?? identifiers.ghsa[0] ?? identifiers.osv[0] ?? "";
      return {
        title: item.title ?? cve ?? "Matched vulnerability intelligence",
        source: item.source ?? "Security intelligence",
        severity: item.severity ?? "info",
        knownExploited: Boolean(item.knownExploited),
        ecosystem: item.ecosystem ?? "project",
        package: item.packageLabel ?? item.packageName ?? "",
        cve,
        published: item.publishedAt ?? item.modifiedAt ?? "",
        whyItMatters: item.whyItMatters ?? ((item.reasons ?? []).join(" ") || "Trusted advisory intelligence matched this scan."),
        url: item.url ?? "",
        findingIds: arrayValue(item.findingIds),
        identifiers,
        matchedPackages: arrayValue(item.matchedPackages),
        reasons: arrayValue(item.reasons),
        priority: item.priority ?? (item.knownExploited ? "urgent" : "normal"),
        fixVersion: item.fixVersion ?? "",
      };
    });
  }

  return findings
    .filter((finding) => finding.cve.length > 0 || finding.ghsa.length > 0 || finding.osv.length > 0)
    .map((finding) => {
      const cve = finding.cve[0] ?? finding.ghsa[0] ?? finding.osv[0] ?? "";
      return {
        title: `${cve || finding.ruleId} affects ${finding.package || finding.title}`,
        source: finding.cve.length > 0 ? "CVE" : finding.ghsa.length > 0 ? "GitHub Advisory" : "OSV",
        severity: finding.severity,
        knownExploited: false,
        ecosystem: finding.package ? "dependency" : "project",
        package: finding.package,
        cve,
        published: "",
        whyItMatters: finding.description || finding.remediation,
        url: firstReference(finding),
        findingIds: [finding.id],
        identifiers: {
          cve: finding.cve,
          ghsa: finding.ghsa,
          osv: finding.osv,
          cwe: finding.cwe,
        },
        matchedPackages: finding.package ? [`dependency:${finding.package}${finding.version ? `@${finding.version}` : ""}`] : [],
        reasons: ["This legacy report finding already contained an advisory identifier."],
        priority: finding.severity === "critical" || finding.severity === "high" ? "high" : "normal",
        fixVersion: "",
      };
    });
}

function buildFixPlan(findings: DashboardReport["findings"]): DashboardReport["fixPlan"] {
  const toItem = (finding: DashboardReport["findings"][number]): FixPlanItem => ({
    title: finding.title,
    findingIds: [finding.id],
    owner: "Project maintainer",
    effort: finding.severity === "critical" || finding.severity === "high" ? "Medium" : "Low",
    validation: "Rerun Hermsec and confirm this finding no longer appears.",
    command: "Run Scan again from the Hermsec dashboard.",
  });

  return {
    fixNow: findings
      .filter((finding) => finding.severity === "critical" || finding.severity === "high" || finding.category === "secret")
      .slice(0, 6)
      .map(toItem),
    fixThisWeek: findings.filter((finding) => finding.severity === "medium").slice(0, 6).map(toItem),
    monitor: findings.filter((finding) => finding.severity === "low" || finding.severity === "info").slice(0, 6).map(toItem),
    needsContext: findings
      .filter((finding) => finding.confidence === "low" || finding.confidence === "medium")
      .slice(0, 4)
      .map(toItem),
  };
}

function buildRawOutputs(document: HermsecDocument): Array<{ scanner: string; content: string }> {
  const tools = document.tools ?? [];
  return tools.map((tool) => ({
    scanner: displayScannerName(tool.label ?? tool.id),
    content: tool.message ?? "No scanner message was recorded.",
  }));
}

function buildArtifactPaths(reportDir: string, document: HermsecDocument): string[] {
  const paths = [
    "report.html",
    "summary.json",
    "findings.json",
    "report-document.json",
    path.join("dashboard", "index.html"),
    path.join("onepager", "index.html"),
    path.join("onepager", "report.pdf"),
    ...(document.evidence?.rawArtifacts ?? []),
  ];
  return paths.map((item) => path.resolve(reportDir, item));
}

function normalizeSeverity(value?: string): Severity {
  const lowered = value?.toLowerCase();
  if (lowered === "critical" || lowered === "high" || lowered === "medium" || lowered === "low" || lowered === "info") {
    return lowered;
  }
  return "info";
}

function arrayValue(value?: string[] | string): string[] {
  if (!value) return [];
  return Array.isArray(value) ? value.filter(Boolean) : [value].filter(Boolean);
}

function packageNameForFinding(finding: HermsecFinding): string {
  if (!finding.package) return "";
  if (typeof finding.package === "string") return finding.package;
  return finding.package.name ?? "";
}

function packageVersionForFinding(finding: HermsecFinding): string {
  if (finding.version) return finding.version;
  if (!finding.package || typeof finding.package === "string") return "";
  return finding.package.installedVersion ?? finding.package.version ?? "";
}

function categoryFromFinding(finding: HermsecFinding): string {
  const text = `${finding.title ?? ""} ${finding.ruleId ?? ""}`.toLowerCase();
  if (/secret|token|credential|key/.test(text)) return "secret";
  if (/package|dependency|cve|ghsa|osv|supply/.test(text)) return "supply-chain";
  return "code";
}

function impactForFinding(severity: Severity, category: string): string {
  if (category === "secret") return "An exposed credential can be reused until it is revoked or rotated.";
  if (severity === "critical") return "This could become direct compromise if the affected path is reachable.";
  if (severity === "high") return "This is likely to matter in realistic project usage and should be fixed early.";
  if (severity === "medium") return "This needs review and may become serious depending on project context.";
  return "This is a hardening or hygiene issue to monitor.";
}

function trustBoundaryForFinding(finding: DashboardReport["findings"][number]): string {
  if (finding.category === "secret") return "Source control to external credential use";
  if (finding.category === "supply-chain") return "Third-party package ecosystem to local execution";
  if (/xss|html|sql|command|exec|eval|input/i.test(`${finding.ruleId} ${finding.title}`)) {
    return "Untrusted input to application execution";
  }
  return "Project code to runtime behavior";
}

function firstReference(finding: DashboardReport["findings"][number]): string {
  if (finding.references.length > 0) return finding.references[0];
  if (finding.cve.length > 0) return `https://nvd.nist.gov/vuln/detail/${finding.cve[0]}`;
  if (finding.ghsa.length > 0) return `https://github.com/advisories/${finding.ghsa[0]}`;
  if (finding.osv.length > 0) return `https://osv.dev/vulnerability/${finding.osv[0]}`;
  return "";
}
