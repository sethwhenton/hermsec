import { existsSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import type { HermsecScanAssistMode } from "../renderer/src/types/scan";

export const SCAN_ASSIST_FILE = "scan-assist.json";

type Severity = "critical" | "high" | "medium" | "low" | "info";

interface ReportFinding {
  id?: string;
  title?: string;
  severity?: string;
  confidence?: string;
  category?: string;
  tool?: string;
  ruleId?: string;
  cwe?: string[];
  evidence?: string;
  remediation?: string;
  description?: string;
  fingerprint?: string;
  identifiers?: {
    cve?: string[];
    ghsa?: string[];
    osv?: string[];
  };
  location?: {
    file?: string;
    startLine?: number;
    endLine?: number;
  };
  package?: {
    ecosystem?: string;
    name?: string;
    installedVersion?: string;
  };
}

interface ReportDocument {
  findings?: ReportFinding[];
  tools?: Array<{ id?: string; label?: string; status?: string; message?: string }>;
  summary?: Record<string, unknown>;
}

export interface ScannerEvidenceItem {
  findingId: string;
  scanner: string;
  ruleId: string;
  severity: Severity;
  confidence: string;
  location: string;
  evidence: string;
}

export interface ScanAssistGroup {
  id: string;
  key: string;
  title: string;
  severity: Severity;
  category: string;
  confidence: "scanner-confirmed" | "multi-scanner" | "needs-review";
  findingIds: string[];
  scanners: string[];
  locations: string[];
  cwe: string[];
  evidence: ScannerEvidenceItem[];
  merged: boolean;
  modelSupport: string;
  recommendation: string;
}

export interface ScanAssistArtifact {
  schemaVersion: "1.0";
  generatedAt: string;
  mode: HermsecScanAssistMode;
  label: string;
  summary: {
    groups: number;
    mergedGroups: number;
    singleScannerGroups: number;
    scannerEvidenceItems: number;
    note: string;
  };
  groups: ScanAssistGroup[];
  matchingPairs: Array<{
    groupId: string;
    scannerA: string;
    findingA: string;
    scannerB: string;
    findingB: string;
    reason: string;
  }>;
}

const severityRank: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export function assistModeLabel(mode: HermsecScanAssistMode): string {
  return mode === "deep-assisted" ? "Deep assisted scan" : "Scanner + model summary";
}

export function writeScanAssistArtifact(
  reportDir: string,
  mode: HermsecScanAssistMode,
): string | undefined {
  const artifact = buildScanAssistArtifact(reportDir, mode);
  if (!artifact) return undefined;
  const artifactPath = path.join(reportDir, SCAN_ASSIST_FILE);
  writeFileSync(artifactPath, JSON.stringify(artifact, null, 2), "utf8");
  return artifactPath;
}

function buildScanAssistArtifact(
  reportDir: string,
  mode: HermsecScanAssistMode,
): ScanAssistArtifact | undefined {
  const document = readReportDocument(reportDir);
  const findings = normalizeFindings(document?.findings ?? readLooseFindings(reportDir));
  if (findings.length === 0) {
    return {
      schemaVersion: "1.0",
      generatedAt: new Date().toISOString(),
      mode,
      label: assistModeLabel(mode),
      summary: {
        groups: 0,
        mergedGroups: 0,
        singleScannerGroups: 0,
        scannerEvidenceItems: 0,
        note: modeNote(mode),
      },
      groups: [],
      matchingPairs: [],
    };
  }

  const grouped = new Map<string, ReportFinding[]>();
  for (const finding of findings) {
    const key = groupKey(finding);
    grouped.set(key, [...(grouped.get(key) ?? []), finding]);
  }

  const groups = Array.from(grouped.entries())
    .map(([key, items], index) => buildGroup(key, items, index + 1, mode))
    .sort((left, right) => severityRank[left.severity] - severityRank[right.severity] || right.evidence.length - left.evidence.length);
  const matchingPairs = groups.flatMap(buildMatchingPairs);

  return {
    schemaVersion: "1.0",
    generatedAt: new Date().toISOString(),
    mode,
    label: assistModeLabel(mode),
    summary: {
      groups: groups.length,
      mergedGroups: groups.filter((group) => group.merged).length,
      singleScannerGroups: groups.filter((group) => !group.merged).length,
      scannerEvidenceItems: groups.reduce((sum, group) => sum + group.evidence.length, 0),
      note: modeNote(mode),
    },
    groups,
    matchingPairs,
  };
}

function readReportDocument(reportDir: string): ReportDocument | undefined {
  return readJson<ReportDocument>(path.join(reportDir, "report-document.json")) ?? undefined;
}

function readLooseFindings(reportDir: string): ReportFinding[] {
  const value = readJson<unknown>(path.join(reportDir, "findings.json"));
  if (Array.isArray(value)) return value as ReportFinding[];
  if (value && typeof value === "object" && Array.isArray((value as { findings?: unknown }).findings)) {
    return (value as { findings: ReportFinding[] }).findings;
  }
  return [];
}

function readJson<T>(filePath: string): T | null {
  if (!existsSync(filePath)) return null;
  return JSON.parse(readFileSync(filePath, "utf8")) as T;
}

function normalizeFindings(findings: ReportFinding[]): ReportFinding[] {
  return findings.map((finding, index) => ({
    ...finding,
    id: finding.id ?? `finding-${index + 1}`,
    title: finding.title ?? "Security finding",
    severity: normalizeSeverity(finding.severity),
    confidence: finding.confidence ?? "medium",
    category: finding.category ?? categoryFromFinding(finding),
    tool: finding.tool ?? "hermsec",
    ruleId: finding.ruleId ?? "hermsec.finding",
  }));
}

function buildGroup(
  key: string,
  findings: ReportFinding[],
  index: number,
  mode: HermsecScanAssistMode,
): ScanAssistGroup {
  const scanners = Array.from(new Set(findings.map((finding) => finding.tool ?? "hermsec"))).sort();
  const locations = Array.from(new Set(findings.map(formatLocation).filter(Boolean))).sort();
  const cwe = Array.from(new Set(findings.flatMap((finding) => finding.cwe ?? []))).sort();
  const sorted = [...findings].sort(
    (left, right) => severityRank[normalizeSeverity(left.severity)] - severityRank[normalizeSeverity(right.severity)],
  );
  const top = sorted[0];
  const evidence = sorted.map(toEvidence);
  const merged = scanners.length > 1 || findings.length > 1;

  return {
    id: `assist-${String(index).padStart(3, "0")}`,
    key,
    title: top.title ?? "Security finding",
    severity: normalizeSeverity(top.severity),
    category: top.category ?? categoryFromFinding(top),
    confidence: merged ? "multi-scanner" : "scanner-confirmed",
    findingIds: sorted.map((finding) => finding.id ?? ""),
    scanners,
    locations,
    cwe,
    evidence,
    merged,
    modelSupport:
      mode === "deep-assisted"
        ? "Deep mode may use the model to explain and prioritize this merged scanner-backed group."
        : "Summary mode keeps model use to the final scanner-backed summary.",
    recommendation: top.remediation ?? "Review the grouped scanner evidence, patch the risky code path, and rerun Hermsec.",
  };
}

function toEvidence(finding: ReportFinding): ScannerEvidenceItem {
  return {
    findingId: finding.id ?? "",
    scanner: finding.tool ?? "hermsec",
    ruleId: finding.ruleId ?? "hermsec.finding",
    severity: normalizeSeverity(finding.severity),
    confidence: finding.confidence ?? "medium",
    location: formatLocation(finding),
    evidence: trimEvidence(finding.evidence ?? finding.description ?? "Scanner evidence was recorded for this finding."),
  };
}

function buildMatchingPairs(group: ScanAssistGroup): ScanAssistArtifact["matchingPairs"] {
  if (!group.merged) return [];
  const pairs: ScanAssistArtifact["matchingPairs"] = [];
  for (let i = 0; i < group.evidence.length; i += 1) {
    for (let j = i + 1; j < group.evidence.length; j += 1) {
      const left = group.evidence[i];
      const right = group.evidence[j];
      if (left.findingId === right.findingId) continue;
      pairs.push({
        groupId: group.id,
        scannerA: left.scanner,
        findingA: left.findingId,
        scannerB: right.scanner,
        findingB: right.findingId,
        reason: pairReason(group),
      });
    }
  }
  return pairs.slice(0, 24);
}

function pairReason(group: ScanAssistGroup): string {
  if (group.locations.length > 0 && group.cwe.length > 0) {
    return `Shared location and CWE: ${group.locations[0]} / ${group.cwe[0]}.`;
  }
  if (group.locations.length > 0) return `Shared location: ${group.locations[0]}.`;
  if (group.cwe.length > 0) return `Shared CWE/category signal: ${group.cwe[0]}.`;
  return "Similar scanner title, package, or rule evidence.";
}

function groupKey(finding: ReportFinding): string {
  const identifiers = [
    ...(finding.identifiers?.cve ?? []),
    ...(finding.identifiers?.ghsa ?? []),
    ...(finding.identifiers?.osv ?? []),
  ];
  if (finding.package?.name && identifiers.length > 0) {
    return `package:${clean(finding.package.ecosystem)}:${clean(finding.package.name)}:${clean(identifiers[0])}`;
  }

  const location = finding.location?.file;
  const line = finding.location?.startLine;
  const primaryCwe = finding.cwe?.[0];
  if (location && line) {
    return `loc:${clean(location)}:${Math.floor(Number(line) / 5)}:${clean(primaryCwe ?? finding.category ?? titleStem(finding.title))}`;
  }
  if (location) {
    return `file:${clean(location)}:${clean(primaryCwe ?? finding.category ?? titleStem(finding.title))}`;
  }
  if (primaryCwe) {
    return `cwe:${clean(primaryCwe)}:${clean(finding.category ?? titleStem(finding.title))}`;
  }
  return `title:${clean(finding.category ?? "code")}:${titleStem(finding.title)}`;
}

function normalizeSeverity(value?: string): Severity {
  const lowered = value?.toLowerCase();
  if (lowered === "critical" || lowered === "high" || lowered === "medium" || lowered === "low" || lowered === "info") {
    return lowered;
  }
  return "info";
}

function categoryFromFinding(finding: ReportFinding): string {
  const text = `${finding.title ?? ""} ${finding.ruleId ?? ""}`.toLowerCase();
  if (/secret|token|credential|key/.test(text)) return "secret";
  if (/package|dependency|cve|ghsa|osv|supply/.test(text)) return "supply-chain";
  return "code";
}

function formatLocation(finding: ReportFinding): string {
  if (!finding.location?.file) return "";
  return `${finding.location.file}${finding.location.startLine ? `:${finding.location.startLine}` : ""}`;
}

function clean(value?: string): string {
  return String(value ?? "")
    .toLowerCase()
    .replace(/[^a-z0-9_.:/-]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

function titleStem(value?: string): string {
  return clean(value)
    .split("-")
    .filter((part) => part.length > 2)
    .slice(0, 5)
    .join("-");
}

function trimEvidence(value: string): string {
  const collapsed = value.replace(/\s+/g, " ").trim();
  return collapsed.length > 220 ? `${collapsed.slice(0, 217)}...` : collapsed;
}

function modeNote(mode: HermsecScanAssistMode): string {
  return mode === "deep-assisted"
    ? "Deep assisted scan groups matching scanner findings and allows model-supported triage over that scanner evidence."
    : "Scanner + model summary keeps scanner output authoritative and uses the model only for concise report-level summarization.";
}

