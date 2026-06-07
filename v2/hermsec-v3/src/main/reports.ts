import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import type {
  DashboardBundleRequest,
  DashboardBundleResult,
  ExplainReportRequest,
  ExplainReportResult,
  LatestReportResult,
  OpenArtifactRequest,
  OpenArtifactResult,
} from "../renderer/src/types/reports";
import { dashboardBundle } from "./reportArtifacts";
import { openReportLocation } from "./scan";
import { readSettings } from "./store";

type Finding = {
  title?: string;
  severity?: string;
  category?: string;
  confidence?: string;
  tool?: string;
  ruleId?: string;
  cwe?: string[];
  description?: string;
  evidence?: string;
  remediation?: string;
  location?: {
    file?: string;
    startLine?: number;
  };
};

type SummaryFile = {
  generatedAt?: string;
  scanId?: string;
  summary?: Record<string, unknown>;
  target?: {
    displayName?: string;
    value?: string;
  };
  workspaceName?: string;
};

interface ReportCandidate {
  reportDir: string;
  generatedAt: string;
  projectPath?: string;
  mtimeMs: number;
}

export function explainReport(request: ExplainReportRequest): ExplainReportResult {
  try {
    const reportPath = path.resolve(request.reportPath);
    if (!existsSync(reportPath)) {
      return { ok: false, message: `Report not found: ${reportPath}`, reportPath };
    }

    const reportDir = path.dirname(reportPath);
    const summary = readJson<SummaryFile>(path.join(reportDir, "summary.json"));
    const findings = normalizeFindings(readJson<unknown>(path.join(reportDir, "findings.json")));
    const question = request.question.toLowerCase();
    const answer = buildReportAnswer({
      reportPath,
      summary,
      findings,
      intent: classifyReportIntent(question),
    });

    return { ok: true, message: answer, reportPath };
  } catch (error) {
    return {
      ok: false,
      message: error instanceof Error ? error.message : "Could not explain the report.",
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

export function latestReport(projectPath?: string): LatestReportResult {
  try {
    const settings = readSettings();
    const root = settings.defaultReportDir;
    if (!existsSync(root)) {
      return { ok: false, message: `Report directory was not found: ${root}` };
    }

    const normalizedProject = projectPath ? normalizePath(projectPath) : undefined;
    const candidate = collectReportCandidates(root)
      .filter((item) => (normalizedProject ? normalizePath(item.projectPath ?? "") === normalizedProject : true))
      .sort((a, b) => {
        const time = Date.parse(b.generatedAt) - Date.parse(a.generatedAt);
        return Number.isFinite(time) && time !== 0 ? time : b.mtimeMs - a.mtimeMs;
      })[0];

    if (!candidate) {
      return { ok: false, message: "No report has been generated for this project yet.", projectPath };
    }

    return candidateToLatest(candidate, projectPath);
  } catch (error) {
    return {
      ok: false,
      message: error instanceof Error ? error.message : "Could not locate the latest report.",
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

export function getDashboardBundle(request: DashboardBundleRequest): DashboardBundleResult {
  return dashboardBundle(request.reportPathOrDir);
}

export async function openArtifact(request: OpenArtifactRequest): Promise<OpenArtifactResult> {
  return openReportLocation({ path: request.path });
}

function readJson<T>(filePath: string): T | null {
  if (!existsSync(filePath)) return null;
  return JSON.parse(readFileSync(filePath, "utf8")) as T;
}

function collectReportCandidates(root: string): ReportCandidate[] {
  const candidates: ReportCandidate[] = [];
  walkReportDirs(path.resolve(root), candidates, 0);
  return candidates;
}

function walkReportDirs(current: string, candidates: ReportCandidate[], depth: number): void {
  if (depth > 8 || candidates.length > 2000) return;

  const reportDocumentPath = path.join(current, "report-document.json");
  const summaryPath = path.join(current, "summary.json");
  if (existsSync(reportDocumentPath) || existsSync(summaryPath)) {
    const document = readJson<SummaryFile>(reportDocumentPath) ?? readJson<SummaryFile>(summaryPath);
    let mtimeMs = Date.now();
    try {
      mtimeMs = statSync(existsSync(reportDocumentPath) ? reportDocumentPath : summaryPath).mtimeMs;
    } catch {
      // Keep a stable fallback if the file disappears between checks.
    }
    candidates.push({
      reportDir: current,
      generatedAt: document?.generatedAt ?? new Date(mtimeMs).toISOString(),
      projectPath: document?.target?.value,
      mtimeMs,
    });
  }

  let entries;
  try {
    entries = readdirSync(current, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    if (entry.name === "dashboard" || entry.name === "onepager") continue;
    walkReportDirs(path.join(current, entry.name), candidates, depth + 1);
  }
}

function candidateToLatest(candidate: ReportCandidate, projectPath?: string): LatestReportResult {
  const reportDir = candidate.reportDir;
  const htmlPath = path.join(reportDir, "report.html");
  const dashboardHtmlPath = path.join(reportDir, "dashboard", "index.html");
  const onepagerHtmlPath = path.join(reportDir, "onepager", "index.html");
  const onepagerPdfPath = path.join(reportDir, "onepager", "report.pdf");
  const projectState = readJson<LatestReportResult["projectState"]>(path.join(reportDir, "project-state.json"));
  return {
    ok: true,
    projectPath: projectPath ?? candidate.projectPath,
    reportDir,
    ...(existsSync(htmlPath) ? { htmlPath } : {}),
    ...(existsSync(dashboardHtmlPath) ? { dashboardHtmlPath } : {}),
    ...(existsSync(onepagerHtmlPath) ? { onepagerHtmlPath } : {}),
    ...(existsSync(onepagerPdfPath) ? { onepagerPdfPath } : {}),
    generatedAt: candidate.generatedAt,
    ...(projectState ? { projectState } : {}),
  };
}

function normalizeFindings(value: unknown): Finding[] {
  if (Array.isArray(value)) return value as Finding[];
  if (value && typeof value === "object" && Array.isArray((value as { findings?: unknown }).findings)) {
    return (value as { findings: Finding[] }).findings;
  }
  return [];
}

function classifyReportIntent(question: string): "fixes" | "severity" | "secrets" | "summary" {
  if (/\b(fix|remed|patch|solve|resolve|how do i)\b/.test(question)) return "fixes";
  if (/\b(severity|critical|high|medium|low|priorit|risk)\b/.test(question)) return "severity";
  if (/\b(secret|token|key|credential)\b/.test(question)) return "secrets";
  return "summary";
}

function buildReportAnswer({
  reportPath,
  summary,
  findings,
  intent,
}: {
  reportPath: string;
  summary: SummaryFile | null;
  findings: Finding[];
  intent: "fixes" | "severity" | "secrets" | "summary";
}): string {
  const counts = normalizeCounts(summary?.summary, findings);
  const targetName =
    summary?.target?.displayName ?? summary?.workspaceName ?? path.basename(path.dirname(path.dirname(reportPath)));
  const topFindings = sortFindings(findings).slice(0, intent === "fixes" ? 5 : 4);
  const scannerFailureText = counts.scannerFailures > 0
    ? ` One scanner reported a failure, so treat this as a strong first pass rather than the final word.`
    : "";

  if (intent === "fixes") {
    return [
      `For ${targetName}, I would fix these first based on the HTML report:`,
      ...topFindings.map((finding, index) => formatFixFinding(finding, index + 1)),
      "",
      `After patching, rerun an Online scan and compare the new report against this one.${scannerFailureText}`,
    ].join("\n");
  }

  if (intent === "severity") {
    return [
      `The report for ${targetName} has ${counts.total} findings: ${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low, and ${counts.info} info.`,
      `Priority order: fix critical code-execution issues first, then exposed secrets, then injection and unsafe dynamic code paths.`,
      ...topFindings.map((finding, index) => formatBriefFinding(finding, index + 1)),
      scannerFailureText.trim(),
    ].filter(Boolean).join("\n");
  }

  if (intent === "secrets") {
    const secretFindings = findings.filter((finding) => finding.category === "secret" || /secret|token|key/i.test(finding.title ?? ""));
    if (secretFindings.length === 0) {
      return `I do not see secret findings in the latest report for ${targetName}. Still, rotate any credential that may have been committed and rerun the scan after cleanup.`;
    }
    return [
      `The latest report found ${secretFindings.length} secret-related issue${secretFindings.length === 1 ? "" : "s"} in ${targetName}.`,
      ...secretFindings.slice(0, 4).map((finding, index) => formatFixFinding(finding, index + 1)),
      "",
      "For secrets, the safe response is remove them from code, rotate the exposed value, and move future values into environment variables or a secret manager.",
    ].join("\n");
  }

  return [
    `Here is the security readout from the latest Hermsec HTML report for ${targetName}:`,
    `It found ${counts.total} findings: ${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low, and ${counts.info} info. Secrets flagged: ${counts.secrets}.`,
    ...topFindings.map((finding, index) => formatBriefFinding(finding, index + 1)),
    "",
    `The practical next step is to fix the highest-severity executable-code and secret findings, then rerun the Online scan to confirm the report improves.${scannerFailureText}`,
  ].join("\n");
}

function normalizeCounts(summary: Record<string, unknown> | undefined, findings: Finding[]) {
  const countSeverity = (severity: string) =>
    findings.filter((finding) => finding.severity?.toLowerCase() === severity).length;
  return {
    total: numberValue(summary?.total, findings.length),
    critical: numberValue(summary?.critical, countSeverity("critical")),
    high: numberValue(summary?.high, countSeverity("high")),
    medium: numberValue(summary?.medium, countSeverity("medium")),
    low: numberValue(summary?.low, countSeverity("low")),
    info: numberValue(summary?.info, countSeverity("info")),
    secrets: numberValue(summary?.secrets, findings.filter((finding) => finding.category === "secret").length),
    scannerFailures: numberValue(summary?.scannerFailures, 0),
  };
}

function numberValue(value: unknown, fallback: number): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function sortFindings(findings: Finding[]): Finding[] {
  const rank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  return [...findings].sort((a, b) => (rank[a.severity ?? "info"] ?? 5) - (rank[b.severity ?? "info"] ?? 5));
}

function formatBriefFinding(finding: Finding, index: number): string {
  const location = formatLocation(finding);
  return `${index}. ${finding.severity?.toUpperCase() ?? "INFO"}: ${finding.title ?? "Security finding"}${location ? ` at ${location}` : ""}. ${finding.description ?? ""}`.trim();
}

function formatFixFinding(finding: Finding, index: number): string {
  const location = formatLocation(finding);
  return `${index}. ${finding.title ?? "Security finding"}${location ? ` (${location})` : ""}: ${finding.remediation ?? "Review the evidence, patch the risky code path, and rerun the scan."}`;
}

function formatLocation(finding: Finding): string {
  if (!finding.location?.file) return "";
  return `${finding.location.file}${finding.location.startLine ? `:${finding.location.startLine}` : ""}`;
}

function normalizePath(filePath: string): string {
  return path.resolve(filePath).toLowerCase();
}
