import path from "node:path";

export type ReportArtifactPaths = {
  workspaceSlug: string;
  timestampSlug: string;
  rootDir: string;
  reportDir: string;
  rawDir: string;
  htmlPath: string;
  cssPath: string;
  markdownPath: string;
  summaryPath: string;
  findingsPath: string;
  evidencePath: string;
  runPath: string;
  agentSummaryPath: string;
  deltaPath: string;
  documentPath: string;
};

export function safeWorkspaceSlug(value: string): string {
  const compact = value
    .normalize("NFKD")
    .replace(/[^\w.\- ]+/g, "")
    .trim()
    .replace(/\s+/g, "-")
    .replace(/[.]{2,}/g, ".")
    .replace(/^-+|-+$/g, "")
    .toLowerCase();

  const slug = compact.length > 0 ? compact : "workspace";
  return slug.slice(0, 80);
}

export function timestampSlug(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    throw new Error(`Invalid report timestamp: ${value}`);
  }
  return date.toISOString().replace(/[:.]/g, "-");
}

export function createReportArtifactPaths(
  rootDir: string,
  workspaceName: string,
  generatedAt: string
): ReportArtifactPaths {
  const resolvedRoot = path.resolve(rootDir);
  const workspaceSlug = safeWorkspaceSlug(workspaceName);
  const timestamp = timestampSlug(generatedAt);
  const reportDir = assertInsideRoot(resolvedRoot, path.join(resolvedRoot, workspaceSlug, timestamp));
  const rawDir = assertInsideRoot(resolvedRoot, path.join(reportDir, "raw"));

  return {
    workspaceSlug,
    timestampSlug: timestamp,
    rootDir: resolvedRoot,
    reportDir,
    rawDir,
    htmlPath: path.join(reportDir, "report.html"),
    cssPath: path.join(reportDir, "report.css"),
    markdownPath: path.join(reportDir, "report.md"),
    summaryPath: path.join(reportDir, "summary.json"),
    findingsPath: path.join(reportDir, "findings.json"),
    evidencePath: path.join(reportDir, "evidence.json"),
    runPath: path.join(reportDir, "run.json"),
    agentSummaryPath: path.join(reportDir, "agent-summary.json"),
    deltaPath: path.join(reportDir, "delta.json"),
    documentPath: path.join(reportDir, "report-document.json")
  };
}

export function assertInsideRoot(rootDir: string, candidatePath: string): string {
  const resolvedRoot = path.resolve(rootDir);
  const resolvedCandidate = path.resolve(candidatePath);
  const relative = path.relative(resolvedRoot, resolvedCandidate);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error(`Report path escapes configured root: ${resolvedCandidate}`);
  }
  return resolvedCandidate;
}
