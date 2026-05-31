import type { Finding, ScanRun } from "../shared/types.js";

export type FindingExplanation = {
  findingId: string;
  summary: string;
  nextStep: string;
};

export function explainFinding(finding: Finding): FindingExplanation {
  const where = finding.location
    ? `${finding.location.file}${finding.location.startLine ? `:${finding.location.startLine}` : ""}`
    : finding.package
      ? `${finding.package.ecosystem}:${finding.package.name}`
      : "the scanned project";
  return {
    findingId: finding.id,
    summary: `${finding.severity.toUpperCase()}: ${finding.title} in ${where}. ${finding.description}`,
    nextStep: finding.remediation,
  };
}

export function summarizeRun(run: ScanRun): string {
  const parts = [
    `${run.summary.total} findings`,
    `${run.summary.critical} critical`,
    `${run.summary.high} high`,
    `${run.summary.medium} medium`,
  ];
  const top = run.findings.slice(0, 3).map((finding) => `- ${finding.severity}: ${finding.title}`).join("\n");
  return [`Hermsec completed scan ${run.id} with ${parts.join(", ")}.`, top].filter(Boolean).join("\n");
}
