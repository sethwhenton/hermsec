import type { Finding } from "../shared/types.js";
import type { DeltaReport } from "./schema.js";

const severityWeight: Record<Finding["severity"], number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4
};

export function buildDeltaReport(
  currentScanId: string,
  currentFindings: readonly Finding[],
  previous?: { scanId: string; findings: readonly Finding[] }
): DeltaReport {
  if (!previous) {
    return {
      currentScanId,
      newFindingIds: sortIds(currentFindings.map((finding) => finding.id)),
      fixedFindingIds: [],
      unchangedFindingIds: [],
      worsenedFindingIds: [],
      improvedFindingIds: [],
      summaryText: `${currentFindings.length} finding(s) in the first indexed scan.`
    };
  }

  const currentByKey = byStableKey(currentFindings);
  const previousByKey = byStableKey(previous.findings);
  const newFindingIds: string[] = [];
  const fixedFindingIds: string[] = [];
  const unchangedFindingIds: string[] = [];
  const worsenedFindingIds: string[] = [];
  const improvedFindingIds: string[] = [];

  for (const [key, current] of currentByKey) {
    const old = previousByKey.get(key);
    if (!old) {
      newFindingIds.push(current.id);
      continue;
    }
    const oldWeight = severityWeight[old.severity];
    const currentWeight = severityWeight[current.severity];
    if (currentWeight > oldWeight) {
      worsenedFindingIds.push(current.id);
    } else if (currentWeight < oldWeight) {
      improvedFindingIds.push(current.id);
    } else {
      unchangedFindingIds.push(current.id);
    }
  }

  for (const [key, old] of previousByKey) {
    if (!currentByKey.has(key)) {
      fixedFindingIds.push(old.id);
    }
  }

  return {
    baseScanId: previous.scanId,
    currentScanId,
    newFindingIds: sortIds(newFindingIds),
    fixedFindingIds: sortIds(fixedFindingIds),
    unchangedFindingIds: sortIds(unchangedFindingIds),
    worsenedFindingIds: sortIds(worsenedFindingIds),
    improvedFindingIds: sortIds(improvedFindingIds),
    summaryText: [
      `${newFindingIds.length} new`,
      `${fixedFindingIds.length} fixed`,
      `${unchangedFindingIds.length} unchanged`,
      `${worsenedFindingIds.length} worsened`,
      `${improvedFindingIds.length} improved`
    ].join(", ")
  };
}

function byStableKey(findings: readonly Finding[]): Map<string, Finding> {
  const result = new Map<string, Finding>();
  for (const finding of findings) {
    result.set(finding.fingerprint || finding.id, finding);
  }
  return result;
}

function sortIds(ids: string[]): string[] {
  return [...ids].sort((left, right) => left.localeCompare(right));
}
