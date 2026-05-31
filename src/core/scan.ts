import path from "node:path";
import { scannerAvailabilityStatuses } from "./doctor.js";
import { assertDirectory, readTextFile, walkSourceTree } from "./files.js";
import { discoverRepositoryMetadata, repositoryDiscoveryMessage } from "./repository.js";
import { runOfflineHeuristicScanners } from "../scanners/heuristics.js";
import { normalizeTargetPath } from "../shared/paths.js";
import { stableId } from "../shared/text.js";
import type { Finding, ScanMode, ScannerStatus, ScanRun, ScanSummary } from "../shared/types.js";

export type ScanOptions = {
  target: string;
  mode?: ScanMode;
};

export async function runScan(options: ScanOptions): Promise<ScanRun> {
  const started = Date.now();
  const startedAt = new Date(started).toISOString();
  const target = validateLocalTarget(options.target);
  await assertDirectory(target);
  const mode = options.mode ?? "offline";

  const walk = await walkSourceTree(target);
  const repository = await discoverRepositoryMetadata(target, walk.files, walk.ignoredDirectories);
  const scannerStatuses: ScannerStatus[] = [
    {
      id: "repository-discovery",
      label: "Repository discovery",
      status: "completed",
      message: repositoryDiscoveryMessage(repository, walk.files.length, walk.truncated),
    },
    ...scannerAvailabilityStatuses(),
  ];

  const offlineResults = await runOfflineHeuristicScanners(walk.files, readTextFile);
  scannerStatuses.push(...offlineResults.statuses);

  const finished = Date.now();
  const uniqueFindings = dedupeFindings(offlineResults.findings);
  const run: ScanRun = {
    schemaVersion: "1.0",
    id: stableId(`${target}:${startedAt}`, "scan"),
    target,
    mode,
    startedAt,
    finishedAt: new Date(finished).toISOString(),
    durationMs: finished - started,
    scannerStatuses,
    findings: uniqueFindings,
    summary: summarize(uniqueFindings),
  };
  if (Object.keys(repository.git).length > 0) {
    run.git = repository.git;
  }
  return run;
}

export function summarize(findings: Finding[]): ScanSummary {
  const summary: ScanSummary = {
    total: findings.length,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const finding of findings) {
    summary[finding.severity] += 1;
  }
  return summary;
}

function validateLocalTarget(input: string): string {
  const trimmed = input.trim();
  if (!trimmed) {
    throw new Error("A local scan target is required.");
  }
  if (isRemoteTarget(trimmed)) {
    throw new Error("This scan harness accepts local directories only. Clone remote repositories locally before scanning.");
  }
  return normalizeTargetPath(trimmed);
}

function isRemoteTarget(input: string): boolean {
  if (/^git@github\.com:/i.test(input)) {
    return true;
  }
  try {
    const url = new URL(input);
    return url.protocol === "http:" || url.protocol === "https:" || url.protocol === "ssh:" || url.protocol === "git:";
  } catch {
    return false;
  }
}

function dedupeFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const result: Finding[] = [];
  for (const finding of findings.sort(compareFindings)) {
    if (!seen.has(finding.fingerprint)) {
      seen.add(finding.fingerprint);
      result.push(finding);
    }
  }
  return result;
}

function compareFindings(a: Finding, b: Finding): number {
  const severityRank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  return (
    severityRank[a.severity] - severityRank[b.severity] ||
    (a.location?.file ?? "").localeCompare(b.location?.file ?? "") ||
    (a.location?.startLine ?? 0) - (b.location?.startLine ?? 0) ||
    a.title.localeCompare(b.title)
  );
}

export function targetDisplayName(target: string): string {
  return path.basename(target) || target;
}
