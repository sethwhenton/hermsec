import fs from "node:fs/promises";
import path from "node:path";
import type { ReportArtifacts } from "../shared/types.js";
import { ensureDir, readJson, writeJson } from "./jsonStore.js";

export type ReportIndex = {
  schemaVersion: "1.0";
  reports: ReportArtifacts[];
};

export function reportIndexPath(reportDirectory: string): string {
  return path.join(reportDirectory, "index.json");
}

export async function loadReportIndex(reportDirectory: string): Promise<ReportIndex> {
  return readJson<ReportIndex>(reportIndexPath(reportDirectory), {
    schemaVersion: "1.0",
    reports: [],
  });
}

export async function addReportToIndex(reportDirectory: string, artifact: ReportArtifacts): Promise<void> {
  await ensureDir(reportDirectory);
  const index = await loadReportIndex(reportDirectory);
  index.reports = [artifact, ...index.reports.filter((item) => item.runId !== artifact.runId)].slice(0, 100);
  await writeJson(reportIndexPath(reportDirectory), index);
}

export async function listReportArtifacts(reportDirectory: string): Promise<ReportArtifacts[]> {
  const index = await loadReportIndex(reportDirectory);
  const checked: ReportArtifacts[] = [];
  for (const report of index.reports) {
    try {
      await fs.access(report.directory);
      checked.push(report);
    } catch {
      // Ignore missing report directories in the listing without mutating user files.
    }
  }
  return checked;
}
