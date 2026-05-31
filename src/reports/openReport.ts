import path from "node:path";
import { findReportIndexEntry } from "./reportIndex.js";
import type { ReportFormat, ReportIndexEntry } from "./schema.js";

export type ReportOpenTarget = {
  scanId: string;
  path: string;
  missing: boolean;
  kind: "html" | "markdown" | "summary" | "directory";
};

export async function getReportOpenTarget(
  scanId: string,
  kind: ReportFormat | "directory" = "html",
  indexPath?: string
): Promise<ReportOpenTarget | undefined> {
  const entry = await findReportIndexEntry(scanId, indexPath);
  if (!entry) {
    return undefined;
  }
  return targetFromEntry(entry, kind);
}

export function targetFromEntry(entry: ReportIndexEntry, kind: ReportFormat | "directory"): ReportOpenTarget {
  const selectedPath =
    kind === "html"
      ? entry.htmlPath
      : kind === "markdown"
        ? entry.markdownPath
        : kind === "json"
          ? entry.summaryPath
          : entry.reportDir;
  return {
    scanId: entry.scanId,
    path: path.resolve(selectedPath),
    missing: entry.missing ?? false,
    kind: kind === "json" ? "summary" : kind
  };
}
