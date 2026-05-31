import fs from "node:fs/promises";
import path from "node:path";
import { appDataDir } from "../shared/paths.js";
import { stableStringify } from "./jsonRenderer.js";
import type { ReportIndexEntry } from "./schema.js";

export type ReportIndex = {
  schemaVersion: "1.0";
  updatedAt: string;
  entries: ReportIndexEntry[];
};

export function defaultReportIndexPath(): string {
  return path.join(appDataDir(), "reports-index.json");
}

export async function readReportIndex(indexPath = defaultReportIndexPath()): Promise<ReportIndex> {
  try {
    const raw = await fs.readFile(indexPath, "utf8");
    const parsed = JSON.parse(raw) as ReportIndex;
    return {
      schemaVersion: "1.0",
      updatedAt: parsed.updatedAt ?? new Date(0).toISOString(),
      entries: Array.isArray(parsed.entries) ? parsed.entries : []
    };
  } catch (error) {
    if (isMissingFile(error)) {
      return { schemaVersion: "1.0", updatedAt: new Date(0).toISOString(), entries: [] };
    }
    throw error;
  }
}

export async function writeReportIndex(index: ReportIndex, indexPath = defaultReportIndexPath()): Promise<void> {
  await fs.mkdir(path.dirname(indexPath), { recursive: true });
  const tmp = `${indexPath}.${process.pid}.tmp`;
  await fs.writeFile(tmp, stableStringify(index), "utf8");
  await fs.rename(tmp, indexPath);
}

export async function appendReportIndexEntry(
  entry: ReportIndexEntry,
  indexPath = defaultReportIndexPath()
): Promise<ReportIndex> {
  const index = await readReportIndex(indexPath);
  const entries = index.entries.filter((candidate) => candidate.scanId !== entry.scanId);
  entries.push(entry);
  entries.sort((left, right) => right.generatedAt.localeCompare(left.generatedAt) || left.scanId.localeCompare(right.scanId));
  const next: ReportIndex = {
    schemaVersion: "1.0",
    updatedAt: entry.generatedAt,
    entries
  };
  await writeReportIndex(next, indexPath);
  return next;
}

export async function listReportIndexEntries(
  filters: { workspaceId?: string } = {},
  indexPath = defaultReportIndexPath()
): Promise<ReportIndexEntry[]> {
  const index = await readReportIndex(indexPath);
  const entries = filters.workspaceId
    ? index.entries.filter((entry) => entry.workspaceId === filters.workspaceId)
    : index.entries;
  return Promise.all(entries.map(markMissingPaths));
}

export async function findReportIndexEntry(
  scanId: string,
  indexPath = defaultReportIndexPath()
): Promise<ReportIndexEntry | undefined> {
  const entries = await listReportIndexEntries({}, indexPath);
  return entries.find((entry) => entry.scanId === scanId);
}

export async function latestReportForWorkspace(
  workspaceId: string,
  indexPath = defaultReportIndexPath()
): Promise<ReportIndexEntry | undefined> {
  const entries = await listReportIndexEntries({ workspaceId }, indexPath);
  return entries[0];
}

async function markMissingPaths(entry: ReportIndexEntry): Promise<ReportIndexEntry> {
  const exists = await pathExists(entry.htmlPath);
  return { ...entry, missing: !exists };
}

async function pathExists(value: string): Promise<boolean> {
  try {
    await fs.access(value);
    return true;
  } catch {
    return false;
  }
}

function isMissingFile(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT";
}
