import crypto from "node:crypto";
import path from "node:path";
import { ensureHermsecAppData, getAppDataLayout } from "./appData.js";
import {
  JsonStore,
  optionalString,
  requireRecord,
  requireString,
} from "./jsonStore.js";
import { workspaceSlug, type WorkspaceProfile } from "./workspaceStore.js";
import { ensureDirectory } from "./jsonStore.js";

export type LocalReportRecord = {
  schemaVersion: 1;
  id: string;
  workspaceId: string;
  scanId: string;
  reportDir: string;
  createdAt: string;
  summaryPath?: string;
  findingsPath?: string;
  evidencePath?: string;
  markdownPath?: string;
  htmlPath?: string;
  jsonPath?: string;
  summary?: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
};

export type ReportIndexFile = {
  schemaVersion: 1;
  reports: LocalReportRecord[];
};

export type ReportArtifactPaths = {
  reportDir: string;
  summaryPath: string;
  findingsPath: string;
  evidencePath: string;
  markdownPath: string;
  htmlPath: string;
  jsonPath: string;
};

function defaultReportIndex(): ReportIndexFile {
  return {
    schemaVersion: 1,
    reports: [],
  };
}

function optionalPath(value: unknown, label: string): string | undefined {
  const text = optionalString(value, label);
  return text ? path.resolve(text) : undefined;
}

export function validateLocalReportRecord(value: unknown): LocalReportRecord {
  const record = requireRecord(value, "report");
  if (record.schemaVersion !== 1) {
    throw new Error("report.schemaVersion must be 1");
  }
  const summaryRaw = record.summary;
  let summary: LocalReportRecord["summary"];
  if (summaryRaw !== undefined) {
    const summaryRecord = requireRecord(summaryRaw, "report.summary");
    summary = {
      total: Number(summaryRecord.total ?? 0),
      critical: Number(summaryRecord.critical ?? 0),
      high: Number(summaryRecord.high ?? 0),
      medium: Number(summaryRecord.medium ?? 0),
      low: Number(summaryRecord.low ?? 0),
      info: Number(summaryRecord.info ?? 0),
    };
  }
  const summaryPath = optionalPath(record.summaryPath, "report.summaryPath");
  const findingsPath = optionalPath(record.findingsPath, "report.findingsPath");
  const evidencePath = optionalPath(record.evidencePath, "report.evidencePath");
  const markdownPath = optionalPath(record.markdownPath, "report.markdownPath");
  const htmlPath = optionalPath(record.htmlPath, "report.htmlPath");
  const jsonPath = optionalPath(record.jsonPath, "report.jsonPath");
  return {
    schemaVersion: 1,
    id: requireString(record.id, "report.id"),
    workspaceId: requireString(record.workspaceId, "report.workspaceId"),
    scanId: requireString(record.scanId, "report.scanId"),
    reportDir: path.resolve(requireString(record.reportDir, "report.reportDir")),
    createdAt: requireString(record.createdAt, "report.createdAt"),
    ...(summaryPath ? { summaryPath } : {}),
    ...(findingsPath ? { findingsPath } : {}),
    ...(evidencePath ? { evidencePath } : {}),
    ...(markdownPath ? { markdownPath } : {}),
    ...(htmlPath ? { htmlPath } : {}),
    ...(jsonPath ? { jsonPath } : {}),
    ...(summary ? { summary } : {}),
  };
}

export function validateReportIndex(value: unknown): ReportIndexFile {
  const record = requireRecord(value, "report index");
  if (record.schemaVersion !== 1) {
    throw new Error("reportIndex.schemaVersion must be 1");
  }
  if (!Array.isArray(record.reports)) {
    throw new Error("reportIndex.reports must be an array");
  }
  return {
    schemaVersion: 1,
    reports: record.reports.map(validateLocalReportRecord),
  };
}

function reportStore(): JsonStore<ReportIndexFile> {
  const layout = getAppDataLayout();
  return new JsonStore(layout.reportIndexFile, defaultReportIndex(), validateReportIndex);
}

export async function allocateReportDirectory(
  workspace: WorkspaceProfile,
  scanId = `scan-${crypto.randomUUID()}`,
  reportRoot?: string,
): Promise<ReportArtifactPaths> {
  const layout = await ensureHermsecAppData();
  const root = path.resolve(reportRoot ?? workspace.reportDir ?? layout.reportsDir);
  const reportDir = path.join(root, scanId);
  await ensureDirectory(reportDir);
  return {
    reportDir,
    summaryPath: path.join(reportDir, "summary.json"),
    findingsPath: path.join(reportDir, "findings.json"),
    evidencePath: path.join(reportDir, "evidence.json"),
    markdownPath: path.join(reportDir, "report.md"),
    htmlPath: path.join(reportDir, "report.html"),
    jsonPath: path.join(reportDir, "report.json"),
  };
}

export function appDataReportRootForWorkspace(workspace: WorkspaceProfile): string {
  return path.join(getAppDataLayout().reportsDir, workspaceSlug(workspace.displayName, workspace.id));
}

export async function addReportRecord(record: Omit<LocalReportRecord, "schemaVersion" | "id" | "createdAt"> & {
  id?: string;
  createdAt?: string;
}): Promise<LocalReportRecord> {
  await ensureHermsecAppData();
  const fullRecord: LocalReportRecord = validateLocalReportRecord({
    schemaVersion: 1,
    id: record.id ?? `rep-${crypto.randomUUID()}`,
    createdAt: record.createdAt ?? new Date().toISOString(),
    ...record,
  });
  const saved = await reportStore().update((index) => ({
    schemaVersion: 1,
    reports: [
      fullRecord,
      ...index.reports.filter((item) => item.id !== fullRecord.id && item.scanId !== fullRecord.scanId),
    ],
  }));
  const result = saved.reports.find((item) => item.id === fullRecord.id);
  if (!result) {
    throw new Error(`Report ${fullRecord.id} was not indexed`);
  }
  return result;
}

export async function listReportRecords(workspaceId?: string): Promise<LocalReportRecord[]> {
  await ensureHermsecAppData();
  const index = await reportStore().load();
  return index.reports
    .filter((record) => !workspaceId || record.workspaceId === workspaceId)
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

export async function latestReportRecord(workspaceId?: string): Promise<LocalReportRecord | undefined> {
  return (await listReportRecords(workspaceId))[0];
}
