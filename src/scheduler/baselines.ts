import path from "node:path";
import { ensureHermsecAppData, getAppDataLayout } from "../storage/appData.js";
import {
  JsonStore,
  optionalString,
  requireRecord,
  requireString,
} from "../storage/jsonStore.js";
import type { BaselineRecord } from "./types.js";

function baselinePath(workspaceId: string): string {
  return path.join(getAppDataLayout().baselinesDir, `${workspaceId}.json`);
}

export function validateBaselineRecord(value: unknown): BaselineRecord {
  const record = requireRecord(value, "baseline");
  if (record.schemaVersion !== 1) {
    throw new Error("baseline.schemaVersion must be 1");
  }
  const branch = optionalString(record.branch, "baseline.branch");
  const headCommit = optionalString(record.headCommit, "baseline.headCommit");
  const lastSuccessfulScanId = optionalString(record.lastSuccessfulScanId, "baseline.lastSuccessfulScanId");
  const workingTreeFingerprint = optionalString(record.workingTreeFingerprint, "baseline.workingTreeFingerprint");
  return {
    schemaVersion: 1,
    workspaceId: requireString(record.workspaceId, "baseline.workspaceId"),
    repoRoot: requireString(record.repoRoot, "baseline.repoRoot"),
    ...(branch ? { branch } : {}),
    ...(headCommit ? { headCommit } : {}),
    ...(lastSuccessfulScanId ? { lastSuccessfulScanId } : {}),
    ...(workingTreeFingerprint ? { workingTreeFingerprint } : {}),
    scannedAt: requireString(record.scannedAt, "baseline.scannedAt"),
  };
}

export async function loadBaseline(workspaceId: string): Promise<BaselineRecord | undefined> {
  await ensureHermsecAppData();
  const fallback: BaselineRecord = {
    schemaVersion: 1,
    workspaceId,
    repoRoot: "",
    scannedAt: new Date(0).toISOString(),
  };
  const result = await new JsonStore(baselinePath(workspaceId), fallback, validateBaselineRecord).loadResult();
  if (!result.ok) {
    throw new Error(`${result.errorCode} reading ${result.path}: ${result.message}`);
  }
  return result.existed ? result.value : undefined;
}

export async function saveBaseline(record: BaselineRecord): Promise<BaselineRecord> {
  await ensureHermsecAppData();
  return new JsonStore(baselinePath(record.workspaceId), record, validateBaselineRecord).save(record);
}
