import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { ensureHermsecAppData, getAppDataLayout } from "../storage/appData.js";
import { ensureDirectory, writeJsonFileAtomic } from "../storage/jsonStore.js";
import { redactSecretText } from "../storage/secretsPolicy.js";
import type { ScheduleStatus, ScanScope } from "./types.js";

export type RunLog = {
  schemaVersion: 1;
  runId: string;
  scheduleId?: string;
  workspaceId: string;
  trigger: "schedule" | "watch" | "manual-run";
  startedAt: string;
  endedAt?: string;
  status: ScheduleStatus;
  skipReason?: string;
  baselineBefore?: object;
  baselineAfter?: object;
  changedFiles: string[];
  classifications: string[];
  scanScope: ScanScope;
  scannerStatuses: Record<string, string>;
  reportPaths: string[];
  queuedTasks: string[];
  errors: { code: string; message: string }[];
};

export type RunEvent = {
  at: string;
  level: "info" | "warn" | "error";
  message: string;
  data?: unknown;
};

function runDirectory(runId: string): string {
  return path.join(getAppDataLayout().runsDir, runId);
}

function runPath(runId: string): string {
  return path.join(runDirectory(runId), "run.json");
}

function eventsPath(runId: string): string {
  return path.join(runDirectory(runId), "events.jsonl");
}

export async function createRunLog(input: {
  scheduleId?: string;
  workspaceId: string;
  trigger: RunLog["trigger"];
  scanScope: ScanScope;
  changedFiles?: string[];
  classifications?: string[];
  baselineBefore?: object;
}): Promise<RunLog> {
  await ensureHermsecAppData();
  const runId = `run-${crypto.randomUUID()}`;
  const log: RunLog = {
    schemaVersion: 1,
    runId,
    ...(input.scheduleId ? { scheduleId: input.scheduleId } : {}),
    workspaceId: input.workspaceId,
    trigger: input.trigger,
    startedAt: new Date().toISOString(),
    status: "partial",
    ...(input.baselineBefore ? { baselineBefore: input.baselineBefore } : {}),
    changedFiles: input.changedFiles ?? [],
    classifications: input.classifications ?? [],
    scanScope: input.scanScope,
    scannerStatuses: {},
    reportPaths: [],
    queuedTasks: [],
    errors: [],
  };
  await ensureDirectory(runDirectory(runId));
  await writeJsonFileAtomic(runPath(runId), log);
  return log;
}

export async function saveRunLog(log: RunLog): Promise<RunLog> {
  await ensureDirectory(runDirectory(log.runId));
  await writeJsonFileAtomic(runPath(log.runId), log);
  return log;
}

export async function finishRunLog(
  log: RunLog,
  status: ScheduleStatus,
  updates: Partial<Omit<RunLog, "schemaVersion" | "runId" | "workspaceId" | "trigger" | "startedAt">> = {},
): Promise<RunLog> {
  return saveRunLog({
    ...log,
    ...updates,
    status,
    endedAt: updates.endedAt ?? new Date().toISOString(),
  });
}

export async function appendRunEvent(runId: string, event: Omit<RunEvent, "at"> & { at?: string }): Promise<void> {
  await ensureDirectory(runDirectory(runId));
  const payload: RunEvent = {
    at: event.at ?? new Date().toISOString(),
    level: event.level,
    message: redactSecretText(event.message),
    ...(event.data === undefined ? {} : { data: event.data }),
  };
  await fs.appendFile(eventsPath(runId), `${JSON.stringify(payload)}\n`, "utf8");
}
