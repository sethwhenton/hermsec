import fs from "node:fs/promises";
import { classifyChangedFiles } from "./changeClassifier.js";
import { loadBaseline } from "./baselines.js";
import { detectGitChanges } from "./gitState.js";
import { computeNextRunAt, updateSchedule } from "./schedules.js";
import type { ChangeClassification, GitChangeDetection, ScheduleRecord, ScheduleRunDecision } from "./types.js";

export type EvaluateScheduleOptions = {
  now?: Date;
  missedRunGraceMs?: number;
  allowFullScanWhenNotGit?: boolean;
};

async function pathExists(targetPath: string): Promise<boolean> {
  try {
    await fs.access(targetPath);
    return true;
  } catch {
    return false;
  }
}

function isDue(schedule: ScheduleRecord, now: Date, graceMs: number): { due: boolean; reason?: string } {
  if (!schedule.nextRunAt) {
    return { due: true };
  }
  const dueAt = Date.parse(schedule.nextRunAt);
  if (Number.isNaN(dueAt)) {
    return { due: true };
  }
  if (dueAt > now.getTime()) {
    return { due: false, reason: `next run is scheduled for ${schedule.nextRunAt}` };
  }
  if (now.getTime() - dueAt > graceMs) {
    return { due: false, reason: "missed run is outside the grace window" };
  }
  return { due: true };
}

function decisionFromGit(
  schedule: ScheduleRecord,
  git: GitChangeDetection,
  classification?: ChangeClassification,
): ScheduleRunDecision {
  if (git.kind === "unchanged") {
    return {
      scheduleId: schedule.id,
      workspaceId: schedule.workspaceId,
      shouldRun: false,
      status: "skipped",
      reason: git.reason,
      mode: schedule.mode,
      scanScope: "none",
      targetPath: schedule.targetPath,
      ...(schedule.nextRunAt ? { dueAt: schedule.nextRunAt } : {}),
      git,
      ...(classification ? { classification } : {}),
    };
  }

  const scanScope = schedule.scanDepth === "full"
    ? "full"
    : schedule.scanDepth === "changed-files"
      ? "changed-files"
      : classification?.scanScope ?? "full";

  return {
    scheduleId: schedule.id,
    workspaceId: schedule.workspaceId,
    shouldRun: scanScope !== "none",
    status: scanScope === "none" ? "skipped" : "due",
    reason: scanScope === "none" ? "only ignored or docs-only changes were detected" : git.reason,
    mode: schedule.mode,
    scanScope,
    targetPath: schedule.targetPath,
    ...(schedule.nextRunAt ? { dueAt: schedule.nextRunAt } : {}),
    git,
    ...(classification ? { classification } : {}),
  };
}

export async function evaluateScheduleRun(
  schedule: ScheduleRecord,
  options: EvaluateScheduleOptions = {},
): Promise<ScheduleRunDecision> {
  const now = options.now ?? new Date();
  const graceMs = options.missedRunGraceMs ?? 2 * 60 * 60 * 1000;

  if (!schedule.enabled) {
    return {
      scheduleId: schedule.id,
      workspaceId: schedule.workspaceId,
      shouldRun: false,
      status: "blocked",
      reason: schedule.disabledReason ?? "schedule is disabled",
      mode: schedule.mode,
      scanScope: "none",
      targetPath: schedule.targetPath,
    };
  }

  const due = isDue(schedule, now, graceMs);
  if (!due.due) {
    return {
      scheduleId: schedule.id,
      workspaceId: schedule.workspaceId,
      shouldRun: false,
      status: "not-due",
      reason: due.reason ?? "schedule is not due",
      mode: schedule.mode,
      scanScope: "none",
      targetPath: schedule.targetPath,
      ...(schedule.nextRunAt ? { dueAt: schedule.nextRunAt } : {}),
    };
  }

  if (!(await pathExists(schedule.targetPath))) {
    return {
      scheduleId: schedule.id,
      workspaceId: schedule.workspaceId,
      shouldRun: false,
      status: "blocked",
      reason: "workspace target path does not exist",
      mode: schedule.mode,
      scanScope: "none",
      targetPath: schedule.targetPath,
    };
  }

  if (schedule.changePolicy === "scan-always") {
    return {
      scheduleId: schedule.id,
      workspaceId: schedule.workspaceId,
      shouldRun: true,
      status: "due",
      reason: "schedule policy is scan-always",
      mode: schedule.mode,
      scanScope: schedule.scanDepth === "changed-files" ? "changed-files" : "full",
      targetPath: schedule.targetPath,
      ...(schedule.nextRunAt ? { dueAt: schedule.nextRunAt } : {}),
    };
  }

  const baseline = await loadBaseline(schedule.workspaceId);
  const git = await detectGitChanges(schedule.targetPath, baseline);
  if (git.kind === "not-git" || git.kind === "git-error") {
    const allowFullScan = options.allowFullScanWhenNotGit ?? true;
    return {
      scheduleId: schedule.id,
      workspaceId: schedule.workspaceId,
      shouldRun: allowFullScan,
      status: allowFullScan ? "due" : "blocked",
      reason: allowFullScan
        ? `${git.reason}; falling back to a full scan decision`
        : git.reason,
      mode: schedule.mode,
      scanScope: allowFullScan ? "full" : "none",
      targetPath: schedule.targetPath,
      ...(schedule.nextRunAt ? { dueAt: schedule.nextRunAt } : {}),
      git,
    };
  }

  const classification = classifyChangedFiles(git.changedFiles);
  return decisionFromGit(schedule, git, classification);
}

export async function recordScheduleDecision(
  schedule: ScheduleRecord,
  status: "success" | "partial" | "skipped" | "failed" | "blocked",
  now = new Date(),
  disabledReason?: string,
): Promise<ScheduleRecord> {
  return updateSchedule(schedule.id, (current) => ({
    ...current,
    enabled: status === "blocked" ? false : current.enabled,
    ...(disabledReason ? { disabledReason } : {}),
    lastRunAt: now.toISOString(),
    lastStatus: status,
    nextRunAt: computeNextRunAt(current, now),
  }));
}
