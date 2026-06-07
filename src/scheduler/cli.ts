import path from "node:path";
import { runScan } from "../core/harness.js";
import { stableId } from "../shared/text.js";
import type { CommandResult, ScanMode } from "../shared/types.js";
import { loadUserConfig } from "../storage/userConfig.js";
import { saveBaseline } from "./baselines.js";
import { readGitState } from "./gitState.js";
import { evaluateScheduleRun, recordScheduleDecision } from "./runner.js";
import {
  addSchedule as addScheduleRecord,
  computeNextRunAt,
  getSchedule,
  listSchedules as listScheduleRecords,
  removeSchedule as removeScheduleRecord,
  updateSchedule as updateScheduleRecord,
} from "./schedules.js";

export async function addSchedule(options: {
  cwd: string;
  target: string;
  dailyTime: string;
  mode: ScanMode;
}): Promise<CommandResult> {
  const targetPath = path.resolve(options.cwd, options.target);
  const schedule = await addScheduleRecord({
    workspaceId: stableId(targetPath, "ws"),
    targetPath,
    time: options.dailyTime,
    mode: options.mode,
  });
  return {
    ok: true,
    message: `Schedule added: ${schedule.id} at ${schedule.time ?? schedule.cron}`,
    data: { schedule },
  };
}

export async function listSchedules(): Promise<CommandResult> {
  const schedules = await listScheduleRecords();
  return {
    ok: true,
    message: schedules.length
      ? schedules.map((schedule) => `${schedule.id}\t${schedule.time ?? schedule.cron}\t${schedule.mode}\t${schedule.targetPath}`).join("\n")
      : "No schedules configured.",
    data: { schedules },
  };
}

export async function removeSchedule(options: { cwd: string; scheduleId: string }): Promise<CommandResult> {
  const removed = await removeScheduleRecord(options.scheduleId);
  return {
    ok: true,
    message: removed ? "Schedule removed." : "Schedule not found.",
    data: { removed },
  };
}

export async function updateSchedule(options: {
  cwd: string;
  scheduleId: string;
  target?: string;
  dailyTime?: string;
  mode?: ScanMode;
  enabled?: boolean;
}): Promise<CommandResult> {
  const schedule = await updateScheduleRecord(options.scheduleId, (current) => {
    const next = { ...current };
    if (options.target) {
      const targetPath = path.resolve(options.cwd, options.target);
      next.targetPath = targetPath;
      next.workspaceId = stableId(targetPath, "ws");
    }
    if (options.dailyTime) {
      next.trigger = "daily";
      next.time = options.dailyTime;
      delete next.cron;
    }
    if (options.mode) {
      next.mode = options.mode;
    }
    if (options.enabled !== undefined) {
      next.enabled = options.enabled;
      if (options.enabled) {
        delete next.disabledReason;
      } else {
        next.disabledReason = "Disabled by user.";
      }
    }
    next.nextRunAt = computeNextRunAt(next);
    return next;
  });
  return {
    ok: true,
    message: `Schedule updated: ${schedule.id}`,
    data: { schedule },
  };
}

export async function setScheduleEnabled(options: {
  cwd: string;
  scheduleId: string;
  enabled: boolean;
}): Promise<CommandResult> {
  return updateSchedule({
    cwd: options.cwd,
    scheduleId: options.scheduleId,
    enabled: options.enabled,
  });
}

export async function runSchedule(options: {
  cwd: string;
  scheduleId: string;
  force?: boolean;
}): Promise<CommandResult> {
  const schedule = await getSchedule(options.scheduleId);
  if (!schedule) {
    return {
      ok: false,
      errorCode: "SCHEDULE_NOT_FOUND",
      message: `Schedule not found: ${options.scheduleId}`,
    };
  }

  const decision = options.force
    ? undefined
    : await evaluateScheduleRun(schedule, { allowFullScanWhenNotGit: true });
  if (decision && !decision.shouldRun) {
    await recordScheduleDecision(
      schedule,
      decision.status === "blocked" ? "blocked" : "skipped",
      new Date(),
      decision.status === "blocked" ? decision.reason : undefined,
    );
    return {
      ok: true,
      message: `Schedule skipped: ${decision.reason}`,
      data: { schedule, decision },
    };
  }

  try {
    const outputDirectory = await configuredScheduleReportDirectory();
    const result = await runScan({
      cwd: options.cwd,
      target: schedule.targetPath,
      mode: schedule.mode,
      formats: ["json", "md", "html"],
      useModel: false,
      ...(outputDirectory ? { outputDirectory } : {}),
    });
    if (result.ok) {
      await saveScheduleBaseline(schedule.workspaceId, schedule.targetPath, decision);
      const updatedSchedule = await recordScheduleDecision(schedule, "success");
      return {
        ok: true,
        message: result.message,
        data: {
          ...(result.data && typeof result.data === "object" ? result.data : {}),
          schedule: updatedSchedule,
          ...(decision ? { decision } : {}),
        },
      };
    }
    await recordScheduleDecision(schedule, "failed");
    return result;
  } catch (error) {
    await recordScheduleDecision(schedule, "failed");
    throw error;
  }
}

async function configuredScheduleReportDirectory(): Promise<string | undefined> {
  const config = await loadUserConfig();
  return config.defaultReportLocation === "custom" ? config.customReportDir : undefined;
}

async function saveScheduleBaseline(
  workspaceId: string,
  targetPath: string,
  decision: Awaited<ReturnType<typeof evaluateScheduleRun>> | undefined,
): Promise<void> {
  const state =
    decision?.git && "state" in decision.git
      ? decision.git.state
      : await readGitState(targetPath).catch(() => undefined);
  if (!state) {
    return;
  }
  await saveBaseline({
    schemaVersion: 1,
    workspaceId,
    repoRoot: state.repoRoot,
    ...(state.branch ? { branch: state.branch } : {}),
    ...(state.headCommit ? { headCommit: state.headCommit } : {}),
    workingTreeFingerprint: state.workingTreeFingerprint,
    scannedAt: new Date().toISOString(),
  });
}
