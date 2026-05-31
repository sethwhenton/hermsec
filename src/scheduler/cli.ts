import { runScan } from "../core/harness.js";
import type { CommandResult, ScanMode } from "../shared/types.js";
import {
  addSchedule as addScheduleRecord,
  getSchedule,
  listSchedules as listScheduleRecords,
  removeSchedule as removeScheduleRecord,
} from "./schedules.js";

export async function addSchedule(options: {
  cwd: string;
  target: string;
  dailyTime: string;
  mode: ScanMode;
}): Promise<CommandResult> {
  const schedule = await addScheduleRecord({
    workspaceId: "local",
    targetPath: options.target,
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

export async function runSchedule(options: { cwd: string; scheduleId: string }): Promise<CommandResult> {
  const schedule = await getSchedule(options.scheduleId);
  if (!schedule) {
    return {
      ok: false,
      errorCode: "SCHEDULE_NOT_FOUND",
      message: `Schedule not found: ${options.scheduleId}`,
    };
  }
  return runScan({
    cwd: options.cwd,
    target: schedule.targetPath,
    mode: schedule.mode,
    formats: ["json", "md", "html"],
    useModel: false,
  });
}
