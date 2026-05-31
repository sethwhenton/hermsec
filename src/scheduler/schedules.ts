import crypto from "node:crypto";
import path from "node:path";
import { ensureHermsecAppData, getAppDataLayout } from "../storage/appData.js";
import {
  JsonStore,
  optionalString,
  requireBoolean,
  requireEnum,
  requireRecord,
  requireString,
} from "../storage/jsonStore.js";
import {
  changePolicies,
  scanDepths,
  scheduleModes,
  scheduleStatuses,
  scheduleTriggers,
  type ScheduleRecord,
  type SchedulesFile,
} from "./types.js";

export type AddScheduleInput = {
  workspaceId: string;
  targetPath: string;
  trigger?: ScheduleRecord["trigger"];
  time?: string;
  cron?: string;
  timezone?: string;
  mode?: ScheduleRecord["mode"];
  changePolicy?: ScheduleRecord["changePolicy"];
  scanDepth?: ScheduleRecord["scanDepth"];
  enabled?: boolean;
  now?: Date;
};

function defaultSchedulesFile(): SchedulesFile {
  return {
    schemaVersion: 1,
    schedules: [],
  };
}

function validateTime(value: string, label: string): string {
  if (!/^\d{2}:\d{2}$/.test(value)) {
    throw new Error(`${label} must be HH:mm`);
  }
  const [hourText, minuteText] = value.split(":");
  const hour = Number(hourText);
  const minute = Number(minuteText);
  if (hour < 0 || hour > 23 || minute < 0 || minute > 59) {
    throw new Error(`${label} must be a valid HH:mm time`);
  }
  return value;
}

export function validateScheduleRecord(value: unknown): ScheduleRecord {
  const record = requireRecord(value, "schedule");
  if (record.schemaVersion !== 1) {
    throw new Error("schedule.schemaVersion must be 1");
  }
  const trigger = requireEnum(record.trigger, "schedule.trigger", scheduleTriggers);
  const time = optionalString(record.time, "schedule.time");
  const cron = optionalString(record.cron, "schedule.cron");
  const nextRunAt = optionalString(record.nextRunAt, "schedule.nextRunAt");
  const lastRunAt = optionalString(record.lastRunAt, "schedule.lastRunAt");
  const disabledReason = optionalString(record.disabledReason, "schedule.disabledReason");
  const lastStatus = record.lastStatus === undefined
    ? undefined
    : requireEnum(record.lastStatus, "schedule.lastStatus", scheduleStatuses);

  return {
    schemaVersion: 1,
    id: requireString(record.id, "schedule.id"),
    workspaceId: requireString(record.workspaceId, "schedule.workspaceId"),
    targetPath: path.resolve(requireString(record.targetPath, "schedule.targetPath")),
    enabled: requireBoolean(record.enabled, "schedule.enabled"),
    trigger,
    ...(time ? { time: validateTime(time, "schedule.time") } : {}),
    ...(cron ? { cron } : {}),
    timezone: requireString(record.timezone, "schedule.timezone"),
    mode: requireEnum(record.mode, "schedule.mode", scheduleModes),
    changePolicy: requireEnum(record.changePolicy, "schedule.changePolicy", changePolicies),
    scanDepth: requireEnum(record.scanDepth, "schedule.scanDepth", scanDepths),
    ...(nextRunAt ? { nextRunAt } : {}),
    ...(lastRunAt ? { lastRunAt } : {}),
    ...(lastStatus ? { lastStatus } : {}),
    ...(disabledReason ? { disabledReason } : {}),
  };
}

function validateSchedulesFile(value: unknown): SchedulesFile {
  const record = requireRecord(value, "schedules");
  if (record.schemaVersion !== 1) {
    throw new Error("schedules.schemaVersion must be 1");
  }
  if (!Array.isArray(record.schedules)) {
    throw new Error("schedules.schedules must be an array");
  }
  return {
    schemaVersion: 1,
    schedules: record.schedules.map(validateScheduleRecord),
  };
}

function scheduleStore(): JsonStore<SchedulesFile> {
  return new JsonStore(getAppDataLayout().schedulesFile, defaultSchedulesFile(), validateSchedulesFile);
}

function zonedParts(date: Date, timeZone: string): {
  year: number;
  month: number;
  day: number;
  hour: number;
  minute: number;
  weekday: number;
} {
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone,
    hour12: false,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    weekday: "short",
  }).formatToParts(date);
  const lookup = new Map(parts.map((part) => [part.type, part.value]));
  const weekdayText = lookup.get("weekday") ?? "Sun";
  const weekday = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"].indexOf(weekdayText);
  return {
    year: Number(lookup.get("year")),
    month: Number(lookup.get("month")),
    day: Number(lookup.get("day")),
    hour: Number(lookup.get("hour")),
    minute: Number(lookup.get("minute")),
    weekday,
  };
}

function cronHourMinute(cron: string): { hour: number; minute: number } {
  const [minuteText, hourText] = cron.trim().split(/\s+/);
  if (minuteText === undefined || hourText === undefined || minuteText === "*" || hourText === "*") {
    throw new Error("Only fixed minute/hour cron schedules are supported in the MVP");
  }
  const minute = Number(minuteText);
  const hour = Number(hourText);
  if (!Number.isInteger(hour) || !Number.isInteger(minute) || hour < 0 || hour > 23 || minute < 0 || minute > 59) {
    throw new Error("Invalid cron minute/hour values");
  }
  return { hour, minute };
}

function targetHourMinute(schedule: Pick<ScheduleRecord, "trigger" | "time" | "cron">): { hour: number; minute: number } {
  if (schedule.trigger === "cron") {
    if (!schedule.cron) {
      throw new Error("Cron schedule requires schedule.cron");
    }
    return cronHourMinute(schedule.cron);
  }
  const time = validateTime(schedule.time ?? "09:00", "schedule.time");
  const [hourText, minuteText] = time.split(":");
  return { hour: Number(hourText), minute: Number(minuteText) };
}

export function computeNextRunAt(schedule: ScheduleRecord, from = new Date()): string {
  const { hour, minute } = targetHourMinute(schedule);
  const startMs = Math.floor(from.getTime() / 60000) * 60000 + 60000;
  for (let offset = 0; offset < 60 * 24 * 8; offset += 1) {
    const candidate = new Date(startMs + offset * 60000);
    const parts = zonedParts(candidate, schedule.timezone);
    const weekdayAllowed = schedule.trigger !== "weekdays" || (parts.weekday >= 1 && parts.weekday <= 5);
    if (weekdayAllowed && parts.hour === hour && parts.minute === minute) {
      return candidate.toISOString();
    }
  }
  throw new Error("Unable to compute next scheduled run within 8 days");
}

export async function addSchedule(input: AddScheduleInput): Promise<ScheduleRecord> {
  const now = input.now ?? new Date();
  const trigger = input.trigger ?? "daily";
  const timezone = input.timezone ?? Intl.DateTimeFormat().resolvedOptions().timeZone ?? "UTC";
  const draft: ScheduleRecord = {
    schemaVersion: 1,
    id: `sch-${crypto.randomUUID()}`,
    workspaceId: input.workspaceId,
    targetPath: path.resolve(input.targetPath),
    enabled: input.enabled ?? true,
    trigger,
    ...(input.time ? { time: input.time } : trigger !== "cron" ? { time: "09:00" } : {}),
    ...(input.cron ? { cron: input.cron } : {}),
    timezone,
    mode: input.mode ?? "auto",
    changePolicy: input.changePolicy ?? "scan-if-git-changed",
    scanDepth: input.scanDepth ?? "auto",
  };
  const schedule = validateScheduleRecord({
    ...draft,
    nextRunAt: computeNextRunAt(draft, now),
  });
  const saved = await scheduleStore().update((file) => ({
    schemaVersion: 1,
    schedules: [schedule, ...file.schedules.filter((item) => item.id !== schedule.id)],
  }));
  const result = saved.schedules.find((item) => item.id === schedule.id);
  if (!result) {
    throw new Error(`Schedule ${schedule.id} was not saved`);
  }
  return result;
}

export async function listSchedules(workspaceId?: string): Promise<ScheduleRecord[]> {
  await ensureHermsecAppData();
  const file = await scheduleStore().load();
  return file.schedules.filter((schedule) => !workspaceId || schedule.workspaceId === workspaceId);
}

export async function getSchedule(scheduleId: string): Promise<ScheduleRecord | undefined> {
  return (await listSchedules()).find((schedule) => schedule.id === scheduleId);
}

export async function removeSchedule(scheduleId: string): Promise<boolean> {
  await ensureHermsecAppData();
  let removed = false;
  await scheduleStore().update((file) => {
    const schedules = file.schedules.filter((schedule) => schedule.id !== scheduleId);
    removed = schedules.length !== file.schedules.length;
    return { schemaVersion: 1, schedules };
  });
  return removed;
}

export async function updateSchedule(
  scheduleId: string,
  mutator: (schedule: ScheduleRecord) => ScheduleRecord,
): Promise<ScheduleRecord> {
  await ensureHermsecAppData();
  const saved = await scheduleStore().update((file) => {
    const index = file.schedules.findIndex((schedule) => schedule.id === scheduleId);
    if (index === -1) {
      throw new Error(`Unknown schedule: ${scheduleId}`);
    }
    const current = file.schedules[index];
    if (!current) {
      throw new Error(`Unknown schedule: ${scheduleId}`);
    }
    const schedules = [...file.schedules];
    schedules[index] = validateScheduleRecord(mutator(current));
    return { schemaVersion: 1, schedules };
  });
  const result = saved.schedules.find((schedule) => schedule.id === scheduleId);
  if (!result) {
    throw new Error(`Unknown schedule: ${scheduleId}`);
  }
  return result;
}
