import type { ScanMode } from "../../shared/types.js";
import { getFlagString, parseArgs, resolveLocalPath, unknownFlagResult } from "../args.js";
import { commandHelp, helpResult, usageError } from "../help.js";
import { moduleSpecs } from "../moduleSpecs.js";
import { invokeOptionalModule } from "../optionalModule.js";
import { toOutcome } from "../output.js";
import type { CliOutcome, CommandContext } from "../types.js";
import { isDailyTime, parseScanMode } from "../validators.js";

type ScheduleAddOptions = {
  cwd: string;
  target: string;
  dailyTime: string;
  mode: ScanMode;
};

type ScheduleIdOptions = {
  cwd: string;
  scheduleId: string;
};

type ScheduleListOptions = {
  cwd: string;
};

export async function runScheduleCommand(args: string[], context: CommandContext): Promise<CliOutcome> {
  const [subcommand, ...rest] = args;
  if (subcommand === undefined || subcommand === "--help" || subcommand === "help") {
    return toOutcome(helpResult(commandHelp("schedule")));
  }

  switch (subcommand) {
    case "add":
      return scheduleAdd(rest, context);
    case "list":
      return scheduleList(rest, context);
    case "run":
      return scheduleRun(rest, context);
    case "remove":
      return scheduleRemove(rest, context);
    default:
      return toOutcome(usageError(`Unknown schedule command: ${subcommand}.`, "hermsec schedule --help"));
  }
}

async function scheduleAdd(args: string[], context: CommandContext): Promise<CliOutcome> {
  const parsed = parseArgs(args, {
    booleanFlags: ["json", "help"],
    valueFlags: ["daily", "mode"],
  });
  const json = parsed.flags.json === true;

  if (parsed.unknownFlags.length > 0) {
    return toOutcome(unknownFlagResult(parsed.unknownFlags, "hermsec schedule add --help"), json);
  }
  if (parsed.flags.help === true) {
    return toOutcome(helpResult("Usage: hermsec schedule add <target> --daily <HH:mm> [--mode auto|offline|online] [--json]"));
  }

  const targetInput = parsed.positionals[0];
  if (!targetInput) {
    return toOutcome(usageError("Schedule add requires a target.", "hermsec schedule --help"), json);
  }

  const dailyTime = getFlagString(parsed, "daily");
  if (!dailyTime || !isDailyTime(dailyTime)) {
    return toOutcome(usageError("Schedule add requires --daily <HH:mm> using 24-hour time.", "hermsec schedule --help"), json);
  }

  const mode = parseScanMode(getFlagString(parsed, "mode"));
  if (mode === undefined) {
    return toOutcome(usageError("Invalid schedule mode. Use auto, offline, or online.", "hermsec schedule --help"), json);
  }

  const result = await invokeOptionalModule<ScheduleAddOptions>(
    moduleSpecs.scheduleAdd,
    {
      cwd: context.cwd,
      target: resolveLocalPath(targetInput, context.cwd),
      dailyTime,
      mode,
    },
    "Schedule added.",
  );
  return toOutcome(result, json);
}

async function scheduleList(args: string[], context: CommandContext): Promise<CliOutcome> {
  const parsed = parseArgs(args, {
    booleanFlags: ["json", "help"],
  });
  const json = parsed.flags.json === true;

  if (parsed.unknownFlags.length > 0) {
    return toOutcome(unknownFlagResult(parsed.unknownFlags, "hermsec schedule list --help"), json);
  }
  if (parsed.flags.help === true) {
    return toOutcome(helpResult("Usage: hermsec schedule list [--json]"));
  }

  const result = await invokeOptionalModule<ScheduleListOptions>(
    moduleSpecs.scheduleList,
    { cwd: context.cwd },
    "Schedules loaded.",
  );
  return toOutcome(result, json);
}

async function scheduleRun(args: string[], context: CommandContext): Promise<CliOutcome> {
  const parsed = parseArgs(args, {
    booleanFlags: ["json", "help"],
  });
  const json = parsed.flags.json === true;

  if (parsed.unknownFlags.length > 0) {
    return toOutcome(unknownFlagResult(parsed.unknownFlags, "hermsec schedule run --help"), json);
  }
  if (parsed.flags.help === true) {
    return toOutcome(helpResult("Usage: hermsec schedule run <schedule-id> [--json]"));
  }

  const scheduleId = parsed.positionals[0];
  if (!scheduleId) {
    return toOutcome(usageError("Schedule run requires a schedule id.", "hermsec schedule --help"), json);
  }

  const result = await invokeOptionalModule<ScheduleIdOptions>(
    moduleSpecs.scheduleRun,
    { cwd: context.cwd, scheduleId },
    "Schedule run completed.",
  );
  return toOutcome(result, json);
}

async function scheduleRemove(args: string[], context: CommandContext): Promise<CliOutcome> {
  const parsed = parseArgs(args, {
    booleanFlags: ["json", "help"],
  });
  const json = parsed.flags.json === true;

  if (parsed.unknownFlags.length > 0) {
    return toOutcome(unknownFlagResult(parsed.unknownFlags, "hermsec schedule remove --help"), json);
  }
  if (parsed.flags.help === true) {
    return toOutcome(helpResult("Usage: hermsec schedule remove <schedule-id> [--json]"));
  }

  const scheduleId = parsed.positionals[0];
  if (!scheduleId) {
    return toOutcome(usageError("Schedule remove requires a schedule id.", "hermsec schedule --help"), json);
  }

  const result = await invokeOptionalModule<ScheduleIdOptions>(
    moduleSpecs.scheduleRemove,
    { cwd: context.cwd, scheduleId },
    "Schedule removed.",
  );
  return toOutcome(result, json);
}
