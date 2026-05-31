import type { ScanMode } from "../../shared/types.js";
import { getFlagString, parseArgs, resolveLocalPath, unknownFlagResult } from "../args.js";
import { commandHelp, helpResult, usageError } from "../help.js";
import { moduleSpecs } from "../moduleSpecs.js";
import { invokeOptionalModule } from "../optionalModule.js";
import { toOutcome } from "../output.js";
import type { CliOutcome, CommandContext } from "../types.js";
import { isDuration, parseScanMode } from "../validators.js";

type WatchOptions = {
  cwd: string;
  target: string;
  afterIdle: string;
  mode: ScanMode;
};

export async function runWatchCommand(args: string[], context: CommandContext): Promise<CliOutcome> {
  const parsed = parseArgs(args, {
    booleanFlags: ["json", "help"],
    valueFlags: ["after-idle", "mode"],
  });
  const json = parsed.flags.json === true;

  if (parsed.unknownFlags.length > 0) {
    return toOutcome(unknownFlagResult(parsed.unknownFlags, "hermsec watch --help"), json);
  }
  if (parsed.flags.help === true) {
    return toOutcome(helpResult(commandHelp("watch")));
  }

  const targetInput = parsed.positionals[0];
  if (!targetInput) {
    return toOutcome(usageError("Watch requires a target.", "hermsec watch --help"), json);
  }

  const afterIdle = getFlagString(parsed, "after-idle") ?? "30s";
  if (!isDuration(afterIdle)) {
    return toOutcome(usageError("Invalid --after-idle duration. Use values like 500ms, 30s, 5m, or 1h.", "hermsec watch --help"), json);
  }

  const mode = parseScanMode(getFlagString(parsed, "mode"));
  if (mode === undefined) {
    return toOutcome(usageError("Invalid watch mode. Use auto, offline, or online.", "hermsec watch --help"), json);
  }

  const result = await invokeOptionalModule<WatchOptions>(
    moduleSpecs.watch,
    {
      cwd: context.cwd,
      target: resolveLocalPath(targetInput, context.cwd),
      afterIdle,
      mode,
    },
    "Watch mode finished.",
  );
  return toOutcome(result, json);
}
