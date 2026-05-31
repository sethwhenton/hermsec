import { parseArgs, unknownFlagResult } from "../args.js";
import { helpResult } from "../help.js";
import { moduleSpecs } from "../moduleSpecs.js";
import { invokeOptionalModule } from "../optionalModule.js";
import { toOutcome } from "../output.js";
import type { CliOutcome, CommandContext } from "../types.js";

type SyncOptions = {
  cwd: string;
  offline?: boolean;
};

export async function runSyncCommand(args: string[], context: CommandContext): Promise<CliOutcome> {
  const parsed = parseArgs(args, {
    booleanFlags: ["json", "help", "offline"],
  });
  const json = parsed.flags.json === true;

  if (parsed.unknownFlags.length > 0) {
    return toOutcome(unknownFlagResult(parsed.unknownFlags, "hermsec sync --help"), json);
  }
  if (parsed.flags.help === true) {
    return toOutcome(helpResult("Usage: hermsec sync [--offline] [--json]"));
  }

  const options: SyncOptions = { cwd: context.cwd };
  if (parsed.flags.offline === true) {
    options.offline = true;
  }

  const result = await invokeOptionalModule<SyncOptions>(
    moduleSpecs.sync,
    options,
    "Sync completed.",
  );
  return toOutcome(result, json);
}
