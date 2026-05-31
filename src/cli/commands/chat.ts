import { parseArgs, unknownFlagResult } from "../args.js";
import { commandHelp, helpResult } from "../help.js";
import { moduleSpecs } from "../moduleSpecs.js";
import { invokeOptionalModule } from "../optionalModule.js";
import { toOutcome } from "../output.js";
import type { CommandContext, CliOutcome } from "../types.js";

type ChatOptions = {
  cwd: string;
  args: string[];
  firstRun: boolean;
};

export async function runChatCommand(
  args: string[],
  context: CommandContext,
  firstRun = false,
): Promise<CliOutcome> {
  const parsed = parseArgs(args, {
    booleanFlags: ["help"],
  });

  if (parsed.unknownFlags.length > 0) {
    return toOutcome(unknownFlagResult(parsed.unknownFlags, "hermsec chat --help"));
  }

  if (parsed.flags.help === true) {
    return toOutcome(helpResult("Usage: hermsec chat"));
  }

  const result = await invokeOptionalModule<ChatOptions>(
    moduleSpecs.chat,
    { cwd: context.cwd, args: parsed.positionals, firstRun },
    "Chat session finished.",
  );
  return toOutcome(result);
}

export async function runOnboardCommand(
  args: string[],
  context: CommandContext,
): Promise<CliOutcome> {
  const parsed = parseArgs(args, {
    booleanFlags: ["help"],
  });

  if (parsed.unknownFlags.length > 0) {
    return toOutcome(unknownFlagResult(parsed.unknownFlags, "hermsec onboard --help"));
  }

  if (parsed.flags.help === true) {
    return toOutcome(helpResult(commandHelp("onboard")));
  }

  const result = await invokeOptionalModule<Omit<ChatOptions, "firstRun">>(
    moduleSpecs.onboard,
    { cwd: context.cwd, args: parsed.positionals },
    "Onboarding finished.",
  );
  return toOutcome(result);
}
