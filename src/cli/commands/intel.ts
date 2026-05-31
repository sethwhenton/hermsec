import { getFlagString, getFlagStrings, parseArgs, unknownFlagResult } from "../args.js";
import { commandHelp, helpResult, usageError } from "../help.js";
import { moduleSpecs } from "../moduleSpecs.js";
import { invokeOptionalModule } from "../optionalModule.js";
import { toOutcome } from "../output.js";
import type { CliOutcome, CommandContext } from "../types.js";

type IntelUpdateOptions = {
  cwd: string;
  workspaceId?: string;
  sources?: string[];
  offline: boolean;
};

export async function runIntelCommand(args: string[], context: CommandContext): Promise<CliOutcome> {
  const [subcommand, ...rest] = args;
  if (subcommand === undefined || subcommand === "--help" || subcommand === "help") {
    return toOutcome(helpResult(commandHelp("intel")));
  }

  if (subcommand !== "update") {
    return toOutcome(usageError(`Unknown intel command: ${subcommand}.`, "hermsec intel --help"));
  }

  return intelUpdate(rest, context);
}

async function intelUpdate(args: string[], context: CommandContext): Promise<CliOutcome> {
  const parsed = parseArgs(args, {
    booleanFlags: ["json", "help", "offline"],
    valueFlags: ["workspace", "source"],
  });
  const json = parsed.flags.json === true;

  if (parsed.unknownFlags.length > 0) {
    return toOutcome(unknownFlagResult(parsed.unknownFlags, "hermsec intel update --help"), json);
  }
  if (parsed.flags.help === true) {
    return toOutcome(helpResult(commandHelp("intel")));
  }

  const options: IntelUpdateOptions = {
    cwd: context.cwd,
    offline: parsed.flags.offline === true,
  };

  const workspaceId = getFlagString(parsed, "workspace");
  if (workspaceId !== undefined) {
    options.workspaceId = workspaceId;
  }
  const sources = getFlagStrings(parsed, "source");
  if (sources.length > 0) {
    options.sources = sources;
  }

  const result = await invokeOptionalModule<IntelUpdateOptions>(
    moduleSpecs.intelUpdate,
    options,
    "Security intelligence updated.",
  );
  if (!json && result.ok) {
    const summaryText = intelSummaryText(result.data);
    if (summaryText) {
      return toOutcome({
        ...result,
        message: `${result.message}\n\nTop security updates:\n${summaryText}`,
      }, json);
    }
  }
  return toOutcome(result, json);
}

function intelSummaryText(data: unknown): string | undefined {
  if (typeof data !== "object" || data === null || !("summaryText" in data)) {
    return undefined;
  }
  const summaryText = (data as { summaryText?: unknown }).summaryText;
  return typeof summaryText === "string" && summaryText.trim().length > 0 ? summaryText : undefined;
}
