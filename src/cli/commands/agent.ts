import { askSecurityAgent, getAgentProviderStatus } from "../../agent/securityChat.js";
import type { ScanMode } from "../../shared/types.js";
import { getFlagString, parseArgs, resolveLocalPath, unknownFlagResult } from "../args.js";
import { commandHelp, helpResult, usageError } from "../help.js";
import { toOutcome } from "../output.js";
import type { CliOutcome, CommandContext } from "../types.js";
import { parseScanMode } from "../validators.js";

export async function runAgentCommand(args: string[], context: CommandContext): Promise<CliOutcome> {
  const [subcommand, ...rest] = args;
  if (subcommand === undefined || subcommand === "--help" || subcommand === "help") {
    return toOutcome(helpResult(commandHelp("agent")));
  }

  switch (subcommand) {
    case "ask":
      return agentAsk(rest, context);
    case "providers":
      return agentProviders(rest, context);
    default:
      return toOutcome(usageError(`Unknown agent command: ${subcommand}.`, "hermsec agent --help"));
  }
}

async function agentAsk(args: string[], context: CommandContext): Promise<CliOutcome> {
  const parsed = parseArgs(args, {
    booleanFlags: ["json", "help", "no-model"],
    valueFlags: ["target", "mode"],
  });
  const json = parsed.flags.json === true;

  if (parsed.unknownFlags.length > 0) {
    return toOutcome(unknownFlagResult(parsed.unknownFlags, "hermsec agent ask --help"), json);
  }
  if (parsed.flags.help === true) {
    return toOutcome(helpResult(commandHelp("agent")), json);
  }

  const content = parsed.positionals.join(" ").trim();
  if (!content) {
    return toOutcome(usageError("Agent ask requires a message.", "hermsec agent ask --help"), json);
  }

  const mode = parseScanMode(getFlagString(parsed, "mode")) ?? "auto";
  const targetInput = getFlagString(parsed, "target");
  const options: {
    cwd: string;
    content: string;
    mode: ScanMode;
    useModel: boolean;
    target?: string;
  } = {
    cwd: context.cwd,
    content,
    mode,
    useModel: parsed.flags["no-model"] !== true,
  };
  if (targetInput) {
    options.target = resolveLocalPath(targetInput, context.cwd);
  }

  return toOutcome(await askSecurityAgent(options), json);
}

async function agentProviders(args: string[], context: CommandContext): Promise<CliOutcome> {
  const parsed = parseArgs(args, {
    booleanFlags: ["json", "help"],
  });
  const json = parsed.flags.json === true;

  if (parsed.unknownFlags.length > 0) {
    return toOutcome(unknownFlagResult(parsed.unknownFlags, "hermsec agent providers --help"), json);
  }
  if (parsed.flags.help === true) {
    return toOutcome(helpResult(commandHelp("agent")), json);
  }

  return toOutcome(await getAgentProviderStatus({ cwd: context.cwd }), json);
}
