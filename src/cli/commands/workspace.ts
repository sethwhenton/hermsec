import { getFlagString, parseArgs, resolveLocalPath, unknownFlagResult } from "../args.js";
import { commandHelp, helpResult, usageError } from "../help.js";
import { moduleSpecs } from "../moduleSpecs.js";
import { invokeOptionalModule } from "../optionalModule.js";
import { toOutcome } from "../output.js";
import type { CliOutcome, CommandContext } from "../types.js";

type WorkspaceListOptions = {
  cwd: string;
};

type WorkspaceAddOptions = {
  cwd: string;
  target: string;
  name?: string;
};

type WorkspaceUseOptions = {
  cwd: string;
  selector: string;
};

export async function runWorkspaceCommand(args: string[], context: CommandContext): Promise<CliOutcome> {
  const [subcommand, ...rest] = args;
  if (subcommand === undefined || subcommand === "--help" || subcommand === "help") {
    return toOutcome(helpResult(commandHelp("workspace")));
  }

  switch (subcommand) {
    case "list":
      return workspaceList(rest, context);
    case "add":
      return workspaceAdd(rest, context);
    case "use":
      return workspaceUse(rest, context);
    default:
      return toOutcome(usageError(`Unknown workspace command: ${subcommand}.`, "hermsec workspace --help"));
  }
}

async function workspaceList(args: string[], context: CommandContext): Promise<CliOutcome> {
  const parsed = parseArgs(args, {
    booleanFlags: ["json", "help"],
  });
  const json = parsed.flags.json === true;

  if (parsed.unknownFlags.length > 0) {
    return toOutcome(unknownFlagResult(parsed.unknownFlags, "hermsec workspace list --help"), json);
  }
  if (parsed.flags.help === true) {
    return toOutcome(helpResult("Usage: hermsec workspace list [--json]"));
  }

  const result = await invokeOptionalModule<WorkspaceListOptions>(
    moduleSpecs.workspaceList,
    { cwd: context.cwd },
    "Workspaces loaded.",
  );
  return toOutcome(result, json);
}

async function workspaceAdd(args: string[], context: CommandContext): Promise<CliOutcome> {
  const parsed = parseArgs(args, {
    booleanFlags: ["json", "help"],
    valueFlags: ["name"],
  });
  const json = parsed.flags.json === true;

  if (parsed.unknownFlags.length > 0) {
    return toOutcome(unknownFlagResult(parsed.unknownFlags, "hermsec workspace add --help"), json);
  }
  if (parsed.flags.help === true) {
    return toOutcome(helpResult("Usage: hermsec workspace add [path] [--name <name>] [--json]"));
  }

  const target = resolveLocalPath(parsed.positionals[0] ?? context.cwd, context.cwd);
  const options: WorkspaceAddOptions = { cwd: context.cwd, target };
  const name = getFlagString(parsed, "name");
  if (name !== undefined) {
    options.name = name;
  }

  const result = await invokeOptionalModule<WorkspaceAddOptions>(
    moduleSpecs.workspaceAdd,
    options,
    "Workspace added.",
  );
  return toOutcome(result, json);
}

async function workspaceUse(args: string[], context: CommandContext): Promise<CliOutcome> {
  const parsed = parseArgs(args, {
    booleanFlags: ["json", "help"],
  });
  const json = parsed.flags.json === true;

  if (parsed.unknownFlags.length > 0) {
    return toOutcome(unknownFlagResult(parsed.unknownFlags, "hermsec workspace use --help"), json);
  }
  if (parsed.flags.help === true) {
    return toOutcome(helpResult("Usage: hermsec workspace use <id|name|path> [--json]"));
  }

  const selector = parsed.positionals[0];
  if (!selector) {
    return toOutcome(usageError("Workspace use requires an id, name, or path.", "hermsec workspace --help"), json);
  }

  const result = await invokeOptionalModule<WorkspaceUseOptions>(
    moduleSpecs.workspaceUse,
    { cwd: context.cwd, selector },
    "Workspace selected.",
  );
  return toOutcome(result, json);
}
