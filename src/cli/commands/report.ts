import { defaultReportDir } from "../../shared/paths.js";
import { getFlagString, parseArgs, unknownFlagResult } from "../args.js";
import { commandHelp, helpResult, usageError } from "../help.js";
import { moduleSpecs } from "../moduleSpecs.js";
import { invokeOptionalModule, isModuleUnavailable } from "../optionalModule.js";
import { toOutcome } from "../output.js";
import type { CliOutcome, CommandContext } from "../types.js";

type ReportListOptions = {
  cwd: string;
  workspaceId?: string;
};

type ReportOpenOptions = {
  cwd: string;
  selector: string;
};

type ReportPathOptions = {
  cwd: string;
  workspaceId?: string;
  reportId?: string;
};

export async function runReportCommand(args: string[], context: CommandContext): Promise<CliOutcome> {
  const [subcommand, ...rest] = args;
  if (subcommand === undefined || subcommand === "--help" || subcommand === "help") {
    return toOutcome(helpResult(commandHelp("report")));
  }

  switch (subcommand) {
    case "list":
      return reportList(rest, context);
    case "open":
      return reportOpen(rest, context);
    case "path":
      return reportPath(rest, context);
    default:
      return toOutcome(usageError(`Unknown report command: ${subcommand}.`, "hermsec report --help"));
  }
}

async function reportList(args: string[], context: CommandContext): Promise<CliOutcome> {
  const parsed = parseArgs(args, {
    booleanFlags: ["json", "help"],
    valueFlags: ["workspace"],
  });
  const json = parsed.flags.json === true;

  if (parsed.unknownFlags.length > 0) {
    return toOutcome(unknownFlagResult(parsed.unknownFlags, "hermsec report list --help"), json);
  }
  if (parsed.flags.help === true) {
    return toOutcome(helpResult("Usage: hermsec report list [--workspace <id>] [--json]"));
  }

  const options: ReportListOptions = { cwd: context.cwd };
  const workspaceId = getFlagString(parsed, "workspace");
  if (workspaceId !== undefined) {
    options.workspaceId = workspaceId;
  }

  const result = await invokeOptionalModule<ReportListOptions>(
    moduleSpecs.reportList,
    options,
    "Reports loaded.",
  );
  return toOutcome(result, json);
}

async function reportOpen(args: string[], context: CommandContext): Promise<CliOutcome> {
  const parsed = parseArgs(args, {
    booleanFlags: ["json", "help"],
  });
  const json = parsed.flags.json === true;

  if (parsed.unknownFlags.length > 0) {
    return toOutcome(unknownFlagResult(parsed.unknownFlags, "hermsec report open --help"), json);
  }
  if (parsed.flags.help === true) {
    return toOutcome(helpResult("Usage: hermsec report open [latest|report-id|path] [--json]"));
  }

  const selector = parsed.positionals[0] ?? "latest";
  const result = await invokeOptionalModule<ReportOpenOptions>(
    moduleSpecs.reportOpen,
    { cwd: context.cwd, selector },
    "Report opened.",
  );
  return toOutcome(result, json);
}

async function reportPath(args: string[], context: CommandContext): Promise<CliOutcome> {
  const parsed = parseArgs(args, {
    booleanFlags: ["json", "help"],
    valueFlags: ["workspace"],
  });
  const json = parsed.flags.json === true;

  if (parsed.unknownFlags.length > 0) {
    return toOutcome(unknownFlagResult(parsed.unknownFlags, "hermsec report path --help"), json);
  }
  if (parsed.flags.help === true) {
    return toOutcome(helpResult("Usage: hermsec report path [report-id] [--workspace <id>] [--json]"));
  }

  const options: ReportPathOptions = { cwd: context.cwd };
  const workspaceId = getFlagString(parsed, "workspace");
  if (workspaceId !== undefined) {
    options.workspaceId = workspaceId;
  }
  const reportId = parsed.positionals[0];
  if (reportId !== undefined) {
    options.reportId = reportId;
  }

  const result = await invokeOptionalModule<ReportPathOptions, { path: string }>(
    moduleSpecs.reportPath,
    options,
    "Report path loaded.",
  );

  if (!isModuleUnavailable(result)) {
    return toOutcome(result, json);
  }

  return toOutcome({
    ok: true,
    message: defaultReportDir(),
    data: { path: defaultReportDir(), fallback: true },
  }, json);
}
