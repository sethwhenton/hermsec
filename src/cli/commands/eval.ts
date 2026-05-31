import { getFlagString, parseArgs, resolveOutputPath, unknownFlagResult } from "../args.js";
import { commandHelp, helpResult, usageError } from "../help.js";
import { moduleSpecs } from "../moduleSpecs.js";
import { invokeOptionalModule } from "../optionalModule.js";
import { toOutcome } from "../output.js";
import type { CliOutcome, CommandContext } from "../types.js";

type EvalMode = "scanner-only" | "agent-assisted";

type EvalRunOptions = {
  cwd: string;
  suite?: string;
  mode?: EvalMode;
  outputDirectory?: string;
};

type EvalCompareOptions = {
  cwd: string;
  scannerOnly: string;
  agentAssisted: string;
  outputPath?: string;
};

type EvalExplainMatchOptions = {
  cwd: string;
  suite?: string;
  caseId: string;
  findingId: string;
};

export async function runEvalCommand(args: string[], context: CommandContext): Promise<CliOutcome> {
  const [subcommand, ...rest] = args;
  if (subcommand === undefined || subcommand === "--help" || subcommand === "help") {
    return toOutcome(helpResult(commandHelp("eval")));
  }

  switch (subcommand) {
    case "run":
      return evalRun(rest, context);
    case "compare":
      return evalCompare(rest, context);
    case "explain-match":
      return evalExplainMatch(rest, context);
    default:
      return toOutcome(usageError(`Unknown eval command: ${subcommand}.`, "hermsec eval --help"));
  }
}

async function evalRun(args: string[], context: CommandContext): Promise<CliOutcome> {
  const parsed = parseArgs(args, {
    booleanFlags: ["json", "help"],
    valueFlags: ["suite", "mode", "out"],
  });
  const json = parsed.flags.json === true;

  if (parsed.unknownFlags.length > 0) {
    return toOutcome(unknownFlagResult(parsed.unknownFlags, "hermsec eval run --help"), json);
  }
  if (parsed.flags.help === true) {
    return toOutcome(helpResult("Usage: hermsec eval run [--suite <path>] [--mode scanner-only|agent-assisted] [--out <dir>] [--json]"));
  }

  const options: EvalRunOptions = { cwd: context.cwd };
  const suite = resolveOutputPath(getFlagString(parsed, "suite"), context.cwd);
  if (suite !== undefined) {
    options.suite = suite;
  }
  const mode = getFlagString(parsed, "mode");
  if (mode !== undefined) {
    if (mode !== "scanner-only" && mode !== "agent-assisted") {
      return toOutcome(usageError("Eval mode must be scanner-only or agent-assisted.", "hermsec eval run --help"), json);
    }
    options.mode = mode;
  }
  const outputDirectory = resolveOutputPath(getFlagString(parsed, "out"), context.cwd);
  if (outputDirectory !== undefined) {
    options.outputDirectory = outputDirectory;
  }

  const result = await invokeOptionalModule<EvalRunOptions>(
    moduleSpecs.evalRun,
    options,
    "Evaluation run completed.",
  );
  return toOutcome(result, json);
}

async function evalCompare(args: string[], context: CommandContext): Promise<CliOutcome> {
  const parsed = parseArgs(args, {
    booleanFlags: ["json", "help"],
    valueFlags: ["scanner-only", "agent-assisted", "out"],
  });
  const json = parsed.flags.json === true;

  if (parsed.unknownFlags.length > 0) {
    return toOutcome(unknownFlagResult(parsed.unknownFlags, "hermsec eval compare --help"), json);
  }
  if (parsed.flags.help === true) {
    return toOutcome(helpResult("Usage: hermsec eval compare --scanner-only <summary.json> --agent-assisted <summary.json> [--out <file>] [--json]"));
  }

  const scannerOnly = resolveOutputPath(getFlagString(parsed, "scanner-only"), context.cwd);
  const agentAssisted = resolveOutputPath(getFlagString(parsed, "agent-assisted"), context.cwd);
  if (!scannerOnly || !agentAssisted) {
    return toOutcome(usageError("Eval compare requires --scanner-only and --agent-assisted summary paths.", "hermsec eval compare --help"), json);
  }

  const options: EvalCompareOptions = {
    cwd: context.cwd,
    scannerOnly,
    agentAssisted,
  };
  const outputPath = resolveOutputPath(getFlagString(parsed, "out"), context.cwd);
  if (outputPath !== undefined) {
    options.outputPath = outputPath;
  }

  const result = await invokeOptionalModule<EvalCompareOptions>(
    moduleSpecs.evalCompare,
    options,
    "Evaluation comparison completed.",
  );
  return toOutcome(result, json);
}

async function evalExplainMatch(args: string[], context: CommandContext): Promise<CliOutcome> {
  const parsed = parseArgs(args, {
    booleanFlags: ["json", "help"],
    valueFlags: ["suite", "case", "finding"],
  });
  const json = parsed.flags.json === true;

  if (parsed.unknownFlags.length > 0) {
    return toOutcome(unknownFlagResult(parsed.unknownFlags, "hermsec eval explain-match --help"), json);
  }
  if (parsed.flags.help === true) {
    return toOutcome(helpResult("Usage: hermsec eval explain-match [--suite <path>] --case <id> --finding <id> [--json]"));
  }

  const caseId = getFlagString(parsed, "case");
  const findingId = getFlagString(parsed, "finding");
  if (!caseId || !findingId) {
    return toOutcome(usageError("Eval explain-match requires --case and --finding.", "hermsec eval explain-match --help"), json);
  }

  const options: EvalExplainMatchOptions = {
    cwd: context.cwd,
    caseId,
    findingId,
  };
  const suite = resolveOutputPath(getFlagString(parsed, "suite"), context.cwd);
  if (suite !== undefined) {
    options.suite = suite;
  }

  const result = await invokeOptionalModule<EvalExplainMatchOptions>(
    moduleSpecs.evalExplainMatch,
    options,
    "Evaluation match explanation completed.",
  );
  return toOutcome(result, json);
}
