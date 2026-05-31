import process from "node:process";
import { runChatCommand, runOnboardCommand } from "./commands/chat.js";
import { runConfigCommand } from "./commands/config.js";
import { runDoctorCommand } from "./commands/doctor.js";
import { runEvalCommand } from "./commands/eval.js";
import { runIntelCommand } from "./commands/intel.js";
import { runReportCommand } from "./commands/report.js";
import { runScanCommand } from "./commands/scan.js";
import { runScheduleCommand } from "./commands/schedule.js";
import { runSyncCommand } from "./commands/sync.js";
import { runWatchCommand } from "./commands/watch.js";
import { runWorkspaceCommand } from "./commands/workspace.js";
import { helpResult, rootHelp, usageError } from "./help.js";
import { exitCodeFor, renderOutcome, toOutcome } from "./output.js";
import type { CliOutcome, CommandContext } from "./types.js";

export async function runCli(argv: string[]): Promise<void> {
  const outcome = await dispatchCli(argv);
  renderOutcome(outcome);
  process.exitCode = exitCodeFor(outcome);
}

export async function dispatchCli(
  argv: string[],
  context: CommandContext = defaultContext(),
): Promise<CliOutcome> {
  const [command, ...rest] = argv;

  if (command === undefined) {
    return runChatCommand([], context, true);
  }

  if (command === "--help" || command === "-h" || command === "help") {
    return toOutcome(helpResult(rootHelp()));
  }

  if (command === "--version" || command === "-v") {
    return toOutcome(helpResult("hermsec 0.1.0"));
  }

  switch (command) {
    case "chat":
      return runChatCommand(rest, context);
    case "doctor":
      return runDoctorCommand(rest, context);
    case "onboard":
      return runOnboardCommand(rest, context);
    case "scan":
      return runScanCommand(rest, context);
    case "config":
      return runConfigCommand(rest, context);
    case "workspace":
      return runWorkspaceCommand(rest, context);
    case "report":
      return runReportCommand(rest, context);
    case "sync":
      return runSyncCommand(rest, context);
    case "schedule":
      return runScheduleCommand(rest, context);
    case "watch":
      return runWatchCommand(rest, context);
    case "intel":
      return runIntelCommand(rest, context);
    case "eval":
      return runEvalCommand(rest, context);
    default:
      return toOutcome(
        usageError(`Unknown command: ${command}.`, "hermsec --help"),
        rest.includes("--json"),
      );
  }
}

function defaultContext(): CommandContext {
  return {
    cwd: process.cwd(),
    env: process.env,
    now: () => new Date(),
  };
}
