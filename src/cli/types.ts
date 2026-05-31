import type { CommandResult } from "../shared/types.js";

export type FlagValue = boolean | string | string[];

export type ParsedArgs = {
  positionals: string[];
  flags: Record<string, FlagValue>;
  unknownFlags: string[];
};

export type CommandContext = {
  cwd: string;
  env: NodeJS.ProcessEnv;
  now: () => Date;
};

export type CliOutcome<T = unknown> = {
  result: CommandResult<T>;
  json: boolean;
  exitCode?: number;
};

export type CommandHandler = (
  args: string[],
  context: CommandContext,
) => Promise<CliOutcome | CommandResult> | CliOutcome | CommandResult;

export type OptionalModuleSpec = {
  modulePath: string;
  exportName: string;
  expectedShape: string;
  unavailableMessage: string;
  remediation: string;
};
