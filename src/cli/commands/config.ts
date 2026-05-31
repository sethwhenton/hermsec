import { appDataDir } from "../../shared/paths.js";
import { getFlagString, parseArgs, unknownFlagResult } from "../args.js";
import { commandHelp, helpResult, usageError } from "../help.js";
import { moduleSpecs } from "../moduleSpecs.js";
import { invokeOptionalModule, isModuleUnavailable } from "../optionalModule.js";
import { toOutcome } from "../output.js";
import type { CliOutcome, CommandContext } from "../types.js";
import { looksLikeSecretValue } from "../validators.js";
import path from "node:path";

type ConfigGetOptions = {
  cwd: string;
  key?: string;
};

type ConfigSetOptions = {
  cwd: string;
  key: string;
  value: string;
};

type ConfigPathOptions = {
  cwd: string;
};

export async function runConfigCommand(args: string[], context: CommandContext): Promise<CliOutcome> {
  const [subcommand, ...rest] = args;
  if (subcommand === undefined || subcommand === "--help" || subcommand === "help") {
    return toOutcome(helpResult(commandHelp("config")));
  }

  switch (subcommand) {
    case "get":
      return configGet(rest, context);
    case "set":
      return configSet(rest, context);
    case "path":
      return configPath(rest, context);
    default:
      return toOutcome(usageError(`Unknown config command: ${subcommand}.`, "hermsec config --help"));
  }
}

async function configGet(args: string[], context: CommandContext): Promise<CliOutcome> {
  const parsed = parseArgs(args, {
    booleanFlags: ["json", "help"],
  });
  const json = parsed.flags.json === true;

  if (parsed.unknownFlags.length > 0) {
    return toOutcome(unknownFlagResult(parsed.unknownFlags, "hermsec config get --help"), json);
  }
  if (parsed.flags.help === true) {
    return toOutcome(helpResult("Usage: hermsec config get [key] [--json]"));
  }

  const options: ConfigGetOptions = { cwd: context.cwd };
  const key = parsed.positionals[0];
  if (key !== undefined) {
    options.key = key;
  }

  const result = await invokeOptionalModule<ConfigGetOptions>(
    moduleSpecs.configGet,
    options,
    "Config value loaded.",
  );
  return toOutcome(result, json);
}

async function configSet(args: string[], context: CommandContext): Promise<CliOutcome> {
  const parsed = parseArgs(args, {
    booleanFlags: ["json", "help"],
  });
  const json = parsed.flags.json === true;

  if (parsed.unknownFlags.length > 0) {
    return toOutcome(unknownFlagResult(parsed.unknownFlags, "hermsec config set --help"), json);
  }
  if (parsed.flags.help === true) {
    return toOutcome(helpResult("Usage: hermsec config set <key> <value> [--json]"));
  }

  const [key, value] = parsed.positionals;
  if (!key || value === undefined) {
    return toOutcome(usageError("Config set requires a key and value.", "hermsec config --help"), json);
  }
  if (looksLikeSecretValue(value)) {
    return toOutcome({
      ok: false,
      errorCode: "SECRET_CONFIG_REJECTED",
      message: "Refusing to store secret-like config values in Hermsec project state.",
      remediation: "Store credentials in environment variables or an OS credential store and save only the reference name.",
    }, json);
  }

  const result = await invokeOptionalModule<ConfigSetOptions>(
    moduleSpecs.configSet,
    { cwd: context.cwd, key, value },
    "Config value saved.",
  );
  return toOutcome(result, json);
}

async function configPath(args: string[], context: CommandContext): Promise<CliOutcome> {
  const parsed = parseArgs(args, {
    booleanFlags: ["json", "help"],
  });
  const json = parsed.flags.json === true;

  if (parsed.unknownFlags.length > 0) {
    return toOutcome(unknownFlagResult(parsed.unknownFlags, "hermsec config path --help"), json);
  }
  if (parsed.flags.help === true) {
    return toOutcome(helpResult("Usage: hermsec config path [--json]"));
  }

  const result = await invokeOptionalModule<ConfigPathOptions, { path: string }>(
    moduleSpecs.configPath,
    { cwd: context.cwd },
    "Config path loaded.",
  );

  if (!isModuleUnavailable(result)) {
    return toOutcome(result, json);
  }

  const fallbackPath = path.join(appDataDir(), "config.json");
  return toOutcome({
    ok: true,
    message: fallbackPath,
    data: { path: fallbackPath, fallback: true },
  }, json);
}
