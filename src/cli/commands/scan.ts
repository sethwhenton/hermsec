import type { OutputFormat, ScanAssistMode, ScanAssistModeInput, ScanMode, ScanProgressEvent } from "../../shared/types.js";
import { getFlagString, parseArgs, resolveLocalPath, resolveOutputPath, unknownFlagResult } from "../args.js";
import { commandHelp, helpResult, usageError } from "../help.js";
import { moduleSpecs } from "../moduleSpecs.js";
import { invokeOptionalModule } from "../optionalModule.js";
import { toOutcome } from "../output.js";
import type { CliOutcome, CommandContext } from "../types.js";
import { parseScanMode, selectedFormats } from "../validators.js";

type ScanOptions = {
  cwd: string;
  target: string;
  mode: ScanMode;
  assistMode?: ScanAssistModeInput;
  outputDirectory?: string;
  formats: OutputFormat[];
  useModel: boolean;
  runId?: string;
  onProgress?: (event: ScanProgressEvent) => void;
};

export async function runScanCommand(args: string[], context: CommandContext): Promise<CliOutcome> {
  const parsed = parseArgs(args, {
    booleanFlags: ["json", "md", "html", "no-model", "help"],
    valueFlags: ["mode", "out", "assist-mode", "run-id"],
  });

  const json = parsed.flags.json === true;

  if (parsed.unknownFlags.length > 0) {
    return toOutcome(unknownFlagResult(parsed.unknownFlags, "hermsec scan --help"), json);
  }

  if (parsed.flags.help === true) {
    return toOutcome(helpResult(commandHelp("scan")));
  }

  const targetInput = parsed.positionals[0];
  if (!targetInput) {
    return toOutcome(usageError("Missing scan target.", "hermsec scan --help"), json);
  }

  const mode = parseScanMode(getFlagString(parsed, "mode"));
  if (mode === undefined) {
    return toOutcome(usageError("Invalid scan mode. Use auto, offline, or online.", "hermsec scan --help"), json);
  }

  const assistMode = parseAssistMode(getFlagString(parsed, "assist-mode"));
  if (assistMode === undefined) {
    return toOutcome(
      usageError(
        "Invalid assist mode. Use scanner-only, single-agent, moa-low, moa-high, scanner-single, scanner-moa-low, or scanner-moa-high.",
        "hermsec scan --help",
      ),
      json,
    );
  }

  const options: ScanOptions = {
    cwd: context.cwd,
    target: resolveLocalPath(targetInput, context.cwd),
    mode,
    assistMode,
    formats: selectedFormats(parsed.flags),
    useModel: parsed.flags["no-model"] !== true,
    ...(json ? { onProgress: writeProgressJsonl } : {}),
  };
  const runId = getFlagString(parsed, "run-id");
  if (runId) {
    options.runId = runId;
  }
  const outputDirectory = resolveOutputPath(getFlagString(parsed, "out"), context.cwd);
  if (outputDirectory !== undefined) {
    options.outputDirectory = outputDirectory;
  }

  const result = await invokeOptionalModule<ScanOptions>(
    moduleSpecs.scan,
    options,
    "Scan completed.",
  );
  return toOutcome(result, json);
}

function writeProgressJsonl(event: ScanProgressEvent): void {
  process.stderr.write(`HERMSEC_PROGRESS ${JSON.stringify(event)}\n`);
}

function parseAssistMode(value: string | undefined): ScanAssistMode | undefined {
  switch (value) {
    case undefined:
    case "scanner-only":
    case "deep-assisted":
    case "scanner-model-summary":
      return "scanner-only";
    case "single-agent":
    case "single-agent-inspection":
      return "single-agent";
    case "moa-low":
    case "moa-assisted":
    case "moa-inspection":
      return "moa-low";
    case "moa-high":
      return "moa-high";
    case "scanner-single":
      return "scanner-single";
    case "scanner-moa-low":
    case "scanner-moa-assisted":
    case "scanner-moa-inspection":
    case "scanner-moa":
      return "scanner-moa-low";
    case "scanner-moa-high":
      return "scanner-moa-high";
    default:
      return undefined;
  }
}
