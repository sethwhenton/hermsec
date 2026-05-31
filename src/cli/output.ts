import type { CommandResult } from "../shared/types.js";
import { redactSecrets } from "../shared/text.js";
import type { CliOutcome } from "./types.js";

export function toOutcome<T = unknown>(
  result: CommandResult<T>,
  json = false,
  exitCode?: number,
): CliOutcome<T> {
  const outcome: CliOutcome<T> = { result, json };
  if (exitCode !== undefined) {
    outcome.exitCode = exitCode;
  }
  return outcome;
}

export function renderOutcome(outcome: CliOutcome): void {
  const safeResult = redactValue(outcome.result);

  if (outcome.json) {
    console.log(JSON.stringify(safeResult, null, 2));
    return;
  }

  if (outcome.result.ok) {
    console.log(redactSecrets(outcome.result.message));
    const data = "data" in outcome.result ? outcome.result.data : undefined;
    if (typeof data === "string" && data.length > 0) {
      console.log(redactSecrets(data));
    }
    return;
  }

  console.error(`Hermsec: ${redactSecrets(outcome.result.message)}`);
  if (outcome.result.remediation) {
    console.error(`Next: ${redactSecrets(outcome.result.remediation)}`);
  }
}

export function exitCodeFor(outcome: CliOutcome): number {
  if (outcome.exitCode !== undefined) {
    return outcome.exitCode;
  }
  return outcome.result.ok ? 0 : 1;
}

function redactValue(value: unknown): unknown {
  if (typeof value === "string") {
    return redactSecrets(value);
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactValue(item));
  }
  if (typeof value === "object" && value !== null) {
    const redacted: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value)) {
      redacted[key] = redactValue(entry);
    }
    return redacted;
  }
  return value;
}
