import path from "node:path";
import type { FlagValue, ParsedArgs } from "./types.js";

type ParseOptions = {
  booleanFlags?: readonly string[];
  valueFlags?: readonly string[];
  allowUnknownFlags?: boolean;
};

export function parseArgs(argv: string[], options: ParseOptions = {}): ParsedArgs {
  const booleanFlags = new Set(options.booleanFlags ?? []);
  const valueFlags = new Set(options.valueFlags ?? []);
  const allowUnknownFlags = options.allowUnknownFlags ?? false;
  const positionals: string[] = [];
  const flags: Record<string, FlagValue> = {};
  const unknownFlags: string[] = [];

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === undefined) {
      continue;
    }

    if (token === "--") {
      positionals.push(...argv.slice(index + 1));
      break;
    }

    if (!token?.startsWith("--") || token === "--") {
      if (token !== undefined) {
        positionals.push(token);
      }
      continue;
    }

    const flagToken = token.slice(2);
    const inlineValueIndex = flagToken.indexOf("=");
    const rawName = inlineValueIndex >= 0 ? flagToken.slice(0, inlineValueIndex) : flagToken;
    const inlineValue = inlineValueIndex >= 0 ? flagToken.slice(inlineValueIndex + 1) : undefined;
    const name = rawName.trim();

    if (!name) {
      unknownFlags.push(token);
      continue;
    }

    if (!allowUnknownFlags && !booleanFlags.has(name) && !valueFlags.has(name)) {
      unknownFlags.push(`--${name}`);
    }

    if (name.startsWith("no-") && inlineValue === undefined && !valueFlags.has(name)) {
      setFlag(flags, name, true);
      setFlag(flags, name.slice(3), false);
      continue;
    }

    if (inlineValue !== undefined) {
      setFlag(flags, name, inlineValue);
      continue;
    }

    if (valueFlags.has(name)) {
      const next = argv[index + 1];
      if (next === undefined || next.startsWith("--")) {
        setFlag(flags, name, "");
        continue;
      }
      setFlag(flags, name, next);
      index += 1;
      continue;
    }

    if (booleanFlags.has(name)) {
      setFlag(flags, name, true);
      continue;
    }

    const next = argv[index + 1];
    if (next !== undefined && !next.startsWith("--")) {
      setFlag(flags, name, next);
      index += 1;
    } else {
      setFlag(flags, name, true);
    }
  }

  return { positionals, flags, unknownFlags };
}

export function hasFlag(parsed: ParsedArgs, name: string): boolean {
  return parsed.flags[name] === true;
}

export function getFlagString(parsed: ParsedArgs, name: string): string | undefined {
  const value = parsed.flags[name];
  if (typeof value === "string" && value.length > 0) {
    return value;
  }
  return undefined;
}

export function getFlagStrings(parsed: ParsedArgs, name: string): string[] {
  const value = parsed.flags[name];
  if (typeof value === "string" && value.length > 0) {
    return value.split(",").map((item) => item.trim()).filter(Boolean);
  }
  if (Array.isArray(value)) {
    return value.flatMap((item) => item.split(",").map((entry) => entry.trim()).filter(Boolean));
  }
  return [];
}

export function unknownFlagResult(unknownFlags: string[], usage: string) {
  return {
    ok: false as const,
    errorCode: "UNKNOWN_FLAG",
    message: `Unknown option ${unknownFlags.join(", ")}.`,
    remediation: `Run ${usage} to see supported options.`,
  };
}

export function resolveLocalPath(value: string, cwd: string): string {
  if (isUrlLike(value) || isSshGitTarget(value)) {
    return value;
  }
  return path.resolve(cwd, value);
}

export function resolveOutputPath(value: string | undefined, cwd: string): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  return path.resolve(cwd, value);
}

function setFlag(flags: Record<string, FlagValue>, name: string, value: FlagValue): void {
  const existing = flags[name];
  if (existing === undefined) {
    flags[name] = value;
    return;
  }

  if (Array.isArray(existing)) {
    existing.push(String(value));
    return;
  }

  flags[name] = [String(existing), String(value)];
}

function isUrlLike(value: string): boolean {
  return /^https?:\/\//i.test(value) || /^file:\/\//i.test(value);
}

function isSshGitTarget(value: string): boolean {
  return /^[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+:.+/.test(value);
}
