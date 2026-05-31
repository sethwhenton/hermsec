import type { CommandResult } from "../shared/types.js";
import type { OptionalModuleSpec } from "./types.js";

export async function invokeOptionalModule<TOptions, TData = unknown>(
  spec: OptionalModuleSpec,
  options: TOptions,
  successMessage: string,
): Promise<CommandResult<TData>> {
  try {
    const namespace = (await import(spec.modulePath)) as Record<string, unknown>;
    const candidate = namespace[spec.exportName];

    if (typeof candidate !== "function") {
      return moduleUnavailable(
        spec,
        `Module ${spec.modulePath} loaded, but export ${spec.exportName} is not a function.`,
      );
    }

    const fn = candidate as (input: TOptions) => Promise<unknown> | unknown;
    const value = await fn(options);
    return normalizeCommandResult<TData>(value, successMessage);
  } catch (error: unknown) {
    return moduleUnavailable<TData>(spec, errorMessage(error));
  }
}

export function moduleUnavailable<TData = unknown>(
  spec: OptionalModuleSpec,
  cause?: string,
): CommandResult<TData> {
  const message = cause
    ? `${spec.unavailableMessage} (${cause})`
    : spec.unavailableMessage;

  return {
    ok: false,
    errorCode: "MODULE_UNAVAILABLE",
    message,
    remediation: `${spec.remediation} Expected shape: ${spec.expectedShape}`,
  };
}

export function isModuleUnavailable(result: CommandResult): boolean {
  return !result.ok && result.errorCode === "MODULE_UNAVAILABLE";
}

function normalizeCommandResult<TData>(value: unknown, successMessage: string): CommandResult<TData> {
  if (isCommandResult<TData>(value)) {
    return value;
  }

  return {
    ok: true,
    message: successMessage,
    data: value as TData,
  };
}

function isCommandResult<TData>(value: unknown): value is CommandResult<TData> {
  if (typeof value !== "object" || value === null || !("ok" in value)) {
    return false;
  }

  const candidate = value as { ok?: unknown; message?: unknown; errorCode?: unknown };
  if (candidate.ok === true) {
    return typeof candidate.message === "string";
  }
  if (candidate.ok === false) {
    return typeof candidate.message === "string" && typeof candidate.errorCode === "string";
  }
  return false;
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}
