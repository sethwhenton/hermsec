import fs from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { sanitizeJsonForWrite } from "./secretsPolicy.js";

export type JsonValidator<T> = (value: unknown) => T;

export type JsonLoadResult<T> =
  | { ok: true; path: string; value: T; existed: boolean }
  | { ok: false; path: string; errorCode: "not-json" | "invalid-schema" | "read-failed"; message: string };

export async function ensureDirectory(directory: string): Promise<void> {
  await fs.mkdir(directory, { recursive: true });
}

export const ensureDir = ensureDirectory;

export async function pathExists(targetPath: string): Promise<boolean> {
  try {
    await fs.access(targetPath);
    return true;
  } catch {
    return false;
  }
}

export async function readJsonFile<T>(
  filePath: string,
  fallback: T,
  validate: JsonValidator<T>,
): Promise<JsonLoadResult<T>> {
  let raw: string;
  try {
    raw = await fs.readFile(filePath, "utf8");
  } catch (error) {
    const code = error && typeof error === "object" && "code" in error ? String(error.code) : "";
    if (code === "ENOENT") {
      return { ok: true, path: filePath, value: fallback, existed: false };
    }
    return {
      ok: false,
      path: filePath,
      errorCode: "read-failed",
      message: error instanceof Error ? error.message : String(error),
    };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    return {
      ok: false,
      path: filePath,
      errorCode: "not-json",
      message: error instanceof Error ? error.message : String(error),
    };
  }

  try {
    return { ok: true, path: filePath, value: validate(parsed), existed: true };
  } catch (error) {
    return {
      ok: false,
      path: filePath,
      errorCode: "invalid-schema",
      message: error instanceof Error ? error.message : String(error),
    };
  }
}

export async function writeJsonFileAtomic<T>(filePath: string, value: T): Promise<void> {
  await ensureDirectory(path.dirname(filePath));
  const sanitized = sanitizeJsonForWrite(value);
  const tmpPath = path.join(
    path.dirname(filePath),
    `.${path.basename(filePath)}.${process.pid}.${Date.now()}.tmp`,
  );
  const payload = `${JSON.stringify(sanitized, null, 2)}\n`;
  await fs.writeFile(tmpPath, payload, { encoding: "utf8", mode: 0o600 });
  await fs.rename(tmpPath, filePath);
}

export async function readJson<T>(filePath: string, fallback: T): Promise<T> {
  const result = await readJsonFile(filePath, fallback, (value) => value as T);
  if (!result.ok) {
    throw new Error(`${result.errorCode} reading ${result.path}: ${result.message}`);
  }
  return result.value;
}

export async function writeJson<T>(filePath: string, value: T): Promise<void> {
  await writeJsonFileAtomic(filePath, value);
}

export async function backupFileIfExists(filePath: string, now = new Date()): Promise<string | undefined> {
  if (!(await pathExists(filePath))) {
    return undefined;
  }
  const backupPath = `${filePath}.bak.${now.toISOString().replace(/[:.]/g, "-")}`;
  await fs.copyFile(filePath, backupPath);
  return backupPath;
}

export class JsonStore<T> {
  constructor(
    private readonly filePath: string,
    private readonly fallback: T,
    private readonly validate: JsonValidator<T>,
  ) {}

  async load(): Promise<T> {
    const result = await readJsonFile(this.filePath, this.fallback, this.validate);
    if (!result.ok) {
      throw new Error(`${result.errorCode} reading ${result.path}: ${result.message}`);
    }
    return result.value;
  }

  async loadResult(): Promise<JsonLoadResult<T>> {
    return readJsonFile(this.filePath, this.fallback, this.validate);
  }

  async save(value: T): Promise<T> {
    const validated = this.validate(value);
    await writeJsonFileAtomic(this.filePath, validated);
    return validated;
  }

  async update(mutator: (current: T) => T | Promise<T>): Promise<T> {
    const current = await this.load();
    const next = await mutator(current);
    return this.save(next);
  }
}

export function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

export function requireString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${label} must be a non-empty string`);
  }
  return value;
}

export function optionalString(value: unknown, label: string): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  return requireString(value, label);
}

export function requireStringArray(value: unknown, label: string): string[] {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    throw new Error(`${label} must be an array of strings`);
  }
  return value as string[];
}

export function optionalStringArray(value: unknown, label: string): string[] | undefined {
  if (value === undefined) {
    return undefined;
  }
  return requireStringArray(value, label);
}

export function requireEnum<T extends string>(value: unknown, label: string, allowed: readonly T[]): T {
  if (typeof value !== "string" || !allowed.includes(value as T)) {
    throw new Error(`${label} must be one of: ${allowed.join(", ")}`);
  }
  return value as T;
}

export function optionalEnum<T extends string>(
  value: unknown,
  label: string,
  allowed: readonly T[],
): T | undefined {
  if (value === undefined) {
    return undefined;
  }
  return requireEnum(value, label, allowed);
}

export function requireBoolean(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") {
    throw new Error(`${label} must be a boolean`);
  }
  return value;
}

export function optionalBoolean(value: unknown, label: string): boolean | undefined {
  if (value === undefined) {
    return undefined;
  }
  return requireBoolean(value, label);
}
