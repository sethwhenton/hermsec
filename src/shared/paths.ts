import path from "node:path";
import process from "node:process";

export function appDataDir(): string {
  const base =
    process.env.HERMSEC_HOME ??
    process.env.LOCALAPPDATA ??
    process.env.APPDATA ??
    process.env.HOME ??
    process.cwd();
  return path.join(base, "Hermsec");
}

export function defaultReportDir(): string {
  return path.join(appDataDir(), "reports");
}

export function toPosixPath(value: string): string {
  return value.replace(/\\/g, "/");
}

export function normalizeTargetPath(value: string): string {
  return path.resolve(value);
}
