import fs from "node:fs/promises";
import path from "node:path";
import {
  optionalString,
  optionalStringArray,
  requireEnum,
  requireRecord,
  requireString,
} from "./jsonStore.js";
import { assertNoSecretFields } from "./secretsPolicy.js";

export const projectScanModes = ["offline", "online", "auto"] as const;
export const projectFailOnValues = ["critical", "high", "none"] as const;
export const projectReportLocations = ["project-local", "app-data", "custom"] as const;
export const projectReportFormats = ["md", "json", "html"] as const;

export type ProjectConfig = {
  schemaVersion: 1;
  displayName?: string;
  scanPolicy?: {
    mode?: (typeof projectScanModes)[number];
    include?: string[];
    exclude?: string[];
    failOn?: (typeof projectFailOnValues)[number];
  };
  reports?: {
    location?: (typeof projectReportLocations)[number];
    customDir?: string;
    formats?: Array<(typeof projectReportFormats)[number]>;
  };
  suppressions?: {
    findingIdOrFingerprint: string;
    reason: string;
    expiresAt?: string;
  }[];
};

export function projectConfigPath(projectRoot: string): string {
  return path.join(path.resolve(projectRoot), ".hermsec", "project.json");
}

export function validateProjectConfig(value: unknown): ProjectConfig {
  assertNoSecretFields(value);
  const record = requireRecord(value, "project config");
  if (record.schemaVersion !== 1) {
    throw new Error("project.schemaVersion must be 1");
  }

  const config: ProjectConfig = { schemaVersion: 1 };
  const displayName = optionalString(record.displayName, "project.displayName");
  if (displayName) {
    config.displayName = displayName;
  }

  if (record.scanPolicy !== undefined) {
    const scanPolicy = requireRecord(record.scanPolicy, "project.scanPolicy");
    const include = optionalStringArray(scanPolicy.include, "project.scanPolicy.include");
    const exclude = optionalStringArray(scanPolicy.exclude, "project.scanPolicy.exclude");
    config.scanPolicy = {
      ...(scanPolicy.mode !== undefined
        ? { mode: requireEnum(scanPolicy.mode, "project.scanPolicy.mode", projectScanModes) }
        : {}),
      ...(include ? { include } : {}),
      ...(exclude ? { exclude } : {}),
      ...(scanPolicy.failOn !== undefined
        ? { failOn: requireEnum(scanPolicy.failOn, "project.scanPolicy.failOn", projectFailOnValues) }
        : {}),
    };
  }

  if (record.reports !== undefined) {
    const reports = requireRecord(record.reports, "project.reports");
    const formats = reports.formats;
    if (formats !== undefined) {
      if (
        !Array.isArray(formats) ||
        formats.some((format) => !projectReportFormats.includes(format as (typeof projectReportFormats)[number]))
      ) {
        throw new Error("project.reports.formats contains unsupported formats");
      }
    }
    config.reports = {
      ...(reports.location !== undefined
        ? { location: requireEnum(reports.location, "project.reports.location", projectReportLocations) }
        : {}),
      ...(reports.customDir !== undefined
        ? { customDir: path.resolve(requireString(reports.customDir, "project.reports.customDir")) }
        : {}),
      ...(formats !== undefined ? { formats: formats as Array<(typeof projectReportFormats)[number]> } : {}),
    };
  }

  if (record.suppressions !== undefined) {
    if (!Array.isArray(record.suppressions)) {
      throw new Error("project.suppressions must be an array");
    }
    config.suppressions = record.suppressions.map((item) => {
      const suppression = requireRecord(item, "project.suppressions[]");
      const expiresAt = optionalString(suppression.expiresAt, "project.suppressions[].expiresAt");
      return {
        findingIdOrFingerprint: requireString(
          suppression.findingIdOrFingerprint,
          "project.suppressions[].findingIdOrFingerprint",
        ),
        reason: requireString(suppression.reason, "project.suppressions[].reason"),
        ...(expiresAt ? { expiresAt } : {}),
      };
    });
  }

  return config;
}

export async function readProjectConfig(projectRoot: string): Promise<ProjectConfig | undefined> {
  const filePath = projectConfigPath(projectRoot);
  let raw: string;
  try {
    raw = await fs.readFile(filePath, "utf8");
  } catch (error) {
    const code = error && typeof error === "object" && "code" in error ? String(error.code) : "";
    if (code === "ENOENT") {
      return undefined;
    }
    throw error;
  }
  return validateProjectConfig(JSON.parse(raw));
}
