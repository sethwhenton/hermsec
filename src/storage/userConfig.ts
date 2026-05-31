import path from "node:path";
import { ensureHermsecAppData, getAppDataLayout } from "./appData.js";
import {
  JsonStore,
  optionalString,
  requireEnum,
  requireRecord,
  requireString,
  requireStringArray,
} from "./jsonStore.js";
import type { HermsecAppDataLayout } from "./platformPaths.js";

export const privacyModes = ["local-only", "balanced", "cloud-assisted"] as const;
export type PrivacyMode = (typeof privacyModes)[number];

export const reportLocations = ["app-data", "project-local", "custom", "ask"] as const;
export type ReportLocation = (typeof reportLocations)[number];

export const modelProviders = [
  "none",
  "ollama",
  "openrouter",
  "openai",
  "claude",
  "gemini",
  "opencode-go",
  "openai-compatible",
] as const;
export type PreferredModelProvider = (typeof modelProviders)[number];

export const credentialRefKinds = ["env", "os-credential-store", "session-only"] as const;
export type ProviderCredentialRef = {
  kind: (typeof credentialRefKinds)[number];
  name?: string;
};

export type UserConfig = {
  schemaVersion: 1;
  privacyMode: PrivacyMode;
  defaultReportLocation: ReportLocation;
  customReportDir?: string;
  preferredModelProvider?: PreferredModelProvider;
  providerCredentialRef?: ProviderCredentialRef;
  recentWorkspaceIds: string[];
};

export function defaultUserConfig(layout: HermsecAppDataLayout = getAppDataLayout()): UserConfig {
  return {
    schemaVersion: 1,
    privacyMode: "local-only",
    defaultReportLocation: "app-data",
    customReportDir: layout.reportsDir,
    preferredModelProvider: "none",
    recentWorkspaceIds: [],
  };
}

export function validateCredentialRef(value: unknown): ProviderCredentialRef | undefined {
  if (value === undefined) {
    return undefined;
  }
  const record = requireRecord(value, "providerCredentialRef");
  const kind = requireEnum(record.kind, "providerCredentialRef.kind", credentialRefKinds);
  const name = optionalString(record.name, "providerCredentialRef.name");
  return name ? { kind, name } : { kind };
}

export function validateUserConfig(value: unknown): UserConfig {
  const record = requireRecord(value, "config");
  if (record.schemaVersion !== 1) {
    throw new Error("config.schemaVersion must be 1");
  }
  const privacyMode = requireEnum(record.privacyMode, "config.privacyMode", privacyModes);
  const defaultReportLocation = requireEnum(
    record.defaultReportLocation,
    "config.defaultReportLocation",
    reportLocations,
  );
  const customReportDir = optionalString(record.customReportDir, "config.customReportDir");
  const preferredModelProvider = record.preferredModelProvider === undefined
    ? undefined
    : requireEnum(record.preferredModelProvider, "config.preferredModelProvider", modelProviders);
  const providerCredentialRef = validateCredentialRef(record.providerCredentialRef);
  const recentWorkspaceIds = requireStringArray(record.recentWorkspaceIds ?? [], "config.recentWorkspaceIds");

  const config: UserConfig = {
    schemaVersion: 1,
    privacyMode,
    defaultReportLocation,
    recentWorkspaceIds,
  };
  if (customReportDir) {
    config.customReportDir = path.resolve(customReportDir);
  }
  if (preferredModelProvider) {
    config.preferredModelProvider = preferredModelProvider;
  }
  if (providerCredentialRef) {
    config.providerCredentialRef = providerCredentialRef;
  }
  return config;
}

export async function loadUserConfig(): Promise<UserConfig> {
  const layout = await ensureHermsecAppData();
  return new JsonStore(layout.configFile, defaultUserConfig(layout), validateUserConfig).load();
}

export async function saveUserConfig(config: UserConfig): Promise<UserConfig> {
  const layout = await ensureHermsecAppData();
  return new JsonStore(layout.configFile, defaultUserConfig(layout), validateUserConfig).save(config);
}

export async function updateRecentWorkspaces(workspaceId: string, limit = 12): Promise<UserConfig> {
  const layout = await ensureHermsecAppData();
  const store = new JsonStore(layout.configFile, defaultUserConfig(layout), validateUserConfig);
  return store.update((config) => ({
    ...config,
    recentWorkspaceIds: [workspaceId, ...config.recentWorkspaceIds.filter((id) => id !== workspaceId)].slice(
      0,
      limit,
    ),
  }));
}

export async function getConfigPath(): Promise<{
  ok: true;
  message: string;
  data: { path: string };
}> {
  const layout = await ensureHermsecAppData();
  return {
    ok: true,
    message: layout.configFile,
    data: { path: layout.configFile },
  };
}

export async function getConfigValue(options: { cwd: string; key?: string }): Promise<{
  ok: true;
  message: string;
  data: unknown;
}> {
  const config = await loadUserConfig();
  if (!options.key) {
    return { ok: true, message: JSON.stringify(config, null, 2), data: config };
  }
  const value = getNested(config as unknown as Record<string, unknown>, options.key);
  return {
    ok: true,
    message: value === undefined ? "" : typeof value === "string" ? value : JSON.stringify(value, null, 2),
    data: value,
  };
}

export async function setConfigValue(options: { cwd: string; key: string; value: string }): Promise<{
  ok: true;
  message: string;
  data: UserConfig;
}> {
  const config = await loadUserConfig();
  switch (options.key) {
    case "privacyMode":
      config.privacyMode = requireEnum(options.value, "privacyMode", privacyModes);
      break;
    case "defaultReportLocation":
      config.defaultReportLocation = requireEnum(options.value, "defaultReportLocation", reportLocations);
      break;
    case "customReportDir":
      config.customReportDir = path.resolve(options.cwd, options.value);
      config.defaultReportLocation = "custom";
      break;
    case "preferredModelProvider":
      config.preferredModelProvider = requireEnum(options.value, "preferredModelProvider", modelProviders);
      break;
    default:
      throw new Error(`Unsupported config key: ${options.key}`);
  }
  const saved = await saveUserConfig(config);
  return {
    ok: true,
    message: `Updated ${options.key}.`,
    data: saved,
  };
}

function getNested(source: Record<string, unknown>, key: string): unknown {
  return key.split(".").reduce<unknown>((current, part) => {
    if (current && typeof current === "object" && part in current) {
      return (current as Record<string, unknown>)[part];
    }
    return undefined;
  }, source);
}
