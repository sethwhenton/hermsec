import path from "node:path";
import { appDataDir, defaultReportDir } from "../shared/paths.js";
import type { HermsecConfig } from "../shared/types.js";
import { ensureDir, readJson, writeJson } from "./jsonStore.js";

export function configPath(): string {
  return path.join(appDataDir(), "config.json");
}

export function defaultConfig(): HermsecConfig {
  return {
    schemaVersion: "1.0",
    reportDirectory: defaultReportDir(),
    privacyMode: "local-only",
    model: {
      provider: "none",
    },
    schedules: [],
  };
}

export async function loadConfig(): Promise<HermsecConfig> {
  const config = await readJson<HermsecConfig>(configPath(), defaultConfig());
  return {
    ...defaultConfig(),
    ...config,
    model: { ...defaultConfig().model, ...config.model },
    schedules: config.schedules ?? [],
  };
}

export async function saveConfig(config: HermsecConfig): Promise<void> {
  await ensureDir(appDataDir());
  await writeJson(configPath(), config);
}

export async function setConfigValue(key: string, value: string): Promise<HermsecConfig> {
  const config = await loadConfig();
  switch (key) {
    case "reportDirectory":
      config.reportDirectory = path.resolve(value);
      break;
    case "privacyMode":
      if (!["local-only", "balanced", "cloud-assisted"].includes(value)) {
        throw new Error("privacyMode must be local-only, balanced, or cloud-assisted");
      }
      config.privacyMode = value as HermsecConfig["privacyMode"];
      break;
    case "model.provider":
      if (!["none", "opencode-go", "openai-compatible", "ollama"].includes(value)) {
        throw new Error("model.provider must be none, opencode-go, openai-compatible, or ollama");
      }
      config.model.provider = value as HermsecConfig["model"]["provider"];
      break;
    case "model.baseUrl":
      config.model.baseUrl = value;
      break;
    case "model.model":
      config.model.model = value;
      break;
    case "model.apiKeyEnv":
      config.model.apiKeyEnv = value;
      break;
    default:
      throw new Error(`Unknown config key: ${key}`);
  }
  await saveConfig(config);
  return config;
}
