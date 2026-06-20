import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { app } from "electron";
import type { HermsecScanAssistMode } from "../renderer/src/types/scan";
import type { AppSettings, AutomationFrequency, DeepPartial, ProviderConfig } from "../renderer/src/types/settings";
import { getEnvDefaults } from "./env";
import { defaultScannerSettings, normalizeScannerSettings } from "./scannerDefaults";

const SETTINGS_FILE = "settings.json";

function defaultProvider(env: ReturnType<typeof getEnvDefaults>): ProviderConfig {
  const models = [
    { id: "kimi-k2.6", label: "Kimi K2.6", enabled: true },
    { id: "glm-5.1", label: "GLM 5.1", enabled: true },
    { id: "deepseek-v4-pro", label: "DeepSeek V4 Pro", enabled: true },
    { id: "deepseek-v4-flash", label: "DeepSeek V4 Flash", enabled: true },
  ];

  if (!models.some((model) => model.id === env.model)) {
    models.unshift({ id: env.model, label: env.model, enabled: true });
  }

  return {
    id: env.provider,
    displayName: "OpenCode Go",
    baseUrl: env.baseUrl,
    authKind: "environment",
    apiKeyEnvVar: env.apiKeyEnvVar,
    enabled: true,
    models,
  };
}

function defaultSettings(): AppSettings {
  const env = getEnvDefaults();
  return {
    general: {
      language: "English",
      autoAcceptPermissions: false,
      terminalShell: "Auto (Default)",
      showReasoning: true,
      privacyMode: false,
      scanMode: "scanner-model-summary",
      thinkingLevel: "balanced",
      contextWindow: "standard",
    },
    defaultProjectDir: "",
    defaultReportDir: join(app.getPath("documents"), "Hermsec", "reports"),
    activeModelId: env.model,
    automation: {
      enabled: false,
      frequency: "custom-days",
      intervalDays: 1,
      time: "09:00",
      scanMode: "scanner-model-summary",
    },
    providers: [defaultProvider(env)],
    scanners: defaultScannerSettings(),
  };
}

function deepMerge<T extends object>(target: T, source: DeepPartial<T>): T {
  const output = { ...target } as T;
  for (const key of Object.keys(source) as Array<keyof T>) {
    const sourceValue = source[key];
    const targetValue = target[key];
    if (
      sourceValue &&
      typeof sourceValue === "object" &&
      !Array.isArray(sourceValue) &&
      targetValue &&
      typeof targetValue === "object" &&
      !Array.isArray(targetValue)
    ) {
      output[key] = deepMerge(targetValue as object, sourceValue as DeepPartial<object>) as T[keyof T];
    } else if (sourceValue !== undefined) {
      output[key] = sourceValue as T[keyof T];
    }
  }
  return output;
}

function settingsPath(): string {
  const dir = app.getPath("userData");
  mkdirSync(dir, { recursive: true });
  return join(dir, SETTINGS_FILE);
}

export function readSettings(): AppSettings {
  const path = settingsPath();
  if (!existsSync(path)) {
    const settings = defaultSettings();
    writeSettings(settings);
    return settings;
  }

  try {
    const raw = readFileSync(path, "utf8");
    const parsed = JSON.parse(raw) as AppSettings;
    return normalizeSettings(deepMerge(defaultSettings(), parsed));
  } catch {
    const settings = defaultSettings();
    writeSettings(settings);
    return settings;
  }
}

export function writeSettings(settings: AppSettings): void {
  const path = settingsPath();
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, JSON.stringify(settings, null, 2), "utf8");
  renameSync(tmp, path);
}

export function updateSettings(partial: DeepPartial<AppSettings>): AppSettings {
  const current = readSettings();
  const next = normalizeSettings(deepMerge(current, partial));
  writeSettings(next);
  return next;
}

function normalizeSettings(settings: AppSettings): AppSettings {
  const defaults = defaultSettings();
  const defaultProvider = defaults.providers[0];
  const providers = settings.providers.map((provider) => {
    if (provider.id !== defaultProvider.id) return provider;
    const existingModelIds = new Set(provider.models.map((model) => model.id));
    const defaultModelsById = new Map(defaultProvider.models.map((model) => [model.id, model]));
    const modelsById = new Map<string, ProviderConfig["models"][number]>();
    for (const model of [
      ...provider.models,
      ...defaultProvider.models.filter((model) => !existingModelIds.has(model.id)),
    ]) {
      const defaultModel = defaultModelsById.get(model.id);
      const current = modelsById.get(model.id);
      modelsById.set(model.id, {
        ...model,
        label: defaultModel && model.label === model.id ? defaultModel.label : model.label,
        enabled: current ? current.enabled || model.enabled : model.enabled,
      });
    }
    return {
      ...provider,
      baseUrl: provider.baseUrl?.trim() ? provider.baseUrl : defaultProvider.baseUrl,
      apiKeyEnvVar: normalizeProviderApiKeyEnv(provider, defaultProvider),
      models: Array.from(modelsById.values()),
    };
  });

  if (!providers.some((provider) => provider.id === defaultProvider.id)) {
    providers.unshift(defaultProvider);
  }

  const enabledModelIds = new Set(
    providers.flatMap((provider) =>
      provider.enabled ? provider.models.filter((model) => model.enabled).map((model) => model.id) : [],
    ),
  );
  const activeModelId = settings.activeModelId && enabledModelIds.has(settings.activeModelId)
    ? settings.activeModelId
    : providers.find((provider) => provider.enabled)?.models.find((model) => model.enabled)?.id;

  return {
    ...settings,
    defaultProjectDir: normalizeDefaultProjectDir(settings.defaultProjectDir),
    general: {
      ...settings.general,
      scanMode: normalizeScanModeSetting(settings.general.scanMode),
      thinkingLevel: normalizeThinkingLevel(settings.general.thinkingLevel),
      contextWindow: normalizeContextWindow(settings.general.contextWindow),
    },
    automation: {
      enabled: Boolean(settings.automation?.enabled),
      frequency: normalizeAutomationFrequency(settings.automation?.frequency),
      intervalDays: normalizeAutomationIntervalDays(settings.automation),
      time: /^\d{2}:\d{2}$/.test(settings.automation?.time ?? "") ? settings.automation.time : "09:00",
      scanMode: normalizeScanModeSetting(settings.automation?.scanMode),
      ...(settings.automation?.lastRunAt ? { lastRunAt: settings.automation.lastRunAt } : {}),
      ...(settings.automation?.lastCheckedAt ? { lastCheckedAt: settings.automation.lastCheckedAt } : {}),
      ...(settings.automation?.lastResult ? { lastResult: settings.automation.lastResult } : {}),
      ...(settings.automation?.lastReportDir ? { lastReportDir: settings.automation.lastReportDir } : {}),
      ...(settings.automation?.lastProjectStateFingerprint
        ? { lastProjectStateFingerprint: settings.automation.lastProjectStateFingerprint }
        : {}),
    },
    providers,
    scanners: normalizeScannerSettings(settings.scanners),
    ...(activeModelId ? { activeModelId } : {}),
  };
}

function normalizeDefaultProjectDir(projectDir: string | undefined): string {
  const value = String(projectDir ?? "").trim();
  if (!value) return "";
  const normalized = value.replace(/\\/g, "/").toLowerCase();
  if (
    normalized.includes("/test projects/hermsec-node-express-vuln-lab") ||
    normalized.includes("/test projects/hermsec-python-flask-vuln-lab")
  ) {
    return "";
  }
  return value;
}

function normalizeScanModeSetting(mode: string | undefined): HermsecScanAssistMode {
  if (mode === "deep-assisted") return "deep-assisted";
  return "scanner-model-summary";
}

function normalizeThinkingLevel(level: AppSettings["general"]["thinkingLevel"] | undefined): AppSettings["general"]["thinkingLevel"] {
  if (level === "fast" || level === "deep") return level;
  return "balanced";
}

function normalizeContextWindow(window: AppSettings["general"]["contextWindow"] | undefined): AppSettings["general"]["contextWindow"] {
  if (window === "compact" || window === "large") return window;
  return "standard";
}

function normalizeProviderApiKeyEnv(provider: ProviderConfig, defaultProvider: ProviderConfig): string {
  const current = provider.apiKeyEnvVar?.trim();
  const defaultEnv = defaultProvider.apiKeyEnvVar?.trim() || "OPENCODE_GO_API_KEY";
  if (!current) return defaultEnv;

  if (
    provider.id === defaultProvider.id &&
    current !== defaultEnv &&
    !process.env[current] &&
    process.env[defaultEnv]
  ) {
    return defaultEnv;
  }

  return current;
}

function normalizeAutomationFrequency(frequency: AutomationFrequency | undefined): AutomationFrequency {
  if (frequency === "weekly" || frequency === "monthly") return frequency;
  return "custom-days";
}

function normalizeAutomationIntervalDays(automation: AppSettings["automation"] | undefined): number {
  if (automation?.frequency === "every-3-days") return 3;
  if (automation?.frequency === "daily") return 1;
  const parsed = Number(automation?.intervalDays);
  if (!Number.isFinite(parsed)) return 1;
  return Math.min(365, Math.max(1, Math.floor(parsed)));
}
