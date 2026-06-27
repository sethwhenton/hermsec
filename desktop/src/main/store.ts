import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { app } from "electron";
import type { HermsecProductScanAssistMode } from "../renderer/src/types/scan";
import type { AgentScanSettings, AppSettings, AutomationFrequency, DeepPartial, ProviderConfig } from "../renderer/src/types/settings";
import { getEnvDefaults } from "./env";
import { normalizeProviderConfig, providerFromPreset, providerPresets } from "./providerCatalog";
import { defaultScannerSettings, normalizeScannerSettings } from "./scannerDefaults";

const SETTINGS_FILE = "settings.json";

function defaultProvider(env: ReturnType<typeof getEnvDefaults>): ProviderConfig {
  const preset = providerPresets().find((item) => item.id === env.provider);
  const provider = preset
    ? providerFromPreset(preset)
    : {
        id: env.provider,
        displayName: env.provider,
        baseUrl: env.baseUrl,
        apiFormat: "openai-compatible" as const,
        authKind: "environment" as const,
        apiKeyEnvVar: env.apiKeyEnvVar,
        enabled: true,
        supportsModelDiscovery: true,
        models: [],
        modelDiscovery: { status: "idle" as const },
      };
  const models = provider.models.some((model) => model.id === env.model)
    ? provider.models
    : [{ id: env.model, label: env.model, enabled: true }, ...provider.models];

  return {
    ...provider,
    baseUrl: env.baseUrl,
    apiKeyEnvVar: env.apiKeyEnvVar,
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
      privacyMode: false,
      scanMode: "deep-assisted",
      thinkingLevel: "balanced",
      contextWindow: "standard",
    },
    defaultProjectDir: "",
    defaultReportDir: join(app.getPath("documents"), "Hermsec", "reports"),
    activeModelId: env.model,
    activeProviderId: env.provider,
    automation: {
      enabled: false,
      frequency: "custom-days",
      intervalDays: 1,
      time: "09:00",
      scanMode: "deep-assisted",
    },
    providers: [defaultProvider(env)],
    scanners: defaultScannerSettings(),
    agents: defaultAgentSettings(),
  };
}

function defaultAgentSettings(): AgentScanSettings {
  return {
    singleAgent: {
      reasoningDepth: "balanced",
      maxToolRounds: 4,
    },
    moa: {
      presetId: "low-panel",
      panelSize: 5,
      debateRounds: 1,
      consensusThreshold: "majority",
    },
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
  const generalSettings = { ...(settings.general as AppSettings["general"] & { showReasoning?: boolean }) };
  delete generalSettings.showReasoning;
  const providers = settings.providers.map(normalizeProviderConfig).map((provider) => {
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

  const activeSelection = normalizeActiveSelection(providers, settings.activeProviderId, settings.activeModelId);

  return {
    ...settings,
    defaultProjectDir: normalizeDefaultProjectDir(settings.defaultProjectDir),
    general: {
      ...generalSettings,
      scanMode: normalizeScanModeSetting(generalSettings.scanMode),
      thinkingLevel: normalizeThinkingLevel(generalSettings.thinkingLevel),
      contextWindow: normalizeContextWindow(generalSettings.contextWindow),
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
    agents: normalizeAgentSettings(settings.agents),
    activeProviderId: activeSelection?.providerId,
    activeModelId: activeSelection?.modelId,
  };
}

function normalizeAgentSettings(agents: AppSettings["agents"]): AgentScanSettings {
  const defaults = defaultAgentSettings();
  const rawMoa = agents?.moa as (Partial<AgentScanSettings["moa"]> & { presetId?: unknown }) | undefined;
  const presetId = normalizeMoaPresetId(rawMoa?.presetId);
  const presetDefaults = moaPresetDefaults(presetId);
  return {
    singleAgent: {
      ...(agents?.singleAgent?.providerId ? { providerId: agents.singleAgent.providerId } : {}),
      ...(agents?.singleAgent?.modelId ? { modelId: agents.singleAgent.modelId } : {}),
      reasoningDepth: normalizeAgentReasoningDepth(agents?.singleAgent?.reasoningDepth),
      maxToolRounds: normalizeAgentToolRounds(agents?.singleAgent?.maxToolRounds),
    },
    moa: {
      presetId,
      panelSize: presetDefaults.panelSize,
      debateRounds: presetDefaults.debateRounds,
      consensusThreshold: presetDefaults.consensusThreshold,
      ...(rawMoa?.roleModels ? { roleModels: rawMoa.roleModels } : {}),
    },
  };
}

function normalizeMoaPresetId(value: unknown): AgentScanSettings["moa"]["presetId"] {
  if (value === "high-panel" || value === "deep-panel") return "high-panel";
  return "low-panel";
}

function moaPresetDefaults(presetId: AgentScanSettings["moa"]["presetId"]): AgentScanSettings["moa"] {
  if (presetId === "high-panel") {
    return {
      presetId,
      panelSize: 7,
      debateRounds: 3,
      consensusThreshold: "supermajority",
    };
  }
  return {
    presetId,
    panelSize: 5,
    debateRounds: 1,
    consensusThreshold: "majority",
  };
}

function normalizeAgentReasoningDepth(value: AgentScanSettings["singleAgent"]["reasoningDepth"] | undefined): AgentScanSettings["singleAgent"]["reasoningDepth"] {
  if (value === "fast" || value === "deep") return value;
  return "balanced";
}

function normalizeAgentToolRounds(value: number | undefined): number {
  if (!Number.isFinite(Number(value))) return 4;
  return Math.min(12, Math.max(1, Math.floor(Number(value))));
}

function normalizeActiveSelection(
  providers: ProviderConfig[],
  providerId: string | undefined,
  modelId: string | undefined,
): { providerId: string; modelId: string } | undefined {
  const chatProviders = providers.filter((item) => item.apiFormat !== "cursor");
  const provider = providerId ? chatProviders.find((item) => item.enabled && item.id === providerId) : undefined;
  const providerModel = provider?.models.find((model) => model.enabled && model.id === modelId);
  if (provider && providerModel) {
    return { providerId: provider.id, modelId: providerModel.id };
  }

  if (modelId) {
    const matchingProvider = chatProviders.find((item) =>
      item.enabled && item.models.some((model) => model.enabled && model.id === modelId),
    );
    if (matchingProvider) {
      return { providerId: matchingProvider.id, modelId };
    }
  }

  const fallbackProvider = chatProviders.find((item) => item.enabled && item.models.some((model) => model.enabled));
  const fallbackModel = fallbackProvider?.models.find((model) => model.enabled);
  return fallbackProvider && fallbackModel
    ? { providerId: fallbackProvider.id, modelId: fallbackModel.id }
    : undefined;
}

function normalizeDefaultProjectDir(projectDir: string | undefined): string {
  const value = String(projectDir ?? "").trim();
  return value;
}

function normalizeScanModeSetting(mode: string | undefined): HermsecProductScanAssistMode {
  if (mode === "single-agent" || mode === "single-agent-inspection") return "single-agent";
  if (mode === "moa-assisted" || mode === "moa-inspection") return "moa-assisted";
  if (
    mode === "scanner-moa-assisted" ||
    mode === "scanner-moa" ||
    mode === "scanner-plus-moa" ||
    mode === "scanner+moa" ||
    mode === "hybrid"
  ) return "scanner-moa-assisted";
  if (mode === "deep-assisted") return "deep-assisted";
  return "deep-assisted";
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
