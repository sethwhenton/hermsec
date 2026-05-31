import { noModelProvider } from "./noModel.js";
import { openAiCompatibleProvider } from "./openaiCompatible.js";
import { opencodeGoProvider } from "./opencodeGo.js";
import type { ModelProviderAdapter, ModelProviderId, ProviderConfig, ProviderHealth } from "./provider.js";

export type PrivacyMode = "local-only" | "balanced" | "cloud-assisted";

export type ProviderSelection = {
  provider: ModelProviderAdapter;
  health: ProviderHealth;
  fallbackReason?: string;
};

const providers: Record<ModelProviderId, ModelProviderAdapter> = {
  none: noModelProvider,
  "openai-compatible": openAiCompatibleProvider,
  "opencode-go": opencodeGoProvider,
  ollama: noModelProvider,
  openai: noModelProvider,
  openrouter: noModelProvider,
  claude: noModelProvider,
  gemini: noModelProvider
};

const remoteProviders = new Set<ModelProviderId>(["opencode-go", "openai", "openrouter", "claude", "gemini"]);

export async function selectModelProvider(
  config: ProviderConfig = {},
  privacyMode: PrivacyMode = "local-only"
): Promise<ProviderSelection> {
  const requestedId = config.provider ?? "none";
  const requested = providers[requestedId] ?? noModelProvider;
  if (requested.id !== "none" && remoteProviders.has(requested.id) && privacyMode === "local-only" && !config.allowRemoteProviders) {
    const health = await noModelProvider.healthCheck(config);
    return {
      provider: noModelProvider,
      health,
      fallbackReason: `${requested.id} is remote and was not explicitly allowed in local-only mode.`
    };
  }

  const health = await requested.healthCheck(config);
  if (!health.ok) {
    const fallbackHealth = await noModelProvider.healthCheck(config);
    return {
      provider: noModelProvider,
      health: fallbackHealth,
      fallbackReason: health.message
    };
  }
  return { provider: requested, health };
}

export function listConfiguredProviders(): ModelProviderAdapter[] {
  return [noModelProvider, openAiCompatibleProvider, opencodeGoProvider];
}
