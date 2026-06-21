import type { ModelConfig, ProviderConfig, ProviderPreset } from "../renderer/src/types/settings";

const LOGO_BASE = "https://raw.githubusercontent.com/ln-dev7/logos-apps/master/logos";

const opencodeGoChatModels: ModelConfig[] = [
  model("glm-5.2", "GLM 5.2"),
  model("glm-5.1", "GLM 5.1"),
  model("kimi-k2.7", "Kimi K2.7"),
  model("kimi-k2.6", "Kimi K2.6"),
  model("deepseek-v4-pro", "DeepSeek V4 Pro"),
  model("deepseek-v4-flash", "DeepSeek V4 Flash"),
  model("mimo-v2.5", "MiMo V2.5"),
  model("mimo-v2.5-pro", "MiMo V2.5 Pro"),
];

export const OPENCODE_GO_CHAT_MODEL_IDS = new Set(opencodeGoChatModels.map((item) => item.id));

export function providerPresets(): ProviderPreset[] {
  return [
    {
      id: "opencode-go",
      displayName: "OpenCode Go",
      description: "Curated coding models through an OpenAI-compatible endpoint.",
      baseUrl: "https://opencode.ai/zen/go/v1",
      apiFormat: "openai-compatible",
      apiKeyEnvVar: "OPENCODE_GO_API_KEY",
      logoUrl: `${LOGO_BASE}/opencode.svg`,
      enabled: true,
      supportsModelDiscovery: true,
      status: "available",
      models: opencodeGoChatModels,
    },
    {
      id: "openai",
      displayName: "OpenAI",
      description: "OpenAI-compatible API for GPT and reasoning-capable models.",
      baseUrl: "https://api.openai.com/v1",
      apiFormat: "openai-compatible",
      apiKeyEnvVar: "OPENAI_API_KEY",
      logoUrl: `${LOGO_BASE}/openai.svg`,
      enabled: true,
      supportsModelDiscovery: true,
      status: "available",
      models: [
        model("gpt-4.1", "GPT-4.1"),
        model("gpt-4.1-mini", "GPT-4.1 Mini"),
        model("gpt-4o", "GPT-4o"),
        model("gpt-4o-mini", "GPT-4o Mini"),
      ],
    },
    {
      id: "anthropic",
      displayName: "Anthropic",
      description: "Claude models through Anthropic's OpenAI compatibility layer.",
      baseUrl: "https://api.anthropic.com/v1",
      apiFormat: "anthropic",
      apiKeyEnvVar: "ANTHROPIC_API_KEY",
      logoUrl: `${LOGO_BASE}/anthropic.svg`,
      enabled: true,
      supportsModelDiscovery: true,
      status: "available",
      models: [
        model("claude-opus-4-8", "Claude Opus 4.8"),
        model("claude-sonnet-4-6", "Claude Sonnet 4.6"),
        model("claude-haiku-4-5", "Claude Haiku 4.5"),
      ],
    },
    {
      id: "google-gemini",
      displayName: "Google Gemini",
      description: "Gemini models through Google's OpenAI-compatible endpoint.",
      baseUrl: "https://generativelanguage.googleapis.com/v1beta/openai",
      apiFormat: "gemini",
      apiKeyEnvVar: "GEMINI_API_KEY",
      logoUrl: `${LOGO_BASE}/google-gemini.svg`,
      enabled: true,
      supportsModelDiscovery: true,
      status: "available",
      models: [
        model("gemini-3.5-flash", "Gemini 3.5 Flash"),
        model("gemini-3.1-pro", "Gemini 3.1 Pro"),
        model("gemini-3-flash", "Gemini 3 Flash"),
      ],
    },
    {
      id: "cursor",
      displayName: "Cursor",
      description: "Cursor agent/API integration is tracked separately from LLM provider setup.",
      baseUrl: "https://cursor.com",
      apiFormat: "cursor",
      apiKeyEnvVar: "CURSOR_API_KEY",
      logoUrl: `${LOGO_BASE}/cursor.svg`,
      enabled: false,
      supportsModelDiscovery: false,
      status: "coming-soon",
      models: [],
    },
  ];
}

export function providerFromPreset(preset: ProviderPreset, existing?: ProviderConfig): ProviderConfig {
  return {
    id: preset.id,
    displayName: preset.displayName,
    description: preset.description,
    baseUrl: preset.baseUrl,
    apiFormat: preset.apiFormat,
    presetId: preset.id,
    logoUrl: preset.logoUrl,
    supportsModelDiscovery: preset.supportsModelDiscovery,
    authKind: existing?.authKind ?? "api_key",
    apiKeyEnvVar: existing?.apiKeyEnvVar ?? preset.apiKeyEnvVar,
    ...(existing?.apiKey ? { apiKey: existing.apiKey } : {}),
    enabled: existing?.enabled ?? preset.enabled,
    models: mergeModels(existing?.models ?? [], preset.models),
    modelDiscovery: existing?.modelDiscovery ?? { status: "idle" },
  };
}

export function normalizeProviderConfig(provider: ProviderConfig): ProviderConfig {
  const preset = providerPresets().find((item) => item.id === provider.presetId || item.id === provider.id);
  const base = preset ? providerFromPreset(preset, provider) : provider;
  return {
    ...base,
    id: cleanProviderId(base.id),
    displayName: base.displayName?.trim() || base.id,
    baseUrl: base.baseUrl?.trim() ?? "",
    apiFormat: base.apiFormat ?? "openai-compatible",
    authKind: base.authKind ?? "api_key",
    enabled: Boolean(base.enabled),
    supportsModelDiscovery: base.supportsModelDiscovery ?? true,
    models: mergeModels([], base.models ?? []),
    modelDiscovery: base.modelDiscovery ?? { status: "idle" },
  };
}

export function mergeModels(existing: ModelConfig[], incoming: ModelConfig[]): ModelConfig[] {
  const byId = new Map<string, ModelConfig>();
  for (const item of existing) {
    if (!item.id?.trim()) continue;
    byId.set(item.id, {
      id: item.id,
      label: item.label?.trim() || labelFromModelId(item.id),
      enabled: item.enabled !== false,
    });
  }
  for (const item of incoming) {
    if (!item.id?.trim()) continue;
    const current = byId.get(item.id);
    byId.set(item.id, {
      id: item.id,
      label: item.label?.trim() || current?.label || labelFromModelId(item.id),
      enabled: current?.enabled ?? item.enabled !== false,
    });
  }
  return [...byId.values()].sort((left, right) => left.label.localeCompare(right.label));
}

export function labelFromModelId(id: string): string {
  return id
    .replace(/^models\//u, "")
    .split(/[-_/]/u)
    .filter(Boolean)
    .map((part) => {
      if (/^(gpt|glm|mimo|api|ai|v\d+)$/iu.test(part)) return part.toUpperCase();
      if (/^\d+(?:\.\d+)*$/u.test(part)) return part;
      return `${part.slice(0, 1).toUpperCase()}${part.slice(1)}`;
    })
    .join(" ");
}

function model(id: string, label: string, enabled = true): ModelConfig {
  return { id, label, enabled };
}

function cleanProviderId(id: string): string {
  const cleaned = id.trim().toLowerCase().replace(/[^a-z0-9_-]+/gu, "-").replace(/^-+|-+$/gu, "");
  return cleaned || "custom-provider";
}
